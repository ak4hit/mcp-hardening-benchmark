"""
Server fingerprinting engine for mcp-hardening-benchmark.

Runs automatically at the start of every audit — 1–2 HTTP requests,
never blocks the audit if detection fails.

Detection priority:
  1. Response headers
  2. Root endpoint response body
  3. Version extraction (regex on body + JSON)
  4. Error page fingerprinting (malformed request fallback)
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

import requests
from packaging.version import Version, InvalidVersion
from requests.exceptions import RequestException

from mcp_benchmark.core.models import Fingerprint

# ─── Detection signal tables ──────────────────────────────────────────────────
HEADER_SIGNALS: dict[str, list[tuple[str, str]]] = {
    "MCPJam":  [("Server", "MCPJam"), ("X-Powered-By", "MCPJam")],
    "FastMCP": [("Server", "FastMCP"), ("X-Powered-By", "FastMCP")],
    "Flask":   [("Server", "Werkzeug"), ("X-Powered-By", "Flask")],
    "Node.js": [("X-Powered-By", "Express"), ("Server", "Node")],
}

BODY_SIGNALS: dict[str, list[str]] = {
    "MCPJam":  ["MCPJam", "mcpjam", "MCPJam Inspector"],
    "FastMCP": ["FastMCP", "fastmcp"],
    "Flask":   ["Werkzeug", "Flask"],
    "Node.js": ["Express", "node"],
}

# Regex patterns for version extraction
VERSION_PATTERNS = [
    re.compile(r'v?(\d+\.\d+\.\d+)'),           # v1.4.2 or 1.4.2
    re.compile(r'"version"\s*:\s*"([^"]+)"'),    # JSON: "version": "2.1.0"
    re.compile(r'Version\s*:\s*v?(\d+\.\d+\.\d+)', re.IGNORECASE),  # Version: v1.4.2
]

# Path to CVE database (relative to package root — resolved at runtime)
_CVE_DB_PATH = Path(__file__).parent.parent.parent / "cve_db.json"


def _load_cve_db() -> list[dict]:
    """Load CVE database from cve_db.json. Returns empty list on failure."""
    try:
        with _CVE_DB_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("cves", [])
    except (OSError, json.JSONDecodeError):
        return []


def _version_affected(version_str: Optional[str], constraint: str) -> bool:
    """
    Check whether a detected version satisfies a CVE constraint string.
    Supported operators: <=, <, ==, >=, >

    If version_str is None, always returns True (conservative — flag the CVE as WARN).
    """
    if version_str is None:
        return True  # Unknown version — be conservative
    try:
        detected = Version(version_str)
    except InvalidVersion:
        return True  # Unparseable version — be conservative

    constraint = constraint.strip()
    for op in ("<=", ">=", "<", ">", "=="):
        if constraint.startswith(op):
            raw = constraint[len(op):].strip()
            try:
                boundary = Version(raw)
            except InvalidVersion:
                return True
            if op == "<=":
                return detected <= boundary
            if op == ">=":
                return detected >= boundary
            if op == "<":
                return detected < boundary
            if op == ">":
                return detected > boundary
            if op == "==":
                return detected == boundary
    return True  # Unrecognised operator — conservative


def _match_cves(framework: str, version: Optional[str], cves: list[dict]) -> list[dict]:
    """Return CVE entries that match the detected framework and version."""
    matched = []
    for cve in cves:
        if cve.get("framework", "").lower() != framework.lower():
            continue
        affected_versions: list[str] = cve.get("affected_versions", [])
        if not affected_versions:
            matched.append(cve)
            continue
        for constraint in affected_versions:
            if _version_affected(version, constraint):
                entry = dict(cve)
                if version is None:
                    entry["_note"] = "version undetected — manual verification required"
                matched.append(entry)
                break
    return matched


def _detect_from_headers(headers: dict) -> tuple[Optional[str], dict]:
    """Return (framework, raw_signals) based on response headers."""
    signals: dict = {}
    for framework, checks in HEADER_SIGNALS.items():
        for header_name, expected_value in checks:
            actual = headers.get(header_name, "")
            if expected_value.lower() in actual.lower():
                signals[header_name] = actual
                return framework, signals
    return None, signals


def _detect_from_body(body: str) -> Optional[str]:
    """Return framework name if body contains a known signal."""
    for framework, keywords in BODY_SIGNALS.items():
        for kw in keywords:
            if kw in body:
                return framework
    return None


def _extract_version(body: str, headers: dict) -> Optional[str]:
    """Try to extract a version string from response body or headers."""
    # Try body first
    for pattern in VERSION_PATTERNS:
        m = pattern.search(body)
        if m:
            return m.group(1)
    # Try header values
    for value in headers.values():
        for pattern in VERSION_PATTERNS:
            m = pattern.search(value)
            if m:
                return m.group(1)
    return None


def fingerprint(target: str, api_key: str) -> Fingerprint:
    """
    Auto-detect MCP server framework and version before checks run.

    Makes at most 2 HTTP requests:
      1. GET /          (primary detection)
      2. GET /nonexistent  (error page fallback)

    Never raises — returns Fingerprint(framework='Unknown') on any failure.

    Args:
        target:  Base URL of the MCP server, e.g. 'http://localhost:5000'
        api_key: API key to include in the request header (may be empty string).

    Returns:
        Fingerprint dataclass with framework, version, cves, and raw_signals.
    """
    target = target.rstrip("/")
    headers: dict[str, str] = {}
    if api_key:
        headers["X-API-Key"] = api_key

    framework: Optional[str] = None
    version: Optional[str] = None
    raw_signals: dict = {}
    body = ""
    resp_headers: dict = {}

    # ── Request 1: GET / ──────────────────────────────────────────────────────
    try:
        resp = requests.get(
            target + "/",
            headers=headers,
            timeout=10,
            allow_redirects=True,
        )
        resp_headers = dict(resp.headers)
        body = resp.text[:8192]  # Cap to 8 KB to avoid memory issues

        # Priority 1: headers
        framework, raw_signals = _detect_from_headers(resp_headers)
        raw_signals.update({"status_code": resp.status_code})

        # Priority 2: body
        if framework is None:
            framework = _detect_from_body(body)
            if framework:
                raw_signals["body_signal"] = framework

        # Priority 3: version extraction
        version = _extract_version(body, resp_headers)
        if version:
            raw_signals["version_source"] = "root_endpoint"

    except RequestException as exc:
        raw_signals["error"] = str(exc)

    # ── Request 2: Error page fallback ────────────────────────────────────────
    if framework is None:
        try:
            err_resp = requests.get(
                target + "/__mcp_nonexistent_probe__",
                headers=headers,
                timeout=8,
                allow_redirects=False,
            )
            err_body = err_resp.text[:2048]
            framework = _detect_from_body(err_body)
            if framework:
                raw_signals["body_signal"] = f"error_page:{framework}"
            if version is None:
                version = _extract_version(err_body, dict(err_resp.headers))
                if version:
                    raw_signals["version_source"] = "error_page"
        except RequestException:
            pass

    # ── CVE matching ──────────────────────────────────────────────────────────
    cves: list[dict] = []
    if framework and framework != "Unknown":
        all_cves = _load_cve_db()
        cves = _match_cves(framework, version, all_cves)

    return Fingerprint(
        framework=framework or "Unknown",
        version=version,
        cves=cves,
        raw_signals=raw_signals,
    )
