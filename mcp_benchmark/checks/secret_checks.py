"""
Category 5 — Secret Management checks.

5.1  No secrets in tool descriptions
5.2  No secrets in error responses
5.3  API key not echoed back in server headers
5.4  No .env file accessible
"""
from __future__ import annotations

import re

import requests
from requests.exceptions import RequestException

from mcp_benchmark.core.models import CheckResult

_TIMEOUT = 10

# Credential detection regex patterns
SECRET_PATTERNS = [
    re.compile(r'[A-Za-z0-9]{32,}'),          # Generic long token
    re.compile(r'(password|passwd|secret|token|api_?key)\s*[:=]\s*\S+', re.IGNORECASE),
    re.compile(r'-----BEGIN (RSA|OPENSSH) PRIVATE KEY-----'),
    re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'),  # Base64 blob
]

_ENV_PATHS = ["/.env", "/app/.env", "/config/.env", "/.env.local", "/.env.production"]


def _contains_secret(text: str) -> list[str]:
    """Return list of matched secret pattern descriptions."""
    found = []
    for pattern in SECRET_PATTERNS:
        m = pattern.search(text)
        if m:
            # Redact the actual value for safety
            found.append(f"Pattern matched: {pattern.pattern[:40]}...")
    return found


def _get_tool_list(target: str, headers: dict) -> list[dict]:
    try:
        resp = requests.get(f"{target}/tools/list", headers=headers, timeout=_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return data.get("tools", [])
    except (RequestException, ValueError):
        pass
    return []


# ─── 5.1 ─────────────────────────────────────────────────────────────────────
def check_5_1(target: str, api_key: str, headers: dict) -> CheckResult:
    """No secrets in tool descriptions or parameter schemas."""
    tool_list = _get_tool_list(target, headers)
    if not tool_list:
        return CheckResult(
            id="5.1", category="Secret Management",
            description="No secrets in tool descriptions",
            status="SKIP",
            detail="Could not retrieve /tools/list.",
            remediation="",
        )
    hits: list[str] = []
    for tool in tool_list:
        text = str(tool)
        matches = _contains_secret(text)
        if matches:
            name = tool.get("name", "?") if isinstance(tool, dict) else "?"
            hits.append(f"Tool '{name}': {matches[0]}")
    if not hits:
        return CheckResult(
            id="5.1", category="Secret Management",
            description="No secrets in tool descriptions",
            status="PASS",
            detail="No credential patterns detected in tool metadata.",
            remediation="",
        )
    return CheckResult(
        id="5.1", category="Secret Management",
        description="No secrets in tool descriptions",
        status="FAIL",
        detail=f"Credential patterns found in tool metadata: {'; '.join(hits)}",
        remediation="Remove all secrets from tool descriptions and parameter schemas. Use environment variables for credentials, never inline them.",
    )

check_5_1.check_id = "5.1"
check_5_1.category = "Secret Management"
check_5_1.description = "No secrets in tool descriptions"


# ─── 5.2 ─────────────────────────────────────────────────────────────────────
def check_5_2(target: str, api_key: str, headers: dict) -> CheckResult:
    """No secrets in error responses — trigger errors and scan the response body."""
    error_triggers = [
        ("GET", f"{target}/nonexistent_path_5_2_probe", None),
        ("POST", f"{target}/tools/call", {"name": "__error_probe__", "arguments": {"x": "y"}}),
    ]
    hits: list[str] = []
    try:
        for method, url, body in error_triggers:
            try:
                if method == "GET":
                    resp = requests.get(url, headers=headers, timeout=_TIMEOUT)
                else:
                    resp = requests.post(url, json=body, headers=headers, timeout=_TIMEOUT)
                matches = _contains_secret(resp.text)
                if matches:
                    hits.append(f"{method} {url.split(target)[-1]}: {matches[0]}")
            except RequestException:
                pass

        if not hits:
            return CheckResult(
                id="5.2", category="Secret Management",
                description="No secrets in error responses",
                status="PASS",
                detail="No credential patterns detected in error response bodies.",
                remediation="",
            )
        return CheckResult(
            id="5.2", category="Secret Management",
            description="No secrets in error responses",
            status="FAIL",
            detail=f"Credential patterns found in error responses: {'; '.join(hits)}",
            remediation="Implement a global error handler that returns sanitized error messages. Never include stack traces, internal paths, or credentials in HTTP error responses.",
        )
    except Exception as exc:
        return CheckResult(
            id="5.2", category="Secret Management",
            description="No secrets in error responses",
            status="SKIP",
            detail=f"Unexpected error during error-response probe: {exc}",
            remediation="",
        )

check_5_2.check_id = "5.2"
check_5_2.category = "Secret Management"
check_5_2.description = "No secrets in error responses"


# ─── 5.3 ─────────────────────────────────────────────────────────────────────
def check_5_3(target: str, api_key: str, headers: dict) -> CheckResult:
    """API key not echoed back in server response headers."""
    try:
        resp = requests.get(f"{target}/tools/list", headers=headers, timeout=_TIMEOUT)
        resp_header_values = " ".join(resp.headers.values())
        if api_key and api_key in resp_header_values:
            return CheckResult(
                id="5.3", category="Secret Management",
                description="API key not in server headers",
                status="FAIL",
                detail="The API key was echoed back in a response header.",
                remediation="Never echo authentication credentials in response headers. Remove any middleware that mirrors request headers.",
            )
        return CheckResult(
            id="5.3", category="Secret Management",
            description="API key not in server headers",
            status="PASS",
            detail="API key was not found in response headers.",
            remediation="",
        )
    except RequestException as exc:
        return CheckResult(
            id="5.3", category="Secret Management",
            description="API key not in server headers",
            status="SKIP",
            detail=f"Request error during header echo check: {exc}",
            remediation="",
        )

check_5_3.check_id = "5.3"
check_5_3.category = "Secret Management"
check_5_3.description = "API key not in server headers"


# ─── 5.4 ─────────────────────────────────────────────────────────────────────
def check_5_4(target: str, api_key: str, headers: dict) -> CheckResult:
    """No .env file accessible via HTTP."""
    accessible: list[str] = []
    try:
        for path in _ENV_PATHS:
            try:
                resp = requests.get(f"{target}{path}", timeout=_TIMEOUT, allow_redirects=False)
                if resp.status_code == 200 and len(resp.text) > 0:
                    accessible.append(path)
            except RequestException:
                pass
        if not accessible:
            return CheckResult(
                id="5.4", category="Secret Management",
                description="No .env file accessible",
                status="PASS",
                detail=f"All probed .env paths returned non-200: {_ENV_PATHS}",
                remediation="",
            )
        return CheckResult(
            id="5.4", category="Secret Management",
            description="No .env file accessible",
            status="FAIL",
            detail=f"Accessible .env file(s) found: {', '.join(accessible)}",
            remediation="Block access to .env files at the web server/reverse proxy level. Never serve .env files publicly.",
        )
    except Exception as exc:
        return CheckResult(
            id="5.4", category="Secret Management",
            description="No .env file accessible",
            status="SKIP",
            detail=f"Unexpected error during .env probe: {exc}",
            remediation="",
        )

check_5_4.check_id = "5.4"
check_5_4.category = "Secret Management"
check_5_4.description = "No .env file accessible"
