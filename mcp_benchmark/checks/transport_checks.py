"""
Category 2 — Transport Security checks.

2.1  No unauthenticated SSE endpoint
2.2  TLS enforced if non-localhost
2.3  CORS policy configured (no wildcard)
2.4  No debug/inspector port exposed publicly
"""
from __future__ import annotations

import socket

import requests
from requests.exceptions import RequestException

from mcp_benchmark.core.models import CheckResult

_TIMEOUT = 10
_INSPECTOR_PORTS = [6274, 6277]  # Common MCP inspector ports


def _is_localhost(target: str) -> bool:
    """Return True if the target hostname resolves to loopback."""
    from urllib.parse import urlparse
    host = urlparse(target).hostname or ""
    return host in ("localhost", "127.0.0.1", "::1")


# ─── 2.1 ─────────────────────────────────────────────────────────────────────
def check_2_1(target: str, api_key: str, headers: dict) -> CheckResult:
    """No unauthenticated SSE endpoint — GET /sse without auth → expect 401."""
    try:
        resp = requests.get(
            f"{target}/sse",
            timeout=_TIMEOUT,
            allow_redirects=False,
            stream=True,  # SSE endpoint may stream forever — don't download body
        )
        resp.close()
        if resp.status_code in (401, 403):
            return CheckResult(
                id="2.1", category="Transport Security",
                description="No unauthenticated SSE endpoint",
                status="PASS",
                detail=f"SSE endpoint returned {resp.status_code} without credentials.",
                remediation="",
            )
        if resp.status_code == 404:
            return CheckResult(
                id="2.1", category="Transport Security",
                description="No unauthenticated SSE endpoint",
                status="PASS",
                detail="SSE endpoint not present (/sse → 404).",
                remediation="",
            )
        return CheckResult(
            id="2.1", category="Transport Security",
            description="No unauthenticated SSE endpoint",
            status="FAIL",
            detail=f"/sse returned {resp.status_code} without credentials — endpoint may be unauthenticated.",
            remediation="Apply authentication to the /sse endpoint. CVE-2025-49596 exploits an unauthenticated /sse endpoint in MCPJam.",
        )
    except RequestException as exc:
        return CheckResult(
            id="2.1", category="Transport Security",
            description="No unauthenticated SSE endpoint",
            status="SKIP",
            detail=f"Could not probe /sse: {exc}",
            remediation="",
        )

check_2_1.check_id = "2.1"
check_2_1.category = "Transport Security"
check_2_1.description = "No unauthenticated SSE endpoint"


# ─── 2.2 ─────────────────────────────────────────────────────────────────────
def check_2_2(target: str, api_key: str, headers: dict) -> CheckResult:
    """TLS enforced if non-localhost — non-local targets must use HTTPS."""
    if _is_localhost(target):
        return CheckResult(
            id="2.2", category="Transport Security",
            description="TLS enforced if non-localhost",
            status="SKIP",
            detail="Target is localhost — TLS requirement does not apply.",
            remediation="",
        )
    if target.startswith("https://"):
        return CheckResult(
            id="2.2", category="Transport Security",
            description="TLS enforced if non-localhost",
            status="PASS",
            detail="Target uses HTTPS — TLS is enforced.",
            remediation="",
        )
    return CheckResult(
        id="2.2", category="Transport Security",
        description="TLS enforced if non-localhost",
        status="FAIL",
        detail="Non-localhost target is using HTTP — traffic is unencrypted.",
        remediation="Deploy a TLS certificate and enforce HTTPS. Redirect all HTTP traffic to HTTPS.",
    )

check_2_2.check_id = "2.2"
check_2_2.category = "Transport Security"
check_2_2.description = "TLS enforced if non-localhost"


# ─── 2.3 ─────────────────────────────────────────────────────────────────────
def check_2_3(target: str, api_key: str, headers: dict) -> CheckResult:
    """CORS policy configured — Access-Control-Allow-Origin must not be wildcard."""
    try:
        resp = requests.get(
            f"{target}/tools/list",
            headers={**headers, "Origin": "https://evil.example.com"},
            timeout=_TIMEOUT,
            allow_redirects=False,
        )
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*":
            return CheckResult(
                id="2.3", category="Transport Security",
                description="CORS policy configured",
                status="FAIL",
                detail="Access-Control-Allow-Origin is wildcard (*) — any origin can read responses.",
                remediation="Restrict CORS to known trusted origins. Never use Access-Control-Allow-Origin: * on authenticated endpoints.",
            )
        if not acao:
            return CheckResult(
                id="2.3", category="Transport Security",
                description="CORS policy configured",
                status="PASS",
                detail="No CORS headers present — cross-origin requests are blocked by default.",
                remediation="",
            )
        return CheckResult(
            id="2.3", category="Transport Security",
            description="CORS policy configured",
            status="PASS",
            detail=f"CORS restricted to: {acao}",
            remediation="",
        )
    except RequestException as exc:
        return CheckResult(
            id="2.3", category="Transport Security",
            description="CORS policy configured",
            status="SKIP",
            detail=f"Could not probe CORS headers: {exc}",
            remediation="",
        )

check_2_3.check_id = "2.3"
check_2_3.category = "Transport Security"
check_2_3.description = "CORS policy configured"


# ─── 2.4 ─────────────────────────────────────────────────────────────────────
def _port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    """Return True if a TCP connection to host:port succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def check_2_4(target: str, api_key: str, headers: dict) -> CheckResult:
    """No debug/inspector port exposed publicly — probe ports 6274, 6277."""
    from urllib.parse import urlparse
    if _is_localhost(target):
        return CheckResult(
            id="2.4", category="Transport Security",
            description="No debug/inspector port exposed publicly",
            status="SKIP",
            detail="Target is localhost — public inspector port exposure check does not apply.",
            remediation="",
        )
    host = urlparse(target).hostname or ""
    exposed: list[int] = [p for p in _INSPECTOR_PORTS if _port_open(host, p)]
    if not exposed:
        return CheckResult(
            id="2.4", category="Transport Security",
            description="No debug/inspector port exposed publicly",
            status="PASS",
            detail=f"Inspector ports {_INSPECTOR_PORTS} are not reachable on {host}.",
            remediation="",
        )
    return CheckResult(
        id="2.4", category="Transport Security",
        description="No debug/inspector port exposed publicly",
        status="FAIL",
        detail=f"Inspector port(s) reachable from the internet: {exposed} on {host}",
        remediation="Bind the MCP inspector/debug interface to 127.0.0.1 only. Use a firewall to block external access to ports 6274 and 6277.",
    )

check_2_4.check_id = "2.4"
check_2_4.category = "Transport Security"
check_2_4.description = "No debug/inspector port exposed publicly"
