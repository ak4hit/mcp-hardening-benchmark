"""
Category 6 — Logging & Monitoring checks.

6.1  Tool calls produce log output (local-only → SKIP)
6.2  Auth failures logged (local-only → SKIP)
6.3  /health endpoint does not expose internals
6.4  Server version not exposed in headers
"""
from __future__ import annotations

import re

import requests
from requests.exceptions import RequestException

from mcp_benchmark.core.models import CheckResult

_TIMEOUT = 10
_LOCAL_SKIP_MSG = "This check requires local shell access to the target host. Run manually: {cmd}"

# Patterns that indicate internal info leak in /health
_INTERNAL_PATTERNS = re.compile(
    r'(/home/|/root/|/etc/|uid=\d+|password|secret|token|internal|private)',
    re.IGNORECASE,
)

# Version exposure in headers
_VERSION_HEADERS = ["Server", "X-Powered-By", "X-Runtime", "X-Version"]
_VERSION_PATTERN = re.compile(r'\d+\.\d+')


# ─── 6.1 ─────────────────────────────────────────────────────────────────────
def check_6_1(target: str, api_key: str, headers: dict) -> CheckResult:
    """Tool calls produce log output — requires local access."""
    return CheckResult(
        id="6.1", category="Logging & Monitoring",
        description="Tool calls produce log output",
        status="SKIP",
        detail=_LOCAL_SKIP_MSG.format(
            cmd="tail -f /var/log/mcp-server.log (make a tool call and verify log entry appears)"
        ),
        remediation="Ensure every tool invocation is logged with: timestamp, tool name, caller identity, and outcome. Send logs to a centralized SIEM.",
    )

check_6_1.check_id = "6.1"
check_6_1.category = "Logging & Monitoring"
check_6_1.description = "Tool calls produce log output"


# ─── 6.2 ─────────────────────────────────────────────────────────────────────
def check_6_2(target: str, api_key: str, headers: dict) -> CheckResult:
    """Auth failures logged — requires local access."""
    return CheckResult(
        id="6.2", category="Logging & Monitoring",
        description="Auth failures logged",
        status="SKIP",
        detail=_LOCAL_SKIP_MSG.format(
            cmd="Send a request with an invalid API key, then check: grep 'auth' /var/log/mcp-server.log"
        ),
        remediation="Log all authentication failures with: timestamp, source IP, and attempted credential hash. Alert on repeated failures.",
    )

check_6_2.check_id = "6.2"
check_6_2.category = "Logging & Monitoring"
check_6_2.description = "Auth failures logged"


# ─── 6.3 ─────────────────────────────────────────────────────────────────────
def check_6_3(target: str, api_key: str, headers: dict) -> CheckResult:
    """/health endpoint does not expose internal configuration or paths."""
    try:
        resp = requests.get(f"{target}/health", headers=headers, timeout=_TIMEOUT)
        if resp.status_code == 404:
            return CheckResult(
                id="6.3", category="Logging & Monitoring",
                description="/health endpoint does not expose internals",
                status="PASS",
                detail="/health endpoint not present — no information exposed.",
                remediation="",
            )
        body = resp.text
        m = _INTERNAL_PATTERNS.search(body)
        if m:
            return CheckResult(
                id="6.3", category="Logging & Monitoring",
                description="/health endpoint does not expose internals",
                status="FAIL",
                detail=f"/health response contains internal information: {m.group()!r}",
                remediation="Sanitize /health endpoint output. It should return only: status (ok/degraded) and uptime. Remove all internal paths, credentials, and version strings.",
            )
        return CheckResult(
            id="6.3", category="Logging & Monitoring",
            description="/health endpoint does not expose internals",
            status="PASS",
            detail="/health endpoint does not appear to expose internal configuration.",
            remediation="",
        )
    except RequestException as exc:
        return CheckResult(
            id="6.3", category="Logging & Monitoring",
            description="/health endpoint does not expose internals",
            status="SKIP",
            detail=f"Could not probe /health: {exc}",
            remediation="",
        )

check_6_3.check_id = "6.3"
check_6_3.category = "Logging & Monitoring"
check_6_3.description = "/health endpoint does not expose internals"


# ─── 6.4 ─────────────────────────────────────────────────────────────────────
def check_6_4(target: str, api_key: str, headers: dict) -> CheckResult:
    """Server version not exposed in response headers."""
    try:
        resp = requests.get(f"{target}/", timeout=_TIMEOUT, allow_redirects=False)
        exposed: list[str] = []
        for header in _VERSION_HEADERS:
            value = resp.headers.get(header, "")
            if value and _VERSION_PATTERN.search(value):
                exposed.append(f"{header}: {value}")
        if not exposed:
            return CheckResult(
                id="6.4", category="Logging & Monitoring",
                description="Server version not exposed in headers",
                status="PASS",
                detail="No version strings found in Server/X-Powered-By headers.",
                remediation="",
            )
        return CheckResult(
            id="6.4", category="Logging & Monitoring",
            description="Server version not exposed in headers",
            status="FAIL",
            detail=f"Version strings found in headers: {'; '.join(exposed)}",
            remediation="Configure your web server to suppress version information from headers (e.g., server_tokens off in Nginx).",
        )
    except RequestException as exc:
        return CheckResult(
            id="6.4", category="Logging & Monitoring",
            description="Server version not exposed in headers",
            status="SKIP",
            detail=f"Could not probe headers: {exc}",
            remediation="",
        )

check_6_4.check_id = "6.4"
check_6_4.category = "Logging & Monitoring"
check_6_4.description = "Server version not exposed in headers"
