"""
Category 1 — Authentication checks.

1.1  Auth enforced on /tools/list
1.2  Auth enforced on /tools/call
1.3  No default/blank API key accepted
1.4  Auth enforced on all discovered endpoints
1.5  Rate limiting on failed auth
"""
from __future__ import annotations

import time

import requests
from requests.exceptions import RequestException

from mcp_benchmark.core.models import CheckResult

_TIMEOUT = 10


def _get(url: str, headers: dict | None = None, timeout: int = _TIMEOUT):
    """GET with safe defaults."""
    return requests.get(url, headers=headers or {}, timeout=timeout, allow_redirects=False)


def _post(url: str, json_body: dict, headers: dict | None = None, timeout: int = _TIMEOUT):
    """POST JSON with safe defaults."""
    return requests.post(url, json=json_body, headers=headers or {}, timeout=timeout)


# ─── 1.1 ─────────────────────────────────────────────────────────────────────
def check_1_1(target: str, api_key: str, headers: dict) -> CheckResult:
    """Auth enforced on /tools/list — expect 401 without credentials."""
    try:
        resp = _get(f"{target}/tools/list")  # No auth header
        if resp.status_code == 401:
            return CheckResult(
                id="1.1", category="Authentication",
                description="Auth enforced on /tools/list",
                status="PASS",
                detail="Server returned 401 without credentials on /tools/list.",
                remediation="",
            )
        return CheckResult(
            id="1.1", category="Authentication",
            description="Auth enforced on /tools/list",
            status="FAIL",
            detail=f"Server returned {resp.status_code} (expected 401) without credentials on /tools/list.",
            remediation="Enforce authentication on the /tools/list endpoint. Return HTTP 401 for unauthenticated requests.",
        )
    except RequestException as exc:
        return CheckResult(
            id="1.1", category="Authentication",
            description="Auth enforced on /tools/list",
            status="SKIP",
            detail=f"Could not reach /tools/list: {exc}",
            remediation="",
        )

check_1_1.check_id = "1.1"
check_1_1.category = "Authentication"
check_1_1.description = "Auth enforced on /tools/list"


# ─── 1.2 ─────────────────────────────────────────────────────────────────────
def check_1_2(target: str, api_key: str, headers: dict) -> CheckResult:
    """Auth enforced on /tools/call — expect 401 without credentials."""
    try:
        resp = _post(f"{target}/tools/call", json_body={"name": "ping", "arguments": {}})
        if resp.status_code == 401:
            return CheckResult(
                id="1.2", category="Authentication",
                description="Auth enforced on /tools/call",
                status="PASS",
                detail="Server returned 401 without credentials on /tools/call.",
                remediation="",
            )
        return CheckResult(
            id="1.2", category="Authentication",
            description="Auth enforced on /tools/call",
            status="FAIL",
            detail=f"Server returned {resp.status_code} (expected 401) without credentials on /tools/call.",
            remediation="Enforce authentication on the /tools/call endpoint. All tool invocations must require a valid credential.",
        )
    except RequestException as exc:
        return CheckResult(
            id="1.2", category="Authentication",
            description="Auth enforced on /tools/call",
            status="SKIP",
            detail=f"Could not reach /tools/call: {exc}",
            remediation="",
        )

check_1_2.check_id = "1.2"
check_1_2.category = "Authentication"
check_1_2.description = "Auth enforced on /tools/call"


# ─── 1.3 ─────────────────────────────────────────────────────────────────────
_WEAK_KEYS = ["", "admin", "test", "password", "secret", "123456", "apikey"]

def check_1_3(target: str, api_key: str, headers: dict) -> CheckResult:
    """No default/blank API key accepted."""
    accepted: list[str] = []
    try:
        for weak_key in _WEAK_KEYS:
            h = {"X-API-Key": weak_key} if weak_key else {}
            resp = _get(f"{target}/tools/list", headers=h)
            if resp.status_code not in (401, 403):
                accepted.append(repr(weak_key) if weak_key else "'' (empty)")
        if not accepted:
            return CheckResult(
                id="1.3", category="Authentication",
                description="No default/blank API key accepted",
                status="PASS",
                detail="Server rejected all tested weak/default credentials.",
                remediation="",
            )
        return CheckResult(
            id="1.3", category="Authentication",
            description="No default/blank API key accepted",
            status="FAIL",
            detail=f"Server accepted weak credentials: {', '.join(accepted)}",
            remediation="Remove all default, blank, or common API keys. Require cryptographically random keys.",
        )
    except RequestException as exc:
        return CheckResult(
            id="1.3", category="Authentication",
            description="No default/blank API key accepted",
            status="SKIP",
            detail=f"Request error during weak-key test: {exc}",
            remediation="",
        )

check_1_3.check_id = "1.3"
check_1_3.category = "Authentication"
check_1_3.description = "No default/blank API key accepted"


# ─── 1.4 ─────────────────────────────────────────────────────────────────────
_PROBE_PATHS = ["/health", "/config", "/debug", "/admin", "/status", "/metrics"]

def check_1_4(target: str, api_key: str, headers: dict) -> CheckResult:
    """Auth enforced on all discovered endpoints."""
    unprotected: list[str] = []
    try:
        for path in _PROBE_PATHS:
            try:
                resp = _get(f"{target}{path}")
                # 200 without auth on a sensitive path = FAIL
                if resp.status_code == 200:
                    unprotected.append(path)
            except RequestException:
                pass  # Can't reach path — treat as not exposed
        if not unprotected:
            return CheckResult(
                id="1.4", category="Authentication",
                description="Auth enforced on all discovered endpoints",
                status="PASS",
                detail="All probed sensitive paths returned non-200 without credentials.",
                remediation="",
            )
        return CheckResult(
            id="1.4", category="Authentication",
            description="Auth enforced on all discovered endpoints",
            status="FAIL",
            detail=f"Unprotected endpoints found (200 without auth): {', '.join(unprotected)}",
            remediation="Apply authentication middleware to all exposed endpoints, including health/debug/admin routes.",
        )
    except Exception as exc:
        return CheckResult(
            id="1.4", category="Authentication",
            description="Auth enforced on all discovered endpoints",
            status="SKIP",
            detail=f"Unexpected error during endpoint probe: {exc}",
            remediation="",
        )

check_1_4.check_id = "1.4"
check_1_4.category = "Authentication"
check_1_4.description = "Auth enforced on all discovered endpoints"


# ─── 1.5 ─────────────────────────────────────────────────────────────────────
def check_1_5(target: str, api_key: str, headers: dict) -> CheckResult:
    """Rate limiting on failed auth — send 20 failed requests, expect 429 or block."""
    got_429 = False
    try:
        for i in range(20):
            resp = _get(f"{target}/tools/list", headers={"X-API-Key": f"invalid_key_{i}"})
            if resp.status_code == 429:
                got_429 = True
                break
            time.sleep(0.05)  # Small delay to avoid hammering
        if got_429:
            return CheckResult(
                id="1.5", category="Authentication",
                description="Rate limiting on failed auth",
                status="PASS",
                detail="Server returned 429 after repeated failed auth attempts.",
                remediation="",
            )
        return CheckResult(
            id="1.5", category="Authentication",
            description="Rate limiting on failed auth",
            status="WARN",
            detail="No 429 response observed after 20 failed auth attempts. Rate limiting may not be configured.",
            remediation="Implement rate limiting or account lockout on authentication failures to prevent brute-force attacks.",
        )
    except RequestException as exc:
        return CheckResult(
            id="1.5", category="Authentication",
            description="Rate limiting on failed auth",
            status="SKIP",
            detail=f"Request error during rate-limit probe: {exc}",
            remediation="",
        )

check_1_5.check_id = "1.5"
check_1_5.category = "Authentication"
check_1_5.description = "Rate limiting on failed auth"
