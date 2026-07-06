"""
Category 7 — Network Controls checks.

7.1  Management port not publicly bound (ports 6274, 6277)
7.2  Server only listens on expected interface (local-only → SKIP)
7.3  No other MCP-related ports exposed (port scan)
"""
from __future__ import annotations

import socket
from urllib.parse import urlparse

from mcp_benchmark.core.models import CheckResult

_TIMEOUT = 5
_INSPECTOR_PORTS = [6274, 6277]
_ALL_MCP_PORTS = [5000, 6274, 6277, 8888, 3000, 8080]
_LOCAL_SKIP_MSG = "This check requires local shell access. Run manually: {cmd}"


def _is_localhost(target: str) -> bool:
    host = urlparse(target).hostname or ""
    return host in ("localhost", "127.0.0.1", "::1")


def _port_open(host: str, port: int, timeout: float = float(_TIMEOUT)) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


# ─── 7.1 ─────────────────────────────────────────────────────────────────────
def check_7_1(target: str, api_key: str, headers: dict) -> CheckResult:
    """Management/inspector port not publicly bound (6274, 6277)."""
    if _is_localhost(target):
        return CheckResult(
            id="7.1", category="Network Controls",
            description="Management port not publicly bound",
            status="SKIP",
            detail="Target is localhost — public management port check does not apply.",
            remediation="",
        )
    host = urlparse(target).hostname or ""
    exposed = [p for p in _INSPECTOR_PORTS if _port_open(host, p)]
    if not exposed:
        return CheckResult(
            id="7.1", category="Network Controls",
            description="Management port not publicly bound",
            status="PASS",
            detail=f"Inspector ports {_INSPECTOR_PORTS} are not reachable from the network.",
            remediation="",
        )
    return CheckResult(
        id="7.1", category="Network Controls",
        description="Management port not publicly bound",
        status="FAIL",
        detail=f"Management port(s) reachable: {exposed} on {host}",
        remediation="Bind the MCP inspector to 127.0.0.1 only. Use a firewall to block external access.",
    )

check_7_1.check_id = "7.1"
check_7_1.category = "Network Controls"
check_7_1.description = "Management port not publicly bound"


# ─── 7.2 ─────────────────────────────────────────────────────────────────────
def check_7_2(target: str, api_key: str, headers: dict) -> CheckResult:
    """Server only listens on expected interface — requires local netstat access."""
    return CheckResult(
        id="7.2", category="Network Controls",
        description="Server listens on expected interface only",
        status="SKIP",
        detail=_LOCAL_SKIP_MSG.format(cmd="netstat -tlnp | grep mcp"),
        remediation="Configure the MCP server to bind only to the required interface (e.g., 127.0.0.1 or a specific internal IP). Avoid binding to 0.0.0.0.",
    )

check_7_2.check_id = "7.2"
check_7_2.category = "Network Controls"
check_7_2.description = "Server listens on expected interface only"


# ─── 7.3 ─────────────────────────────────────────────────────────────────────
def check_7_3(target: str, api_key: str, headers: dict) -> CheckResult:
    """No other MCP-related ports exposed — port scan common MCP ports."""
    if _is_localhost(target):
        return CheckResult(
            id="7.3", category="Network Controls",
            description="No other MCP-related ports exposed",
            status="SKIP",
            detail="Target is localhost — public port exposure check does not apply.",
            remediation="",
        )
    host = urlparse(target).hostname or ""
    # Determine which port the target itself is using, so we don't flag it
    target_port = urlparse(target).port
    check_ports = [p for p in _ALL_MCP_PORTS if p != target_port]
    exposed = [p for p in check_ports if _port_open(host, p)]
    if not exposed:
        return CheckResult(
            id="7.3", category="Network Controls",
            description="No other MCP-related ports exposed",
            status="PASS",
            detail=f"No unexpected MCP-related ports reachable: {check_ports}",
            remediation="",
        )
    return CheckResult(
        id="7.3", category="Network Controls",
        description="No other MCP-related ports exposed",
        status="WARN",
        detail=f"Unexpected port(s) reachable on {host}: {exposed}",
        remediation="Close or firewall all ports not required for MCP service operation. Review what services are listening on these ports.",
    )

check_7_3.check_id = "7.3"
check_7_3.category = "Network Controls"
check_7_3.description = "No other MCP-related ports exposed"
