"""
Category 4 — Process Isolation checks.

4.1  Server not running as root (HTTP heuristic)
4.2  Dedicated service user exists (local-only → SKIP)
4.3  NoNewPrivileges set in systemd (local-only → SKIP)
4.4  Filesystem access restricted (local-only → SKIP)
"""
from __future__ import annotations

import re

import requests
from requests.exceptions import RequestException

from mcp_benchmark.core.models import CheckResult

_TIMEOUT = 10

# Patterns that suggest root execution in error responses
_ROOT_PATTERNS = re.compile(
    r'(uid=0|gid=0|\broot\b|/root/|\(root\))',
    re.IGNORECASE,
)

_LOCAL_SKIP_MSG = "This check requires local shell access to the target host. Run manually: {cmd}"


# ─── 4.1 ─────────────────────────────────────────────────────────────────────
def check_4_1(target: str, api_key: str, headers: dict) -> CheckResult:
    """Server not running as root — HTTP heuristic via error responses."""
    signals: list[str] = []
    probe_paths = [
        "/tools/call",
        "/nonexistent_path_probe",
        "/health",
    ]
    try:
        for path in probe_paths:
            try:
                if path == "/tools/call":
                    resp = requests.post(
                        f"{target}{path}",
                        json={"name": "__root_probe__", "arguments": {}},
                        headers=headers,
                        timeout=_TIMEOUT,
                    )
                else:
                    resp = requests.get(f"{target}{path}", headers=headers, timeout=_TIMEOUT)
                m = _ROOT_PATTERNS.search(resp.text)
                if m:
                    signals.append(f"{path}: {m.group()!r}")
            except RequestException:
                pass

        if signals:
            return CheckResult(
                id="4.1", category="Process Isolation",
                description="Server not running as root",
                status="FAIL",
                detail=f"Root execution indicators found in HTTP responses: {'; '.join(signals)}",
                remediation="Run the MCP server as a dedicated non-root service user. Never run production services as uid=0.",
            )
        return CheckResult(
            id="4.1", category="Process Isolation",
            description="Server not running as root",
            status="WARN",
            detail="No root indicators found in HTTP responses. This check is unreliable without local shell access — verify with 'ps aux | grep mcp'.",
            remediation="",
        )
    except Exception as exc:
        return CheckResult(
            id="4.1", category="Process Isolation",
            description="Server not running as root",
            status="SKIP",
            detail=f"Unexpected error during root heuristic probe: {exc}",
            remediation="",
        )

check_4_1.check_id = "4.1"
check_4_1.category = "Process Isolation"
check_4_1.description = "Server not running as root"


# ─── 4.2 ─────────────────────────────────────────────────────────────────────
def check_4_2(target: str, api_key: str, headers: dict) -> CheckResult:
    """Dedicated service user exists — requires local access."""
    return CheckResult(
        id="4.2", category="Process Isolation",
        description="Dedicated service user exists",
        status="SKIP",
        detail=_LOCAL_SKIP_MSG.format(cmd="grep -i mcp /etc/passwd"),
        remediation="Create a dedicated non-privileged system user for the MCP service (e.g., useradd -r -s /sbin/nologin mcp-server).",
    )

check_4_2.check_id = "4.2"
check_4_2.category = "Process Isolation"
check_4_2.description = "Dedicated service user exists"


# ─── 4.3 ─────────────────────────────────────────────────────────────────────
def check_4_3(target: str, api_key: str, headers: dict) -> CheckResult:
    """NoNewPrivileges set in systemd service unit — requires local access."""
    return CheckResult(
        id="4.3", category="Process Isolation",
        description="NoNewPrivileges set in systemd",
        status="SKIP",
        detail=_LOCAL_SKIP_MSG.format(
            cmd="grep -r NoNewPrivileges /etc/systemd/system/*.service"
        ),
        remediation="Add 'NoNewPrivileges=yes' to your systemd service unit under [Service] to prevent privilege escalation.",
    )

check_4_3.check_id = "4.3"
check_4_3.category = "Process Isolation"
check_4_3.description = "NoNewPrivileges set in systemd"


# ─── 4.4 ─────────────────────────────────────────────────────────────────────
def check_4_4(target: str, api_key: str, headers: dict) -> CheckResult:
    """Filesystem access restricted via systemd ReadOnlyPaths — requires local access."""
    return CheckResult(
        id="4.4", category="Process Isolation",
        description="Filesystem access restricted",
        status="SKIP",
        detail=_LOCAL_SKIP_MSG.format(
            cmd="grep -r ReadOnlyPaths /etc/systemd/system/*.service"
        ),
        remediation="Add 'ReadOnlyPaths=/' and 'ReadWritePaths=/var/lib/mcp-server' to your systemd unit to restrict filesystem access.",
    )

check_4_4.check_id = "4.4"
check_4_4.category = "Process Isolation"
check_4_4.description = "Filesystem access restricted"
