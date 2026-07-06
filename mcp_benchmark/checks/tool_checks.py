"""
Category 3 — Tool Exposure checks.

3.1  No hidden callable tools (brute-force wordlist)
3.2  Dangerous tool names absent
3.3  Tool inputs validated (malformed arguments)
3.4  Tool list doesn't leak paths or credentials
3.5  No tool executes shell commands (RCE probe)
"""
from __future__ import annotations

import re

import requests
from requests.exceptions import RequestException

from mcp_benchmark.core.models import CheckResult

_TIMEOUT = 10

# ─── Hidden tool wordlist ─────────────────────────────────────────────────────
HIDDEN_TOOL_NAMES: list[str] = [
    "ops._admin_dump", "ops._debug_mode", "ops._shell",
    "admin.exec", "admin.dump", "admin.reset",
    "debug.eval", "debug.shell", "debug.exec",
    "internal.run", "internal.cmd", "internal.exec",
    "system.exec", "system.shell", "system.run",
    "_exec", "_shell", "_eval", "_debug", "_admin",
    "tools.exec", "tools.run", "tools.shell",
]

# Dangerous name patterns (regex)
_DANGEROUS_PATTERNS = re.compile(
    r'(admin|dump|debug|exec|shell|eval|cmd|command|backdoor|bypass)',
    re.IGNORECASE,
)

# Path / credential leak patterns
_LEAK_PATTERNS = [
    re.compile(r'[A-Za-z]:[/\\]'),           # Windows absolute path
    re.compile(r'(/home/|/root/|/etc/|/var/|/usr/)'),  # Unix paths
    re.compile(r'(password|passwd|secret|token|api_?key)\s*[:=]\s*\S+', re.IGNORECASE),
    re.compile(r'-----BEGIN\s+(RSA|OPENSSH)\s+PRIVATE KEY-----'),
]

# Shell metacharacter payloads for RCE probe
_RCE_PAYLOADS = [
    "; id",
    "| id",
    "$(id)",
    "`id`",
    "&& id",
    "|| id",
    "\x00; id",  # null byte
]

# Shell output indicators
_RCE_INDICATORS = re.compile(
    r'(uid=\d+|gid=\d+|root:[a-zA-Z!*]|/bin/sh|/bin/bash)',
    re.IGNORECASE,
)


def _get_tool_list(target: str, headers: dict) -> list[dict] | None:
    """Fetch /tools/list and return parsed tool list, or None on error."""
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
    return None


# ─── 3.1 ─────────────────────────────────────────────────────────────────────
def check_3_1(target: str, api_key: str, headers: dict) -> CheckResult:
    """No hidden callable tools — brute-force wordlist against /tools/call."""
    found: list[str] = []
    try:
        for name in HIDDEN_TOOL_NAMES:
            resp = requests.post(
                f"{target}/tools/call",
                json={"name": name, "arguments": {}},
                headers=headers,
                timeout=_TIMEOUT,
            )
            # Not-404 means the tool exists (even if it errors on bad args)
            if resp.status_code != 404:
                found.append(name)
        if not found:
            return CheckResult(
                id="3.1", category="Tool Exposure",
                description="No hidden callable tools",
                status="PASS",
                detail="All wordlist tool names returned 404 on /tools/call.",
                remediation="",
            )
        return CheckResult(
            id="3.1", category="Tool Exposure",
            description="No hidden callable tools",
            status="FAIL",
            detail=f"Hidden tool(s) responded (not 404): {', '.join(found)}",
            remediation="Remove all unlisted/hidden tools or gate them behind a separate elevated auth mechanism.",
        )
    except RequestException as exc:
        return CheckResult(
            id="3.1", category="Tool Exposure",
            description="No hidden callable tools",
            status="SKIP",
            detail=f"Request error during hidden tool probe: {exc}",
            remediation="",
        )

check_3_1.check_id = "3.1"
check_3_1.category = "Tool Exposure"
check_3_1.description = "No hidden callable tools"


# ─── 3.2 ─────────────────────────────────────────────────────────────────────
def check_3_2(target: str, api_key: str, headers: dict) -> CheckResult:
    """Dangerous tool names absent from /tools/list."""
    tool_list = _get_tool_list(target, headers)
    if tool_list is None:
        return CheckResult(
            id="3.2", category="Tool Exposure",
            description="Dangerous tool names absent",
            status="SKIP",
            detail="Could not retrieve /tools/list (auth required or server error).",
            remediation="",
        )
    dangerous: list[str] = []
    for tool in tool_list:
        name = tool.get("name", "") if isinstance(tool, dict) else str(tool)
        if _DANGEROUS_PATTERNS.search(name):
            dangerous.append(name)
    if not dangerous:
        return CheckResult(
            id="3.2", category="Tool Exposure",
            description="Dangerous tool names absent",
            status="PASS",
            detail="No dangerous tool name patterns found in /tools/list.",
            remediation="",
        )
    return CheckResult(
        id="3.2", category="Tool Exposure",
        description="Dangerous tool names absent",
        status="FAIL",
        detail=f"Dangerous tool name(s) found: {', '.join(dangerous)}",
        remediation="Rename or remove tools with dangerous names (admin, dump, debug, exec, shell, eval). Adopt a strict allow-list naming convention.",
    )

check_3_2.check_id = "3.2"
check_3_2.category = "Tool Exposure"
check_3_2.description = "Dangerous tool names absent"


# ─── 3.3 ─────────────────────────────────────────────────────────────────────
def check_3_3(target: str, api_key: str, headers: dict) -> CheckResult:
    """Tool inputs validated — oversized/malformed args must return 400, not 500."""
    oversized_str = "A" * 100_000
    payloads = [
        {"name": "ping", "arguments": {"input": oversized_str}},
        {"name": "ping", "arguments": None},
        {"name": "ping", "arguments": {"__proto__": {"polluted": True}}},
    ]
    issues: list[str] = []
    try:
        for payload in payloads:
            resp = requests.post(
                f"{target}/tools/call",
                json=payload,
                headers=headers,
                timeout=_TIMEOUT,
            )
            if resp.status_code == 500:
                issues.append(f"Payload {list(payload['arguments'].keys()) if isinstance(payload.get('arguments'), dict) else 'null'} → 500")
        if not issues:
            return CheckResult(
                id="3.3", category="Tool Exposure",
                description="Tool inputs validated",
                status="PASS",
                detail="Malformed/oversized inputs did not produce 500 errors.",
                remediation="",
            )
        return CheckResult(
            id="3.3", category="Tool Exposure",
            description="Tool inputs validated",
            status="WARN",
            detail=f"Server returned 500 on malformed inputs: {'; '.join(issues)}",
            remediation="Validate all tool arguments server-side. Return 400 for invalid inputs. Never let unhandled exceptions propagate as 500.",
        )
    except RequestException as exc:
        return CheckResult(
            id="3.3", category="Tool Exposure",
            description="Tool inputs validated",
            status="SKIP",
            detail=f"Request error during input validation probe: {exc}",
            remediation="",
        )

check_3_3.check_id = "3.3"
check_3_3.category = "Tool Exposure"
check_3_3.description = "Tool inputs validated"


# ─── 3.4 ─────────────────────────────────────────────────────────────────────
def check_3_4(target: str, api_key: str, headers: dict) -> CheckResult:
    """Tool list doesn't leak filesystem paths or credentials."""
    tool_list = _get_tool_list(target, headers)
    if tool_list is None:
        return CheckResult(
            id="3.4", category="Tool Exposure",
            description="Tool list doesn't leak paths",
            status="SKIP",
            detail="Could not retrieve /tools/list.",
            remediation="",
        )
    leaks: list[str] = []
    for tool in tool_list:
        text = str(tool)
        for pattern in _LEAK_PATTERNS:
            match = pattern.search(text)
            if match:
                leaks.append(f"Tool {tool.get('name', '?') if isinstance(tool, dict) else '?'}: {match.group()!r}")
                break
    if not leaks:
        return CheckResult(
            id="3.4", category="Tool Exposure",
            description="Tool list doesn't leak paths",
            status="PASS",
            detail="No filesystem paths or credential patterns found in tool descriptions.",
            remediation="",
        )
    return CheckResult(
        id="3.4", category="Tool Exposure",
        description="Tool list doesn't leak paths",
        status="FAIL",
        detail=f"Sensitive data found in tool metadata: {'; '.join(leaks)}",
        remediation="Sanitize tool descriptions and parameter schemas. Remove any absolute paths, credentials, or internal configuration values.",
    )

check_3_4.check_id = "3.4"
check_3_4.category = "Tool Exposure"
check_3_4.description = "Tool list doesn't leak paths"


# ─── 3.5 ─────────────────────────────────────────────────────────────────────
def check_3_5(target: str, api_key: str, headers: dict) -> CheckResult:
    """No tool executes shell commands — RCE probe via shell metacharacters."""
    tool_list = _get_tool_list(target, headers) or []
    rce_hits: list[str] = []

    # Probe each listed tool + a generic "ping" tool name
    tool_names = [t.get("name") for t in tool_list if isinstance(t, dict) and t.get("name")]
    tool_names = list(dict.fromkeys(tool_names + ["ping", "echo", "run"]))[:10]  # Cap at 10

    try:
        for tool_name in tool_names:
            for payload in _RCE_PAYLOADS:
                for arg_name in ["input", "command", "cmd", "query", "path"]:
                    resp = requests.post(
                        f"{target}/tools/call",
                        json={"name": tool_name, "arguments": {arg_name: payload}},
                        headers=headers,
                        timeout=_TIMEOUT,
                    )
                    if _RCE_INDICATORS.search(resp.text):
                        rce_hits.append(f"{tool_name}({arg_name}={payload!r})")

        if not rce_hits:
            return CheckResult(
                id="3.5", category="Tool Exposure",
                description="No tool executes shell commands",
                status="PASS",
                detail="No RCE indicators detected in tool responses to shell metacharacter payloads.",
                remediation="",
            )
        return CheckResult(
            id="3.5", category="Tool Exposure",
            description="No tool executes shell commands",
            status="FAIL",
            detail=f"Possible RCE detected: {'; '.join(rce_hits)}",
            remediation="Do not pass user-supplied input to shell.exec(), subprocess, or os.system(). Use parameterized APIs. Sanitize all inputs.",
        )
    except RequestException as exc:
        return CheckResult(
            id="3.5", category="Tool Exposure",
            description="No tool executes shell commands",
            status="SKIP",
            detail=f"Request error during RCE probe: {exc}",
            remediation="",
        )

check_3_5.check_id = "3.5"
check_3_5.category = "Tool Exposure"
check_3_5.description = "No tool executes shell commands"
