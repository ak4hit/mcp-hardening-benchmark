"""
Audit runner for mcp-hardening-benchmark.

Orchestrates all check categories, calls fingerprinting first,
then assembles a complete AuditReport.
"""
from __future__ import annotations

import datetime
from typing import Optional

from mcp_benchmark.core.fingerprint import fingerprint as run_fingerprint
from mcp_benchmark.core.models import AuditReport, CheckResult
from mcp_benchmark.core.scorer import build_report

# ─── Category imports ─────────────────────────────────────────────────────────
from mcp_benchmark.checks.auth_checks import (
    check_1_1, check_1_2, check_1_3, check_1_4, check_1_5,
)
from mcp_benchmark.checks.transport_checks import (
    check_2_1, check_2_2, check_2_3, check_2_4,
)
from mcp_benchmark.checks.tool_checks import (
    check_3_1, check_3_2, check_3_3, check_3_4, check_3_5,
)
from mcp_benchmark.checks.process_checks import (
    check_4_1, check_4_2, check_4_3, check_4_4,
)
from mcp_benchmark.checks.secret_checks import (
    check_5_1, check_5_2, check_5_3, check_5_4,
)
from mcp_benchmark.checks.logging_checks import (
    check_6_1, check_6_2, check_6_3, check_6_4,
)
from mcp_benchmark.checks.network_checks import (
    check_7_1, check_7_2, check_7_3,
)

# ─── Category registry ────────────────────────────────────────────────────────
# Checks that invoke /tools/call — skipped in passive mode
_ACTIVE_CHECK_IDS = {"1.2", "3.3", "3.5"}

# Per-category grouping for filtered runs
_CATEGORY_MAP: dict[str, list] = {
    "auth":      [check_1_1, check_1_2, check_1_3, check_1_4, check_1_5],
    "transport": [check_2_1, check_2_2, check_2_3, check_2_4],
    "tools":     [check_3_1, check_3_2, check_3_3, check_3_4, check_3_5],
    "process":   [check_4_1, check_4_2, check_4_3, check_4_4],
    "secrets":   [check_5_1, check_5_2, check_5_3, check_5_4],
    "logging":   [check_6_1, check_6_2, check_6_3, check_6_4],
    "network":   [check_7_1, check_7_2, check_7_3],
}

_ALL_CHECKS = [
    check_1_1, check_1_2, check_1_3, check_1_4, check_1_5,
    check_2_1, check_2_2, check_2_3, check_2_4,
    check_3_1, check_3_2, check_3_3, check_3_4, check_3_5,
    check_4_1, check_4_2, check_4_3, check_4_4,
    check_5_1, check_5_2, check_5_3, check_5_4,
    check_6_1, check_6_2, check_6_3, check_6_4,
    check_7_1, check_7_2, check_7_3,
]


def _make_skip(check_fn, reason: str) -> CheckResult:
    """Return a SKIP CheckResult using a check function's expected ID/category."""
    # Each check function exposes .check_id and .category as attributes
    # (set at the module level). Fall back gracefully if not present.
    check_id = getattr(check_fn, "check_id", "?")
    category = getattr(check_fn, "category", "Unknown")
    description = getattr(check_fn, "description", check_fn.__name__)
    return CheckResult(
        id=check_id,
        category=category,
        description=description,
        status="SKIP",
        detail=reason,
        remediation="",
    )


def run_audit(
    target: str,
    api_key: str,
    profile: str = "level1",
    passive: bool = False,
    auth_type: str = "apikey",
    category: Optional[str] = None,
    min_score: Optional[int] = None,
) -> AuditReport:
    """
    Run a full MCP server audit.

    1. Fingerprint the server (always runs)
    2. Execute all applicable checks (respecting profile / passive / category filters)
    3. Score results and return an AuditReport

    Args:
        target:     Base URL of the MCP server.
        api_key:    API key or Bearer token.
        profile:    'level1' | 'level2'
        passive:    If True, skip any check that makes a /tools/call request.
        auth_type:  'apikey' → X-API-Key header | 'bearer' → Authorization: Bearer
        category:   If set, run only checks in that category (e.g. 'auth', 'tools').
        min_score:  CI pass threshold (0–100). None means use default 70%.

    Returns:
        Fully populated AuditReport.
    """
    target = target.rstrip("/")
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ── Build request headers ─────────────────────────────────────────────────
    if auth_type == "bearer":
        request_headers = {"Authorization": f"Bearer {api_key}"}
    else:
        request_headers = {"X-API-Key": api_key}

    # ── Step 1: Fingerprint ───────────────────────────────────────────────────
    fp = run_fingerprint(target, api_key)

    # ── Step 2: Select checks ─────────────────────────────────────────────────
    if category:
        check_fns = _CATEGORY_MAP.get(category, _ALL_CHECKS)
    else:
        check_fns = _ALL_CHECKS

    # ── Step 3: Execute checks ────────────────────────────────────────────────
    results: list[CheckResult] = []
    for check_fn in check_fns:
        check_id = getattr(check_fn, "check_id", "?")

        # Passive mode: skip active probes
        if passive and check_id in _ACTIVE_CHECK_IDS:
            results.append(_make_skip(check_fn, "Skipped — passive mode active (no /tools/call)"))
            continue

        try:
            result = check_fn(target=target, api_key=api_key, headers=request_headers)
        except Exception as exc:  # noqa: BLE001
            # Never let a check crash the entire audit
            result = CheckResult(
                id=check_id,
                category=getattr(check_fn, "category", "Unknown"),
                description=getattr(check_fn, "description", check_fn.__name__),
                status="SKIP",
                detail=f"Check raised an unexpected exception: {exc}",
                remediation="",
            )
        results.append(result)

    # ── Step 4: Score + assemble report ──────────────────────────────────────
    return build_report(
        target=target,
        profile=profile,
        timestamp=timestamp,
        results=results,
        min_score=min_score,
        fingerprint=fp,
    )
