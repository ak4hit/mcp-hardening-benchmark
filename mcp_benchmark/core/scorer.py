"""
Scoring engine for mcp-hardening-benchmark.

Calculates weighted score from a list of CheckResult objects.
Supports Level 1 (basic) and Level 2 (hardened) profiles.
"""
from __future__ import annotations

from typing import Optional

from mcp_benchmark.core.models import AuditReport, CheckResult

# ─── Score weights ────────────────────────────────────────────────────────────
WEIGHTS: dict[str, Optional[float]] = {
    "PASS": 1.0,
    "WARN": 0.5,
    "FAIL": 0.0,
    "SKIP": None,  # Excluded from denominator
}

# ─── Profile check-ID sets ────────────────────────────────────────────────────
# Level 1 — minimum baseline (most critical checks only)
LEVEL1_CHECKS = {
    "1.1", "1.2", "1.3",           # Core auth
    "2.1", "2.2",                  # TLS + SSE
    "3.1", "3.2", "3.4",           # Hidden tools, dangerous names, path leak
    "4.1",                         # Root process (HTTP heuristic)
    "5.1", "5.4",                  # Secrets in descriptions, .env exposure
    "6.3", "6.4",                  # Health endpoint + version header
    "7.1",                         # Management port publicly bound
}

# Level 2 — all checks (hardened production)
LEVEL2_CHECKS = {
    "1.1", "1.2", "1.3", "1.4", "1.5",
    "2.1", "2.2", "2.3", "2.4",
    "3.1", "3.2", "3.3", "3.4", "3.5",
    "4.1", "4.2", "4.3", "4.4",
    "5.1", "5.2", "5.3", "5.4",
    "6.1", "6.2", "6.3", "6.4",
    "7.1", "7.2", "7.3",
}

PROFILES: dict[str, set[str]] = {
    "level1": LEVEL1_CHECKS,
    "level2": LEVEL2_CHECKS,
}


def calculate_score(
    results: list[CheckResult],
    profile: str = "level1",
    min_score: Optional[int] = None,
) -> tuple[int, int, str]:
    """
    Calculate weighted score for a list of CheckResults under the given profile.

    Args:
        results:    All check results from the audit runner.
        profile:    'level1' or 'level2'. Unknown profiles default to level1.
        min_score:  If set, 'FAIL' is returned as level when pct < min_score,
                    regardless of the 70% default threshold.

    Returns:
        (score, max_score, level) where score and max_score are integers
        and level is 'PASS' or 'FAIL'.
    """
    applicable_ids = PROFILES.get(profile, LEVEL1_CHECKS)

    weighted_sum = 0.0
    denominator = 0

    for result in results:
        if result.id not in applicable_ids:
            continue
        weight = WEIGHTS.get(result.status)
        if weight is None:  # SKIP — excluded
            continue
        weighted_sum += weight
        denominator += 1

    score = round(weighted_sum)
    max_score = denominator

    if max_score == 0:
        return 0, 0, "FAIL"

    pct = weighted_sum / max_score * 100
    threshold = min_score if min_score is not None else 70
    level = "PASS" if pct >= threshold else "FAIL"

    return score, max_score, level


def build_report(
    target: str,
    profile: str,
    timestamp: str,
    results: list[CheckResult],
    min_score: Optional[int] = None,
    fingerprint=None,
) -> AuditReport:
    """
    Assemble a complete AuditReport from raw check results.

    Args:
        target:      The MCP server URL that was audited.
        profile:     Audit profile ('level1' | 'level2').
        timestamp:   ISO-8601 UTC string.
        results:     List of CheckResult objects.
        min_score:   Optional CI pass threshold (0–100).
        fingerprint: Optional Fingerprint dataclass instance.

    Returns:
        A fully populated AuditReport.
    """
    score, max_score, level = calculate_score(results, profile, min_score)
    return AuditReport(
        target=target,
        profile=profile,
        timestamp=timestamp,
        results=results,
        score=score,
        max_score=max_score,
        level=level,
        fingerprint=fingerprint,
    )
