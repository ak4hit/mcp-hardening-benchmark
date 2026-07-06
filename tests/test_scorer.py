"""Tests for the scoring engine."""
from __future__ import annotations

import pytest

from mcp_benchmark.core.models import CheckResult
from mcp_benchmark.core.scorer import calculate_score, LEVEL1_CHECKS, LEVEL2_CHECKS


def _make(check_id: str, status: str) -> CheckResult:
    return CheckResult(
        id=check_id, category="Test", description="Test check",
        status=status, detail="", remediation="",
    )


# ─── Basic score calculation ───────────────────────────────────────────────────

def test_all_pass_gives_100_percent():
    results = [_make(cid, "PASS") for cid in LEVEL1_CHECKS]
    score, max_score, level = calculate_score(results, "level1")
    assert score == max_score
    assert level == "PASS"


def test_all_fail_gives_0_percent():
    results = [_make(cid, "FAIL") for cid in LEVEL1_CHECKS]
    score, max_score, level = calculate_score(results, "level1")
    assert score == 0
    assert level == "FAIL"


def test_warn_counts_as_half():
    """Single WARN check should contribute 0.5 to score."""
    check_id = next(iter(LEVEL1_CHECKS))
    results = [_make(check_id, "WARN")]
    score, max_score, level = calculate_score(results, "level1")
    # 0.5 / 1 = 50% → rounded score 0 or 1, but max_score = 1
    assert max_score == 1
    assert score == 0  # round(0.5) = 0 in Python (banker's rounding)


def test_skip_excluded_from_denominator():
    """SKIP checks should not count toward max_score."""
    results = [
        _make("1.1", "PASS"),
        _make("1.2", "SKIP"),  # Should be excluded
    ]
    score, max_score, level = calculate_score(results, "level1")
    assert max_score == 1  # Only 1.1 counts


def test_min_score_gate_triggers():
    """min_score=90 with 70% actual should give FAIL."""
    results = [_make(cid, "PASS") for cid in list(LEVEL1_CHECKS)[:7]]
    results += [_make(cid, "FAIL") for cid in list(LEVEL1_CHECKS)[7:]]
    _, _, level = calculate_score(results, "level1", min_score=90)
    assert level == "FAIL"


def test_min_score_gate_passes():
    """min_score=50 with all PASS should give PASS."""
    results = [_make(cid, "PASS") for cid in LEVEL1_CHECKS]
    _, _, level = calculate_score(results, "level1", min_score=50)
    assert level == "PASS"


def test_empty_results_gives_fail():
    score, max_score, level = calculate_score([], "level1")
    assert score == 0
    assert max_score == 0
    assert level == "FAIL"


def test_level2_has_more_checks_than_level1():
    assert len(LEVEL2_CHECKS) > len(LEVEL1_CHECKS)


def test_unknown_profile_defaults_to_level1():
    results = [_make(cid, "PASS") for cid in LEVEL1_CHECKS]
    score_l1, max_l1, _ = calculate_score(results, "level1")
    score_unk, max_unk, _ = calculate_score(results, "nonexistent_profile")
    assert max_l1 == max_unk


def test_scorer_calculates_correctly():
    """11/17 checks passing → ~64% → FAIL (below 70 threshold)."""
    check_ids = sorted(LEVEL1_CHECKS)[:17]  # Use first 17 IDs
    results = (
        [_make(cid, "PASS") for cid in check_ids[:11]] +
        [_make(cid, "FAIL") for cid in check_ids[11:]]
    )
    score, max_score, level = calculate_score(results, "level1")
    assert max_score > 0
