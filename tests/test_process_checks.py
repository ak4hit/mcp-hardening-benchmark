"""Tests for process_checks (Category 4)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mcp_benchmark.checks.process_checks import (
    check_4_1, check_4_2, check_4_3, check_4_4,
)


TARGET = "http://localhost:15000"
HEADERS = {"X-API-Key": "test123"}


def _mock_response(status_code: int, text: str = "") -> MagicMock:
    m = MagicMock()
    m.status_code = status_code
    m.text = text
    return m


# ─── 4.1 ─────────────────────────────────────────────────────────────────────

def test_4_1_fail_when_uid_0_in_response():
    mock = _mock_response(200, '{"process": "uid=0(root) gid=0(root)"}')
    with patch("mcp_benchmark.checks.process_checks.requests.get", return_value=mock):
        with patch("mcp_benchmark.checks.process_checks.requests.post", return_value=mock):
            result = check_4_1(TARGET, "key", HEADERS)
    assert result.status == "FAIL"
    assert "uid=0" in result.detail or "root" in result.detail.lower()


def test_4_1_warn_when_no_root_indicators():
    mock = _mock_response(200, '{"status": "ok"}')
    with patch("mcp_benchmark.checks.process_checks.requests.get", return_value=mock):
        with patch("mcp_benchmark.checks.process_checks.requests.post", return_value=mock):
            result = check_4_1(TARGET, "key", HEADERS)
    # WARN because HTTP heuristic alone is unreliable
    assert result.status == "WARN"


# ─── 4.2–4.4 SKIP ─────────────────────────────────────────────────────────────

def test_4_2_always_skips():
    result = check_4_2(TARGET, "key", HEADERS)
    assert result.status == "SKIP"


def test_4_3_always_skips():
    result = check_4_3(TARGET, "key", HEADERS)
    assert result.status == "SKIP"


def test_4_4_always_skips():
    result = check_4_4(TARGET, "key", HEADERS)
    assert result.status == "SKIP"


def test_skip_includes_manual_instructions():
    """SKIP results must include a manual command the user can run."""
    for fn in (check_4_2, check_4_3, check_4_4):
        result = fn(TARGET, "key", HEADERS)
        assert "Run manually" in result.detail or "requires local" in result.detail
