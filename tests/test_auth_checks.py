"""Tests for auth_checks (Category 1)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mcp_benchmark.checks.auth_checks import (
    check_1_1, check_1_2, check_1_3, check_1_4, check_1_5,
)


TARGET = "http://localhost:15000"
HEADERS = {"X-API-Key": "test123"}


def _mock_response(status_code: int, text: str = "") -> MagicMock:
    m = MagicMock()
    m.status_code = status_code
    m.text = text
    m.json.return_value = {}
    return m


# ─── 1.1 ─────────────────────────────────────────────────────────────────────

def test_1_1_pass_when_401():
    with patch("mcp_benchmark.checks.auth_checks.requests.get",
               return_value=_mock_response(401)):
        result = check_1_1(TARGET, "key", HEADERS)
    assert result.status == "PASS"


def test_1_1_fail_when_200():
    with patch("mcp_benchmark.checks.auth_checks.requests.get",
               return_value=_mock_response(200)):
        result = check_1_1(TARGET, "key", HEADERS)
    assert result.status == "FAIL"


# ─── 1.2 ─────────────────────────────────────────────────────────────────────

def test_1_2_pass_when_401():
    with patch("mcp_benchmark.checks.auth_checks.requests.post",
               return_value=_mock_response(401)):
        result = check_1_2(TARGET, "key", HEADERS)
    assert result.status == "PASS"


def test_1_2_fail_when_200():
    with patch("mcp_benchmark.checks.auth_checks.requests.post",
               return_value=_mock_response(200)):
        result = check_1_2(TARGET, "key", HEADERS)
    assert result.status == "FAIL"


# ─── 1.3 ─────────────────────────────────────────────────────────────────────

def test_1_3_pass_when_all_weak_keys_rejected():
    with patch("mcp_benchmark.checks.auth_checks.requests.get",
               return_value=_mock_response(401)):
        result = check_1_3(TARGET, "key", HEADERS)
    assert result.status == "PASS"


def test_1_3_fail_when_blank_key_accepted():
    with patch("mcp_benchmark.checks.auth_checks.requests.get",
               return_value=_mock_response(200)):
        result = check_1_3(TARGET, "key", HEADERS)
    assert result.status == "FAIL"


# ─── 1.4 ─────────────────────────────────────────────────────────────────────

def test_1_4_pass_when_no_open_endpoints():
    with patch("mcp_benchmark.checks.auth_checks.requests.get",
               return_value=_mock_response(404)):
        result = check_1_4(TARGET, "key", HEADERS)
    assert result.status == "PASS"


def test_1_4_fail_when_health_returns_200():
    with patch("mcp_benchmark.checks.auth_checks.requests.get",
               return_value=_mock_response(200)):
        result = check_1_4(TARGET, "key", HEADERS)
    assert result.status == "FAIL"


# ─── 1.5 ─────────────────────────────────────────────────────────────────────

def test_1_5_pass_when_429_received():
    with patch("mcp_benchmark.checks.auth_checks.requests.get",
               return_value=_mock_response(429)):
        result = check_1_5(TARGET, "key", HEADERS)
    assert result.status == "PASS"


def test_1_5_warn_when_no_rate_limit():
    with patch("mcp_benchmark.checks.auth_checks.requests.get",
               return_value=_mock_response(401)):
        with patch("mcp_benchmark.checks.auth_checks.time.sleep"):
            result = check_1_5(TARGET, "key", HEADERS)
    assert result.status == "WARN"
