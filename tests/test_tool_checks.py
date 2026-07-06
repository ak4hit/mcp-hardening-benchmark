"""Tests for tool_checks (Category 3)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mcp_benchmark.checks.tool_checks import (
    check_3_1, check_3_2, check_3_4,
    HIDDEN_TOOL_NAMES,
)


TARGET = "http://localhost:15000"
HEADERS = {"X-API-Key": "test123"}


def _mock_response(status_code: int, text: str = "", json_data=None) -> MagicMock:
    m = MagicMock()
    m.status_code = status_code
    m.text = text
    m.json.return_value = json_data if json_data is not None else {}
    return m


# ─── 3.1 ─────────────────────────────────────────────────────────────────────

def test_3_1_pass_when_all_hidden_tools_return_404():
    with patch("mcp_benchmark.checks.tool_checks.requests.post",
               return_value=_mock_response(404)):
        result = check_3_1(TARGET, "key", HEADERS)
    assert result.status == "PASS"


def test_3_1_fail_when_hidden_tool_responds():
    """Simulate ops._admin_dump returning 200."""
    responses = {}
    for name in HIDDEN_TOOL_NAMES:
        if name == "ops._admin_dump":
            responses[name] = _mock_response(200, '{"result": "data"}')
        else:
            responses[name] = _mock_response(404)

    call_count = [0]
    def side_effect(url, json, headers, timeout):
        call_count[0] += 1
        name = json.get("name", "")
        return responses.get(name, _mock_response(404))

    with patch("mcp_benchmark.checks.tool_checks.requests.post", side_effect=side_effect):
        result = check_3_1(TARGET, "key", HEADERS)
    assert result.status == "FAIL"
    assert "ops._admin_dump" in result.detail


def test_hidden_tool_wordlist_not_empty():
    assert len(HIDDEN_TOOL_NAMES) >= 20


# ─── 3.2 ─────────────────────────────────────────────────────────────────────

def test_3_2_pass_when_no_dangerous_names():
    safe_tools = [{"name": "ping"}, {"name": "echo"}, {"name": "search"}]
    with patch("mcp_benchmark.checks.tool_checks.requests.get",
               return_value=_mock_response(200, json_data=safe_tools)):
        result = check_3_2(TARGET, "key", HEADERS)
    assert result.status == "PASS"


def test_3_2_fail_when_dangerous_name_present():
    dangerous_tools = [{"name": "admin_dump"}, {"name": "ping"}]
    with patch("mcp_benchmark.checks.tool_checks.requests.get",
               return_value=_mock_response(200, json_data=dangerous_tools)):
        result = check_3_2(TARGET, "key", HEADERS)
    assert result.status == "FAIL"
    assert "admin_dump" in result.detail


# ─── 3.4 ─────────────────────────────────────────────────────────────────────

def test_3_4_pass_when_no_path_leak():
    clean_tools = [{"name": "ping", "description": "A simple ping tool"}]
    with patch("mcp_benchmark.checks.tool_checks.requests.get",
               return_value=_mock_response(200, json_data=clean_tools)):
        result = check_3_4(TARGET, "key", HEADERS)
    assert result.status == "PASS"


def test_3_4_fail_when_path_in_description():
    leaky_tools = [{"name": "read", "description": "Reads from /home/ubuntu/secrets/config.json"}]
    with patch("mcp_benchmark.checks.tool_checks.requests.get",
               return_value=_mock_response(200, json_data=leaky_tools)):
        result = check_3_4(TARGET, "key", HEADERS)
    assert result.status == "FAIL"
