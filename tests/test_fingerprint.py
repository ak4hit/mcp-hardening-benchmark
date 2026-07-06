"""Tests for server fingerprinting engine."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from packaging.version import Version

from mcp_benchmark.core.fingerprint import (
    fingerprint,
    _match_cves,
    _version_affected,
    _detect_from_headers,
    _detect_from_body,
    _extract_version,
)
from mcp_benchmark.core.models import Fingerprint


# ─── Version constraint tests ─────────────────────────────────────────────────

def test_version_affected_lte_true():
    assert _version_affected("1.4.2", "<=1.4.2") is True


def test_version_affected_lte_false():
    assert _version_affected("1.5.0", "<=1.4.2") is False


def test_version_affected_lt_boundary():
    assert _version_affected("1.4.2", "<1.4.3") is True


def test_version_affected_unknown_version_conservative():
    """Unknown version should be treated as affected (conservative)."""
    assert _version_affected(None, "<=1.4.2") is True


def test_version_affected_unrecognised_operator():
    assert _version_affected("1.0.0", "~=1.0.0") is True  # Conservative fallback


# ─── CVE matching tests ────────────────────────────────────────────────────────

SAMPLE_CVES = [
    {
        "id": "CVE-2026-23744",
        "framework": "MCPJam",
        "affected_versions": ["<=1.4.2"],
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Test CVE",
        "url": "https://example.com",
    },
    {
        "id": "CVE-2025-49596",
        "framework": "MCPJam",
        "affected_versions": ["<=1.3.0"],
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Test CVE 2",
        "url": "https://example.com/2",
    },
]


def test_cve_matched_for_affected_version():
    """MCPJam 1.4.2 should match CVE-2026-23744 (<=1.4.2)."""
    matched = _match_cves("MCPJam", "1.4.2", SAMPLE_CVES)
    ids = [c["id"] for c in matched]
    assert "CVE-2026-23744" in ids


def test_no_cve_for_patched_version():
    """MCPJam 1.5.0 should NOT match CVE-2026-23744 (<=1.4.2)."""
    matched = _match_cves("MCPJam", "1.5.0", SAMPLE_CVES)
    ids = [c["id"] for c in matched]
    assert "CVE-2026-23744" not in ids


def test_cve_not_matched_for_different_framework():
    matched = _match_cves("Flask", "1.4.2", SAMPLE_CVES)
    assert matched == []


def test_unknown_version_flags_all_cves_as_warn():
    """Unknown version → all CVEs for the framework flagged with _note."""
    matched = _match_cves("MCPJam", None, SAMPLE_CVES)
    assert len(matched) >= 1
    for cve in matched:
        assert "_note" in cve
        assert "manual verification" in cve["_note"]


# ─── Header / body detection tests ────────────────────────────────────────────

def test_mcpjam_detected_from_headers():
    headers = {"Server": "MCPJam/1.4.2"}
    framework, signals = _detect_from_headers(headers)
    assert framework == "MCPJam"


def test_flask_detected_from_headers():
    headers = {"Server": "Werkzeug/3.0.0 Python/3.11"}
    framework, signals = _detect_from_headers(headers)
    assert framework == "Flask"


def test_nodejs_detected_from_headers():
    headers = {"X-Powered-By": "Express"}
    framework, signals = _detect_from_headers(headers)
    assert framework == "Node.js"


def test_unknown_framework_graceful():
    headers = {"Content-Type": "application/json"}
    framework, signals = _detect_from_headers(headers)
    assert framework is None  # Body detection will be attempted next


def test_mcpjam_detected_from_body():
    body = "MCPJam Inspector v1.4.2 — ready"
    assert _detect_from_body(body) == "MCPJam"


def test_version_extracted_from_json_body():
    body = '{"server": "OPSMCP", "version": "2.1.0"}'
    version = _extract_version(body, {})
    assert version == "2.1.0"


def test_version_extracted_from_semver_in_body():
    body = "MCPJam Version: v1.4.2"
    version = _extract_version(body, {})
    assert version == "1.4.2"


# ─── Integration test with mock HTTP ─────────────────────────────────────────

def test_fingerprint_returns_unknown_on_connection_error():
    """If the server is unreachable, fingerprint should return 'Unknown' gracefully."""
    with patch("mcp_benchmark.core.fingerprint.requests.get") as mock_get:
        from requests.exceptions import ConnectionError as ConnErr
        mock_get.side_effect = ConnErr("Connection refused")
        result = fingerprint("http://localhost:19999", "")
    assert result.framework == "Unknown"
    assert result.version is None
    assert result.cves == []


def test_fingerprint_returns_mcpjam_with_cves():
    """Full fingerprint run against a mock MCPJam server response."""
    mock_resp = MagicMock()
    mock_resp.headers = {"Server": "MCPJam/1.4.2"}
    mock_resp.text = '{"server": "MCPJam", "version": "1.4.2"}'
    mock_resp.status_code = 200

    with patch("mcp_benchmark.core.fingerprint.requests.get", return_value=mock_resp):
        with patch("mcp_benchmark.core.fingerprint._load_cve_db", return_value=SAMPLE_CVES):
            result = fingerprint("http://localhost:5000", "key123")

    assert result.framework == "MCPJam"
    assert result.version == "1.4.2"
    assert len(result.cves) >= 1
