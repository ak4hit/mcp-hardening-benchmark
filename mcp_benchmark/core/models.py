"""
Data models / dataclasses for mcp-hardening-benchmark.

CheckResult  — result of a single audit check
Fingerprint  — server framework/version/CVE detection result
AuditReport  — full audit output assembled by the runner
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CheckResult:
    """Result of a single audit check."""

    id: str
    """Check identifier, e.g. '1.1'"""

    category: str
    """Human-readable category, e.g. 'Authentication'"""

    description: str
    """Short description of what the check verifies."""

    status: str
    """One of: PASS | FAIL | WARN | SKIP"""

    detail: str
    """Human-readable explanation of the outcome."""

    remediation: str
    """What to fix when status is FAIL or WARN. Empty string for PASS/SKIP."""

    def __post_init__(self) -> None:
        valid_statuses = {"PASS", "FAIL", "WARN", "SKIP"}
        if self.status not in valid_statuses:
            raise ValueError(f"Invalid status '{self.status}'. Must be one of {valid_statuses}.")


@dataclass
class Fingerprint:
    """Server framework / version detection result."""

    framework: str
    """Detected framework name, e.g. 'MCPJam' | 'FastMCP' | 'Flask' | 'Node.js' | 'Unknown'"""

    version: Optional[str]
    """Detected version string, e.g. '1.4.2', or None if undetected."""

    cves: list[dict] = field(default_factory=list)
    """CVEs matched against cve_db.json for this framework/version combination."""

    raw_signals: dict = field(default_factory=dict)
    """Headers / body patterns that led to framework/version detection."""


@dataclass
class AuditReport:
    """Full audit report produced by the runner."""

    target: str
    """The audited MCP server URL."""

    profile: str
    """Audit profile used, e.g. 'level1' | 'level2'."""

    timestamp: str
    """ISO-8601 UTC timestamp of when the audit ran."""

    results: list[CheckResult]
    """Ordered list of all check results."""

    score: int
    """Weighted score achieved (float mapped to int after rounding)."""

    max_score: int
    """Maximum achievable score (excluding SKIP checks)."""

    level: str
    """Overall outcome: 'PASS' | 'FAIL'"""

    fingerprint: Optional[Fingerprint] = None
    """Server fingerprint detected before checks ran. May be None on connection failure."""

    @property
    def percent(self) -> int:
        """Percentage score, 0–100."""
        if self.max_score == 0:
            return 0
        return round(self.score / self.max_score * 100)
