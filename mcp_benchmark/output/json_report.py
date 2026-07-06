"""
JSON report exporter for mcp-hardening-benchmark.
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import IO

from mcp_benchmark.core.models import AuditReport


def _report_to_dict(report: AuditReport) -> dict:
    """Convert AuditReport to a serialisable dict."""
    results = [
        {
            "id": r.id,
            "category": r.category,
            "description": r.description,
            "status": r.status,
            "detail": r.detail,
            "remediation": r.remediation,
        }
        for r in report.results
    ]

    fingerprint = None
    if report.fingerprint:
        fp = report.fingerprint
        fingerprint = {
            "framework": fp.framework,
            "version": fp.version,
            "cves": fp.cves,
        }

    return {
        "target": report.target,
        "profile": report.profile,
        "timestamp": report.timestamp,
        "score": report.score,
        "max_score": report.max_score,
        "percent": report.percent,
        "level": report.level,
        "fingerprint": fingerprint,
        "results": results,
    }


def export_json(report: AuditReport, output_path: str | Path | None = None) -> str:
    """
    Serialise report to JSON.

    Args:
        report:       The AuditReport to export.
        output_path:  If given, write JSON to this file. If None, return as string.

    Returns:
        JSON string (always returned, even when writing to file).
    """
    data = _report_to_dict(report)
    json_str = json.dumps(data, indent=2, ensure_ascii=False)

    if output_path:
        Path(output_path).write_text(json_str, encoding="utf-8")

    return json_str
