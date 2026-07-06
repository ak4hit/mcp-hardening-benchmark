"""
SARIF 2.1.0 report exporter for mcp-hardening-benchmark.

SARIF (Static Analysis Results Interchange Format) output for GitHub Code Scanning.

Upload with:
  gh code-scanning upload-results --sarif results.sarif

FAIL  → SARIF level: error
WARN  → SARIF level: warning
PASS/SKIP → not included
"""
from __future__ import annotations

import json
from pathlib import Path

from mcp_benchmark.core.models import AuditReport

_TOOL_NAME = "mcp-hardening-benchmark"
_TOOL_VERSION = "1.0.0"
_TOOL_URI = "https://github.com/ak4hit/mcp-hardening-benchmark"
_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

_STATUS_TO_LEVEL = {
    "FAIL": "error",
    "WARN": "warning",
}


def export_sarif(report: AuditReport, output_path: str | Path | None = None) -> str:
    """
    Export audit report in SARIF 2.1.0 format.

    Args:
        report:       The AuditReport to export.
        output_path:  If given, write SARIF JSON to this file.

    Returns:
        SARIF JSON string.
    """
    # Collect rules from all results
    rules = {}
    for result in report.results:
        if result.id not in rules:
            rules[result.id] = {
                "id": f"MCP{result.id.replace('.', '')}",
                "name": result.description.replace(" ", ""),
                "shortDescription": {"text": result.description},
                "fullDescription": {"text": result.description},
                "help": {"text": result.remediation or "No remediation available."},
                "properties": {
                    "category": result.category,
                    "checkId": result.id,
                },
            }

    # Collect SARIF results (only FAIL and WARN)
    sarif_results = []
    for result in report.results:
        level = _STATUS_TO_LEVEL.get(result.status)
        if level is None:
            continue
        sarif_results.append({
            "ruleId": f"MCP{result.id.replace('.', '')}",
            "level": level,
            "message": {
                "text": result.detail or result.description,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": report.target,
                            "uriBaseId": "%SRCROOT%",
                        }
                    }
                }
            ],
            "properties": {
                "remediation": result.remediation,
                "category": result.category,
            },
        })

    sarif_doc = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": _TOOL_VERSION,
                        "informationUri": _TOOL_URI,
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
                "properties": {
                    "target": report.target,
                    "profile": report.profile,
                    "timestamp": report.timestamp,
                    "score": report.score,
                    "maxScore": report.max_score,
                    "percent": report.percent,
                    "level": report.level,
                },
            }
        ],
    }

    sarif_str = json.dumps(sarif_doc, indent=2, ensure_ascii=False)
    if output_path:
        Path(output_path).write_text(sarif_str, encoding="utf-8")
    return sarif_str
