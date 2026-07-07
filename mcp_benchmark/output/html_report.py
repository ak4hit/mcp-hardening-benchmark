"""
HTML report exporter using Jinja2.

Produces a fully self-contained single-page HTML file:
- Score badge at top (red/green)
- Category-by-category breakdown
- Collapsible remediation blocks on FAIL/WARN items
- No external CSS/JS dependencies — offline-safe
"""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, BaseLoader

from mcp_benchmark.core.models import AuditReport

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MCP Hardening Benchmark Report — {{ report.target }}</title>
<style>
  :root {
    --pass: #22c55e; --fail: #ef4444; --warn: #f59e0b; --skip: #94a3b8;
    --bg: #0f172a; --card: #1e293b; --border: #334155; --text: #e2e8f0;
    --text-dim: #94a3b8; --font: 'Segoe UI', system-ui, sans-serif;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font); padding: 2rem; }
  h1 { font-size: 1.5rem; margin-bottom: 0.25rem; }
  .subtitle { color: var(--text-dim); font-size: 0.9rem; margin-bottom: 2rem; }
  .score-badge {
    display: inline-block; padding: 0.5rem 1.5rem; border-radius: 999px;
    font-size: 1.25rem; font-weight: bold; margin-bottom: 1.5rem;
    background: {{ '#22c55e' if report.level == 'PASS' else '#ef4444' }};
    color: white;
  }
  .meta { display: flex; gap: 2rem; margin-bottom: 2rem; flex-wrap: wrap; }
  .meta-item { background: var(--card); border: 1px solid var(--border); padding: 0.75rem 1rem; border-radius: 8px; }
  .meta-label { font-size: 0.75rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.05em; }
  .meta-value { font-size: 1rem; font-weight: 600; margin-top: 0.25rem; }
  .category { margin-bottom: 1.5rem; }
  .category-title { font-size: 1rem; font-weight: 700; padding: 0.5rem 0; border-bottom: 1px solid var(--border); margin-bottom: 0.5rem; }
  .check { padding: 0.5rem 0; border-bottom: 1px solid var(--border); }
  .check-header { display: flex; align-items: center; gap: 0.75rem; }
  .badge { font-size: 0.7rem; font-weight: bold; padding: 0.2rem 0.5rem; border-radius: 4px; min-width: 3.5rem; text-align: center; }
  .badge-PASS { background: var(--pass); color: #fff; }
  .badge-FAIL { background: var(--fail); color: #fff; }
  .badge-WARN { background: var(--warn); color: #000; }
  .badge-SKIP { background: var(--skip); color: #fff; }
  .check-id { color: var(--text-dim); font-size: 0.85rem; min-width: 2rem; }
  .check-desc { flex: 1; }
  .check-detail { font-size: 0.8rem; color: var(--text-dim); margin-top: 0.35rem; padding-left: 5.5rem; }
  details > summary { cursor: pointer; list-style: none; }
  details > summary::-webkit-details-marker { display: none; }
  .remediation { font-size: 0.8rem; color: #fbbf24; margin-top: 0.25rem; padding-left: 5.5rem; }
  .remediation::before { content: "→ Fix: "; font-weight: bold; }
  .fingerprint { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem; }
  .fingerprint-title { font-weight: 700; margin-bottom: 0.5rem; }
  .cve { color: #ef4444; font-weight: 600; }
  .cve-url { font-size: 0.8rem; color: var(--text-dim); }
  footer { margin-top: 3rem; color: var(--text-dim); font-size: 0.8rem; }
</style>
</head>
<body>
<h1>MCP Server Hardening Benchmark</h1>
<div class="subtitle">{{ report.target }} &nbsp;·&nbsp; {{ report.timestamp }} &nbsp;·&nbsp; Profile: {{ report.profile }}</div>

<div class="score-badge">{{ report.level }} &nbsp; {{ report.score }}/{{ report.max_score }} ({{ report.percent }}%)</div>

<div class="meta">
  <div class="meta-item"><div class="meta-label">Target</div><div class="meta-value">{{ report.target }}</div></div>
  <div class="meta-item"><div class="meta-label">Profile</div><div class="meta-value">{{ report.profile }}</div></div>
  <div class="meta-item"><div class="meta-label">Score</div><div class="meta-value">{{ report.score }} / {{ report.max_score }}</div></div>
  <div class="meta-item"><div class="meta-label">Percent</div><div class="meta-value">{{ report.percent }}%</div></div>
  <div class="meta-item"><div class="meta-label">Overall</div><div class="meta-value" style="color: {{ '#22c55e' if report.level == 'PASS' else '#ef4444' }}">{{ report.level }}</div></div>
  <div class="meta-item"><div class="meta-label">Timestamp</div><div class="meta-value">{{ report.timestamp }}</div></div>
</div>

{% if report.fingerprint %}
<div class="fingerprint">
  <div class="fingerprint-title">🔍 Server Fingerprint</div>
  <div>Framework: <strong>{{ report.fingerprint.framework }}</strong></div>
  {% if report.fingerprint.version %}<div>Version: <strong>v{{ report.fingerprint.version }}</strong></div>{% endif %}
  {% if report.fingerprint.cves %}
    {% for cve in report.fingerprint.cves %}
    <div class="cve" style="margin-top:0.5rem;">⚠ {{ cve.id }} — {{ cve.severity }} (CVSS {{ cve.cvss }}) — {{ cve.description }}</div>
    <div class="cve-url">{{ cve.url }}</div>
    {% endfor %}
  {% else %}
    <div style="color: var(--pass); margin-top:0.5rem;">✓ No CVEs matched</div>
  {% endif %}
</div>
{% endif %}

{% set categories = [] %}
{% for result in report.results %}
  {% if result.category not in categories %}
    {% set _ = categories.append(result.category) %}
  {% endif %}
{% endfor %}

{% for category in categories %}
<div class="category">
  <div class="category-title">{{ category }}</div>
  {% for result in report.results if result.category == category %}
  <div class="check">
    {% if result.status in ('FAIL', 'WARN') and result.remediation %}
    <details>
      <summary>
        <div class="check-header">
          <span class="badge badge-{{ result.status }}">{{ result.status }}</span>
          <span class="check-id">{{ result.id }}</span>
          <span class="check-desc">{{ result.description }}</span>
        </div>
        {% if result.detail %}<div class="check-detail">{{ result.detail }}</div>{% endif %}
      </summary>
      <div class="remediation">{{ result.remediation }}</div>
    </details>
    {% else %}
    <div class="check-header">
      <span class="badge badge-{{ result.status }}">{{ result.status }}</span>
      <span class="check-id">{{ result.id }}</span>
      <span class="check-desc">{{ result.description }}</span>
    </div>
    {% if result.detail %}<div class="check-detail">{{ result.detail }}</div>{% endif %}
    {% endif %}
  </div>
  {% endfor %}
</div>
{% endfor %}

<footer>Generated by mcp-hardening-benchmark &nbsp;·&nbsp; github.com/ak4hit/mcp-hardening-benchmark</footer>
</body>
</html>"""


def export_html(report: AuditReport, output_path: str | Path | None = None) -> str:
    """
    Render report as a self-contained HTML page.

    Args:
        report:       The AuditReport to export.
        output_path:  If given, write HTML to this file. If None, return as string.

    Returns:
        HTML string (always returned, even when writing to file).
    """
    env = Environment(loader=BaseLoader())
    template = env.from_string(_HTML_TEMPLATE)
    html = template.render(report=report)

    if output_path:
        Path(output_path).write_text(html, encoding="utf-8")

    return html
