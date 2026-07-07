"""
Terminal output renderer using Rich.

Prints:
  1. Banner (tool name, target, profile)
  2. Fingerprint + CVE block
  3. Check results grouped by category
  4. Score summary
"""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

from mcp_benchmark.core.models import AuditReport, CheckResult, Fingerprint

console = Console()

_STATUS_STYLE = {
    "PASS": "bold green",
    "FAIL": "bold red",
    "WARN": "bold yellow",
    "SKIP": "dim",
}

_STATUS_LABEL = {
    "PASS": "[PASS]",
    "FAIL": "[FAIL]",
    "WARN": "[WARN]",
    "SKIP": "[SKIP]",
}


def _render_banner(target: str, profile: str) -> None:
    title = Text("MCP Server Hardening Benchmark", style="bold white")
    content = (
        f"[dim cyan]Target :[/dim cyan] {target}\n"
        f"[dim cyan]Profile:[/dim cyan] {'Level 1 (Basic)' if profile == 'level1' else 'Level 2 (Hardened)'}"
    )
    console.print(
        Panel(content, title="[bold white]MCP Server Hardening Benchmark[/bold white]",
              border_style="bright_blue", padding=(0, 2)),
        "",
    )


def _render_fingerprint(fp: Fingerprint) -> None:
    console.print("[dim cyan]\\[~][/dim cyan] Fingerprinting...")
    console.print(f"[dim cyan]\\[~][/dim cyan] Framework : {fp.framework}")
    if fp.version:
        console.print(f"[dim cyan]\\[~][/dim cyan] Version   : v{fp.version}")
    else:
        console.print("[dim cyan]\\[~][/dim cyan] Version   : [dim]Unknown[/dim]")

    if fp.cves:
        for cve in fp.cves:
            note = cve.get("_note", "")
            note_str = f" [dim]({note})[/dim]" if note else ""
            console.print(
                f"[bold red]\\[!][/bold red] [bold]{cve['id']}[/bold]  "
                f"[red]{cve['severity']}[/red] "
                f"(CVSS {cve['cvss']}) — {cve['description']}{note_str}"
            )
            console.print(f"    [dim]→ {cve['url']}[/dim]")
    else:
        console.print("[green]\\[+][/green] No CVEs matched for detected framework/version")

    console.print("")
    console.print("[dim]Running audit...[/dim]")
    console.print("[dim]" + "-" * 50 + "[/dim]")
    console.print("")


def _render_results(results: list[CheckResult], verbose: bool = False) -> None:
    current_category = None
    for result in results:
        if result.category != current_category:
            current_category = result.category
            console.print(f"\n[bold white]{result.category}[/bold white]")

        style = _STATUS_STYLE.get(result.status, "")
        label = _STATUS_LABEL.get(result.status, f"[{result.status}]")
        line = f"  [{style}]{label}[/{style}] [dim]{result.id}[/dim]  {result.description}"
        console.print(line)

        # Always show detail for FAIL; show for all if verbose
        if result.status == "FAIL" or verbose:
            if result.detail:
                console.print(f"         [dim]{result.detail}[/dim]")
            if result.remediation and result.status in ("FAIL", "WARN"):
                console.print(f"         [yellow]-> Fix:[/yellow] [dim]{result.remediation}[/dim]")


def _render_summary(report: AuditReport) -> None:
    console.print("")
    console.print("[dim]" + "-" * 50 + "[/dim]")

    pct = report.percent
    level_style = "bold green" if report.level == "PASS" else "bold red"
    level_icon = "[PASS]" if report.level == "PASS" else "[FAIL]"

    console.print(f"Score   : [bold]{report.score} / {report.max_score}[/bold]   ({pct}%)")
    console.print(
        f"Profile : {'Level 1' if report.profile == 'level1' else 'Level 2'} - "
        f"[{level_style}]{level_icon} {report.level}[/{level_style}]"
    )
    console.print("[dim]" + "-" * 50 + "[/dim]")


def render_report(report: AuditReport, verbose: bool = False) -> None:
    """
    Render a complete AuditReport to the terminal.

    Args:
        report:  The completed AuditReport.
        verbose: If True, show detail and remediation for all results (not just FAILs).
    """
    _render_banner(report.target, report.profile)
    if report.fingerprint:
        _render_fingerprint(report.fingerprint)
    _render_results(report.results, verbose=verbose)
    _render_summary(report)
