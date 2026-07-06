"""
Click-based CLI entry point for mcp-hardening-benchmark.

Usage:
  mcp-audit                              # Full interactive mode
  mcp-audit --target URL --api-key KEY   # Non-interactive
  mcp-audit --list-checks                # Print all check IDs and descriptions
  mcp-audit --target URL --api-key KEY --profile level2 --json --output report.json
  mcp-audit --target URL --api-key KEY --sarif --output results.sarif
  mcp-audit --target URL --api-key KEY --html --output report.html
  mcp-audit --target URL --api-key KEY --min-score 80   # CI gate
  mcp-audit --target URL --api-key KEY --passive        # Read-only probes only
  mcp-audit --target URL --api-key KEY --category auth  # Single category
  mcp-audit --target URL --api-key KEY --verbose        # Show remediation for all
"""
from __future__ import annotations

import sys
import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from mcp_benchmark.core.runner import run_audit, _ALL_CHECKS, _CATEGORY_MAP
from mcp_benchmark.output.terminal import render_report
from mcp_benchmark.output.json_report import export_json
from mcp_benchmark.output.html_report import export_html
from mcp_benchmark.output.sarif_report import export_sarif

console = Console()

_CATEGORIES = sorted(_CATEGORY_MAP.keys())

# ─── --list-checks helper ─────────────────────────────────────────────────────
def _list_checks() -> None:
    console.print("\n[bold white]All available checks:[/bold white]\n")
    current_cat = None
    for fn in _ALL_CHECKS:
        cat = getattr(fn, "category", "?")
        check_id = getattr(fn, "check_id", "?")
        desc = getattr(fn, "description", fn.__name__)
        if cat != current_cat:
            current_cat = cat
            console.print(f"  [bold cyan]{cat}[/bold cyan]")
        console.print(f"    [dim]{check_id}[/dim]  {desc}")
    console.print("")


# ─── Interactive prompt helpers ────────────────────────────────────────────────
def _prompt_target(existing: Optional[str]) -> str:
    if existing:
        return existing
    return click.prompt("? Enter target URL", default="http://localhost:5000")


def _prompt_api_key(existing: Optional[str]) -> str:
    if existing:
        return existing
    return click.prompt("? Enter API key", hide_input=True, default="")


def _prompt_auth_type(existing: Optional[str]) -> str:
    if existing:
        return existing
    return click.prompt("? Auth type", type=click.Choice(["apikey", "bearer"]), default="apikey")


def _prompt_profile(existing: Optional[str]) -> str:
    if existing:
        return existing
    return click.prompt("? Profile", type=click.Choice(["level1", "level2"]), default="level1")


def _prompt_output_format(json_flag: bool, html_flag: bool, sarif_flag: bool) -> str:
    """If none of the format flags are set, prompt interactively."""
    if json_flag:
        return "json"
    if html_flag:
        return "html"
    if sarif_flag:
        return "sarif"
    fmt = click.prompt(
        "? Output format",
        type=click.Choice(["terminal", "json", "html", "sarif"]),
        default="terminal",
    )
    return fmt


def _prompt_output_file(existing: Optional[str], fmt: str) -> Optional[str]:
    if existing:
        return existing
    if click.confirm("? Save report to file?", default=False):
        default_name = f"report.{fmt if fmt != 'terminal' else 'txt'}"
        return click.prompt("? Output file", default=default_name)
    return None


def _prompt_passive(existing: bool) -> bool:
    if existing:
        return True
    return click.confirm("? Passive mode? (no /tools/call probes)", default=False)


def _prompt_min_score(existing: Optional[int]) -> Optional[int]:
    if existing is not None:
        return existing
    if click.confirm("? Set minimum score for CI gate?", default=False):
        return click.prompt("? Minimum score (0–100)", type=int, default=80)
    return None


def _prompt_category(existing: Optional[str]) -> Optional[str]:
    if existing:
        return existing
    if click.confirm("? Run single category only?", default=False):
        return click.prompt(
            "? Category",
            type=click.Choice(_CATEGORIES),
        )
    return None


def _prompt_verbose(existing: bool) -> bool:
    if existing:
        return True
    return click.confirm("? Verbose output? (show remediation for all checks)", default=False)


# ─── CLI ──────────────────────────────────────────────────────────────────────
@click.command()
@click.option("--target",    default=None, help="MCP server base URL")
@click.option("--api-key",   default=None, help="API key or Bearer token", envvar="MCP_API_KEY")
@click.option("--auth-type", default=None, type=click.Choice(["apikey", "bearer"]), help="Auth scheme")
@click.option("--profile",   default=None, type=click.Choice(["level1", "level2"]), help="Audit profile")
@click.option("--json",      "use_json",   is_flag=True, default=False, help="JSON output format")
@click.option("--html",      "use_html",   is_flag=True, default=False, help="HTML output format")
@click.option("--sarif",     "use_sarif",  is_flag=True, default=False, help="SARIF output format")
@click.option("--output",    default=None, help="Output file path")
@click.option("--passive",   is_flag=True, default=False, help="Passive mode — no /tools/call probes")
@click.option("--min-score", default=None, type=int, help="CI gate — exit 1 if score below N")
@click.option("--category",  default=None, type=click.Choice(_CATEGORIES), help="Run single category")
@click.option("--verbose",   is_flag=True, default=False, help="Show remediation for all checks")
@click.option("--list-checks", "do_list",  is_flag=True, default=False, help="List all checks and exit")
def cli(
    target: Optional[str],
    api_key: Optional[str],
    auth_type: Optional[str],
    profile: Optional[str],
    use_json: bool,
    use_html: bool,
    use_sarif: bool,
    output: Optional[str],
    passive: bool,
    min_score: Optional[int],
    category: Optional[str],
    verbose: bool,
    do_list: bool,
) -> None:
    """MCP Server Hardening Benchmark — CIS-Style Security Audit Tool."""

    if do_list:
        _list_checks()
        return

    # ── Non-TTY / CI guard ────────────────────────────────────────────────────
    import os
    is_interactive = sys.stdin.isatty() and not os.environ.get("CI") and not os.environ.get("MCP_NONINTERACTIVE")
    if not is_interactive and (target is None or api_key is None):
        console.print(
            "[bold red][!][/bold red] Non-interactive mode detected. Required flags missing.\n"
            "    Usage: mcp-audit --target <url> --api-key <key>"
        )
        sys.exit(1)

    # ── Interactive prompts (only for missing values) ─────────────────────────
    if is_interactive:
        target = _prompt_target(target)
        api_key = _prompt_api_key(api_key)
        auth_type = _prompt_auth_type(auth_type)
        profile = _prompt_profile(profile)

        # Output format
        fmt = _prompt_output_format(use_json, use_html, use_sarif)
        use_json = fmt == "json"
        use_html = fmt == "html"
        use_sarif = fmt == "sarif"

        output = _prompt_output_file(output, fmt)
        passive = _prompt_passive(passive)
        min_score = _prompt_min_score(min_score)
        category = _prompt_category(category)
        verbose = _prompt_verbose(verbose)

        console.print(
            f"\n[green][+][/green] Configuration complete. "
            f"Starting audit against [bold]{target}[/bold]...\n"
        )
    else:
        # Non-interactive: fill in defaults for anything not supplied by flags
        auth_type = auth_type or "apikey"
        profile = profile or "level1"

    # ── Run audit ─────────────────────────────────────────────────────────────
    report = run_audit(
        target=target,
        api_key=api_key or "",
        profile=profile,
        passive=passive,
        auth_type=auth_type,
        category=category,
        min_score=min_score,
    )

    # ── Render / export ───────────────────────────────────────────────────────
    if use_json:
        json_str = export_json(report, output_path=output)
        if not output:
            print(json_str)
        else:
            console.print(f"[green][+][/green] JSON report saved: [bold]{output}[/bold]")

    elif use_html:
        export_html(report, output_path=output)
        if output:
            console.print(f"[green][+][/green] HTML report saved: [bold]{output}[/bold]")
        else:
            console.print("[yellow][!][/yellow] --html requires --output <file.html>")

    elif use_sarif:
        export_sarif(report, output_path=output)
        if output:
            console.print(f"[green][+][/green] SARIF report saved: [bold]{output}[/bold]")
        else:
            console.print("[yellow][!][/yellow] --sarif requires --output <file.sarif>")

    else:
        render_report(report, verbose=verbose)

        # Also save a timestamped JSON alongside terminal output if --output given
        if output:
            export_json(report, output_path=output)
            console.print(f"\n[green][+][/green] Report saved: [bold]{output}[/bold]")

    # ── CI exit code ──────────────────────────────────────────────────────────
    if min_score is not None and report.percent < min_score:
        console.print(
            f"\n[bold red][!][/bold red] Score {report.percent}% is below minimum {min_score}% — exiting with code 1"
        )
        sys.exit(1)
