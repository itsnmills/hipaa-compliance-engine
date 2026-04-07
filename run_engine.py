#!/usr/bin/env python3
"""HIPAA Compliance Engine — CLI Entrypoint.

VerifAI Security — Continuous compliance monitoring for the 2025 HIPAA Security Rule.

Usage:
    python run_engine.py scan [--demo] [--category CATEGORY]
    python run_engine.py dashboard [--demo]
    python run_engine.py report [--demo] [--output PATH]
    python run_engine.py freshness [--demo]
    python run_engine.py check CONTROL_ID [--demo]
    python run_engine.py control CONTROL_ID
    python run_engine.py export [--demo] [--format csv]
    python run_engine.py history
"""

from __future__ import annotations

import csv
import json
import sys
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from engine.config import load_config, get_output_dir
from engine.orchestrator import ComplianceOrchestrator
from engine.models import ComplianceReport, get_score_band
from controls.registry import ControlRegistry
from reports.dashboard import (
    render_dashboard, render_freshness_detail, render_control_detail,
)
from reports.pdf_generator import generate_pdf

console = Console()


@click.group()
@click.version_option(version="1.0.0", prog_name="HIPAA Compliance Engine")
def cli():
    """VerifAI Security — HIPAA Compliance Engine.

    Continuous compliance monitoring for the 2025 HIPAA Security Rule.
    Verifies all 31 mandatory controls through automated technical checks.
    """
    pass


@cli.command()
@click.option("--demo", is_flag=True, help="Run in demo mode (Midwest Family Dental)")
@click.option("--category", type=str, default=None,
              help="Only scan a specific category (technical/administrative/physical/cross-cutting)")
@click.option("--config", "config_path", type=str, default=None, help="Path to config file")
def scan(demo: bool, category: str | None, config_path: str | None):
    """Run a full compliance scan against all controls."""
    if demo:
        _print_demo_banner()

    config = load_config(config_path, demo=demo)
    org_name = config["organization"]["name"]

    console.print(f"\n[bold cyan]Starting compliance scan for [white]{org_name}[/white]...[/bold cyan]\n")

    orchestrator = ComplianceOrchestrator(config, demo=demo)
    registry = orchestrator.registry

    controls = registry.all_controls
    if category:
        controls = [c for c in controls if c.category.lower() == category.lower()]
        console.print(f"[dim]Filtering to category: {category} ({len(controls)} controls)[/dim]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("[dim]{task.fields[status]}[/dim]"),
        console=console,
    ) as progress:
        task = progress.add_task(
            "Checking controls...",
            total=len(controls),
            status="",
        )

        def _callback(control_id: str, status: str):
            color = {"PASS": "green", "FAIL": "red", "PARTIAL": "yellow"}.get(status, "white")
            progress.update(task, advance=1, status=f"[{color}]{control_id}: {status}[/{color}]")

        report = orchestrator.run_all_checks(category=category, callback=_callback)

    console.print()
    render_dashboard(report, console)


@cli.command()
@click.option("--demo", is_flag=True, help="View demo dashboard")
@click.option("--config", "config_path", type=str, default=None, help="Path to config file")
def dashboard(demo: bool, config_path: str | None):
    """View the compliance dashboard."""
    if demo:
        _print_demo_banner()

    config = load_config(config_path, demo=demo)
    orchestrator = ComplianceOrchestrator(config, demo=demo)
    report = orchestrator.run_all_checks()
    render_dashboard(report, console)


@cli.command()
@click.option("--demo", is_flag=True, help="Generate demo report")
@click.option("--output", "output_path", type=str, default=None, help="Output PDF path")
@click.option("--config", "config_path", type=str, default=None, help="Path to config file")
def report(demo: bool, output_path: str | None, config_path: str | None):
    """Generate the annual compliance audit PDF report."""
    if demo:
        _print_demo_banner()

    config = load_config(config_path, demo=demo)
    org_name = config["organization"]["name"]

    console.print(f"\n[bold cyan]Running compliance scan for report generation...[/bold cyan]\n")

    orchestrator = ComplianceOrchestrator(config, demo=demo)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning controls...", total=31)

        def _callback(control_id: str, status: str):
            progress.update(task, advance=1)

        compliance_report = orchestrator.run_all_checks(callback=_callback)

    # Generate PDF
    if output_path is None:
        safe_name = org_name.lower().replace(" ", "_").replace("'", "")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = get_output_dir()
        output_path = str(output_dir / f"compliance_report_{safe_name}_{timestamp}.pdf")

    console.print(f"\n[bold cyan]Generating PDF report...[/bold cyan]")

    pdf_path = generate_pdf(compliance_report, output_path)

    console.print(f"\n[bold green]Report generated:[/bold green] {pdf_path}")
    console.print(f"  Score: [bold]{compliance_report.overall_score:.1f}/100[/bold] ({compliance_report.overall_band})")
    console.print(f"  Findings: {len(compliance_report.findings)} total")
    console.print(f"  Controls: {len(compliance_report.control_statuses)} assessed\n")


@cli.command()
@click.option("--demo", is_flag=True, help="View demo freshness status")
@click.option("--config", "config_path", type=str, default=None, help="Path to config file")
def freshness(demo: bool, config_path: str | None):
    """View compliance freshness status for all controls."""
    if demo:
        _print_demo_banner()

    config = load_config(config_path, demo=demo)
    orchestrator = ComplianceOrchestrator(config, demo=demo)
    report = orchestrator.run_all_checks()
    render_freshness_detail(report, console)


@cli.command("check")
@click.argument("control_id")
@click.option("--demo", is_flag=True, help="Run in demo mode")
@click.option("--config", "config_path", type=str, default=None, help="Path to config file")
def check_control(control_id: str, demo: bool, config_path: str | None):
    """Run a check for a specific control."""
    if demo:
        _print_demo_banner()

    config = load_config(config_path, demo=demo)
    orchestrator = ComplianceOrchestrator(config, demo=demo)

    try:
        result = orchestrator.run_check(control_id.upper())
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

    cs = orchestrator.get_control_status(control_id.upper())
    render_control_detail(cs, console)


@cli.command("control")
@click.argument("control_id")
def control_detail(control_id: str):
    """Show details for a specific control definition."""
    registry = ControlRegistry()

    try:
        control = registry.get(control_id.upper())
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

    from engine.models import ControlStatus
    cs = ControlStatus(control=control)
    render_control_detail(cs, console)


@cli.command("export")
@click.option("--demo", is_flag=True, help="Export demo data")
@click.option("--format", "fmt", type=click.Choice(["csv", "json"]), default="csv",
              help="Export format")
@click.option("--output", "output_path", type=str, default=None, help="Output file path")
@click.option("--config", "config_path", type=str, default=None, help="Path to config file")
def export_findings(demo: bool, fmt: str, output_path: str | None, config_path: str | None):
    """Export findings to CSV or JSON."""
    if demo:
        _print_demo_banner()

    config = load_config(config_path, demo=demo)
    orchestrator = ComplianceOrchestrator(config, demo=demo)
    report = orchestrator.run_all_checks()

    org_name = config["organization"]["name"]
    safe_name = org_name.lower().replace(" ", "_").replace("'", "")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if output_path is None:
        output_dir = get_output_dir()
        output_path = str(output_dir / f"findings_{safe_name}_{timestamp}.{fmt}")

    if fmt == "csv":
        _export_csv(report, output_path)
    else:
        _export_json(report, output_path)

    console.print(f"\n[bold green]Exported {len(report.findings)} findings to:[/bold green] {output_path}\n")


@cli.command()
def history():
    """View check history."""
    from engine.orchestrator import CheckHistory

    hist = CheckHistory()
    runs = hist.get_history()

    if not runs:
        console.print("\n[yellow]No check history found. Run a scan first.[/yellow]\n")
        return

    from rich.table import Table
    from rich import box

    table = Table(
        title="Check History",
        box=box.ROUNDED,
        width=80,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Date", width=22)
    table.add_column("Controls", justify="center", width=10)
    table.add_column("Pass", justify="center", width=8, style="green")
    table.add_column("Fail", justify="center", width=8, style="red")
    table.add_column("Partial", justify="center", width=8, style="yellow")

    for run in runs[-10:]:
        timestamp = run.get("timestamp", "")[:19].replace("T", " ")
        controls = run.get("controls_checked", 0)
        summary = run.get("results_summary", {})

        pass_count = sum(1 for v in summary.values() if v.get("status") == "PASS")
        fail_count = sum(1 for v in summary.values() if v.get("status") == "FAIL")
        partial_count = sum(1 for v in summary.values() if v.get("status") == "PARTIAL")

        table.add_row(timestamp, str(controls), str(pass_count), str(fail_count), str(partial_count))

    console.print()
    console.print(table)
    console.print()


# ----------------------------------------------------------
# HELPER FUNCTIONS
# ----------------------------------------------------------

def _print_demo_banner():
    """Print demo mode banner."""
    console.print()
    console.print(
        "[bold on cyan] DEMO MODE [/bold on cyan] "
        "[cyan]Simulating: Midwest Family Dental — Small dental practice (18 staff)[/cyan]"
    )


def _export_csv(report: ComplianceReport, output_path: str) -> None:
    """Export findings to CSV."""
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "control_id", "severity", "cfr_reference", "title",
            "description", "remediation", "estimated_effort",
        ])
        writer.writeheader()
        for finding in report.findings:
            writer.writerow({
                "control_id": finding.control_id,
                "severity": finding.severity,
                "cfr_reference": finding.cfr_reference,
                "title": finding.title,
                "description": finding.description,
                "remediation": finding.remediation,
                "estimated_effort": finding.estimated_effort,
            })


def _export_json(report: ComplianceReport, output_path: str) -> None:
    """Export findings to JSON."""
    data = {
        "organization": report.organization_name,
        "report_date": report.report_date,
        "overall_score": report.overall_score,
        "overall_band": report.overall_band,
        "findings": [f.to_dict() for f in report.findings],
    }
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)


if __name__ == "__main__":
    cli()
