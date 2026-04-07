"""Terminal dashboard using Rich library."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.progress_bar import ProgressBar
from rich import box

from engine.models import (
    ComplianceReport, ControlStatus, CategoryScore,
    CheckStatus, get_score_band, get_band_color, ScoreBand,
)
from scoring.freshness import is_approaching_stale
from scoring.risk_calculator import get_next_actions


# Color mapping for Rich
BAND_RICH_COLORS = {
    "Fully Compliant": "green",
    "Substantially Compliant": "bright_green",
    "Partially Compliant": "yellow",
    "Significant Gaps": "dark_orange",
    "Non-Compliant": "red",
}

SEVERITY_RICH_COLORS = {
    "Critical": "red",
    "High": "dark_orange",
    "Medium": "yellow",
    "Low": "green",
}

STATUS_RICH_COLORS = {
    "PASS": "green",
    "FAIL": "red",
    "PARTIAL": "yellow",
    "ERROR": "bright_black",
    "NOT_CHECKED": "bright_black",
}


def render_dashboard(report: ComplianceReport, console: Console | None = None) -> None:
    """Render the full compliance dashboard to the terminal.

    Args:
        report: Complete compliance report data.
        console: Rich Console instance (creates one if not provided).
    """
    c = console or Console()

    c.print()
    _render_header(c, report)
    c.print()
    _render_overall_score(c, report)
    c.print()
    _render_category_breakdown(c, report)
    c.print()
    _render_findings_summary(c, report)
    c.print()
    _render_freshness_status(c, report)
    c.print()
    _render_next_actions(c, report)
    c.print()
    _render_history(c, report)
    c.print()


def _render_header(c: Console, report: ComplianceReport) -> None:
    """Render the dashboard header."""
    c.print(Panel(
        f"[bold cyan]VerifAI Security[/bold cyan] — HIPAA Compliance Engine\n"
        f"[white]{report.organization_name}[/white] | "
        f"Report Date: {report.report_date} | "
        f"Controls: {len(report.control_statuses)}",
        border_style="cyan",
        width=80,
    ))


def _render_overall_score(c: Console, report: ComplianceReport) -> None:
    """Render the overall compliance score with gauge."""
    band = report.overall_band
    color = BAND_RICH_COLORS.get(band, "white")
    score = report.overall_score

    # Build score gauge bar
    filled = int(score / 100 * 40)
    empty = 40 - filled
    gauge = f"[{color}]{'█' * filled}[/{color}][bright_black]{'░' * empty}[/bright_black]"

    score_panel = Panel(
        f"\n  {gauge}  [{color} bold]{score:.1f}[/{color} bold]/100\n\n"
        f"  Compliance Band: [{color} bold]{band}[/{color} bold]\n"
        f"  Findings: [red]{len(report.critical_findings)}[/red] Critical | "
        f"[dark_orange]{len(report.high_findings)}[/dark_orange] High | "
        f"[yellow]{len(report.medium_findings)}[/yellow] Medium | "
        f"[green]{len(report.low_findings)}[/green] Low\n",
        title="[bold]Overall Compliance Score[/bold]",
        border_style=color,
        width=80,
    )
    c.print(score_panel)


def _render_category_breakdown(c: Console, report: ComplianceReport) -> None:
    """Render per-category score breakdown."""
    table = Table(
        title="Category Compliance Scores",
        box=box.ROUNDED,
        width=80,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Category", style="bold", width=20)
    table.add_column("Score", justify="center", width=8)
    table.add_column("Band", width=22)
    table.add_column("Weight", justify="center", width=8)
    table.add_column("Controls", justify="center", width=18)

    for cs in report.category_scores:
        color = BAND_RICH_COLORS.get(cs.band, "white")
        bar_len = int(cs.score / 100 * 15)
        bar = f"[{color}]{'█' * bar_len}[/{color}][bright_black]{'░' * (15 - bar_len)}[/bright_black]"

        controls_str = (
            f"[green]{cs.controls_passing}[/green]P "
            f"[red]{cs.controls_failing}[/red]F "
            f"[yellow]{cs.controls_partial}[/yellow]W"
        )

        table.add_row(
            cs.category,
            f"[{color}]{cs.score:.0f}[/{color}]",
            f"{bar} [{color}]{cs.band}[/{color}]",
            f"{cs.weight:.0%}",
            controls_str,
        )

    c.print(table)


def _render_findings_summary(c: Console, report: ComplianceReport) -> None:
    """Render findings summary table."""
    if not report.findings:
        c.print(Panel(
            "[green]No findings — all controls passing![/green]",
            title="[bold]Findings[/bold]",
            border_style="green",
            width=80,
        ))
        return

    table = Table(
        title="Top Findings",
        box=box.ROUNDED,
        width=80,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Severity", width=10)
    table.add_column("Control", width=14)
    table.add_column("Finding", width=40)
    table.add_column("Effort", width=12)

    for finding in report.findings[:10]:
        color = SEVERITY_RICH_COLORS.get(finding.severity, "white")
        table.add_row(
            f"[{color}]{finding.severity}[/{color}]",
            finding.control_id,
            finding.title[:50] + ("..." if len(finding.title) > 50 else ""),
            finding.estimated_effort,
        )

    if len(report.findings) > 10:
        table.add_row(
            "", "", f"[bright_black]...and {len(report.findings) - 10} more findings[/bright_black]", ""
        )

    c.print(table)


def _render_freshness_status(c: Console, report: ComplianceReport) -> None:
    """Render freshness overview."""
    stale = report.stale_controls
    approaching = report.approaching_stale
    fresh = len(report.control_statuses) - len(stale) - len(approaching)

    table = Table(
        title="Freshness Status",
        box=box.ROUNDED,
        width=80,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Status", width=14)
    table.add_column("Count", justify="center", width=8)
    table.add_column("Controls", width=54)

    # Fresh
    table.add_row(
        "[green]Fresh[/green]",
        f"[green]{fresh}[/green]",
        "[bright_black]All checks within decay period[/bright_black]",
    )

    # Approaching stale
    approaching_names = ", ".join(cs.control.id for cs in approaching[:5])
    if len(approaching) > 5:
        approaching_names += f" +{len(approaching) - 5} more"
    table.add_row(
        "[yellow]Approaching[/yellow]",
        f"[yellow]{len(approaching)}[/yellow]",
        approaching_names or "[bright_black]None[/bright_black]",
    )

    # Stale
    stale_names = ", ".join(cs.control.id for cs in stale[:5])
    if len(stale) > 5:
        stale_names += f" +{len(stale) - 5} more"
    table.add_row(
        "[red]Stale[/red]",
        f"[red]{len(stale)}[/red]",
        stale_names or "[bright_black]None[/bright_black]",
    )

    c.print(table)


def _render_next_actions(c: Console, report: ComplianceReport) -> None:
    """Render prioritized next actions."""
    actions = get_next_actions(report, max_actions=5)

    if not actions:
        return

    table = Table(
        title="Next Actions",
        box=box.ROUNDED,
        width=80,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Priority", width=10)
    table.add_column("Control", width=15)
    table.add_column("Action", width=51)

    priority_colors = {
        "URGENT": "red bold",
        "CRITICAL": "red",
        "HIGH": "dark_orange",
        "WARNING": "yellow",
    }

    for action in actions:
        color = priority_colors.get(action["priority"], "white")
        table.add_row(
            f"[{color}]{action['priority']}[/{color}]",
            action["control_id"],
            action["action"][:60],
        )

    c.print(table)


def _render_history(c: Console, report: ComplianceReport) -> None:
    """Render check history trend."""
    history = report.history
    if not history or len(history) < 2:
        return

    table = Table(
        title="Check History (Last 5 Runs)",
        box=box.ROUNDED,
        width=80,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Date", width=22)
    table.add_column("Controls", justify="center", width=10)
    table.add_column("Results", width=44)

    for run in history[-5:]:
        timestamp = run.get("timestamp", "")[:19].replace("T", " ")
        controls = run.get("controls_checked", 0)
        summary = run.get("results_summary", {})

        pass_count = sum(1 for v in summary.values() if v.get("status") == "PASS")
        fail_count = sum(1 for v in summary.values() if v.get("status") == "FAIL")
        partial_count = sum(1 for v in summary.values() if v.get("status") == "PARTIAL")

        results_str = (
            f"[green]{pass_count}[/green] Pass | "
            f"[red]{fail_count}[/red] Fail | "
            f"[yellow]{partial_count}[/yellow] Partial"
        )

        table.add_row(timestamp, str(controls), results_str)

    c.print(table)


def render_freshness_detail(report: ComplianceReport, console: Console | None = None) -> None:
    """Render detailed freshness view for all controls."""
    c = console or Console()

    c.print()
    c.print(Panel(
        "[bold cyan]Compliance Freshness Status[/bold cyan]",
        border_style="cyan",
        width=80,
    ))
    c.print()

    table = Table(
        box=box.ROUNDED,
        width=80,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Control", width=14)
    table.add_column("Title", width=28)
    table.add_column("Freshness", justify="center", width=10)
    table.add_column("Status", justify="center", width=8)
    table.add_column("Days Since", justify="center", width=10)
    table.add_column("Next Due", width=12)

    for cs in sorted(report.control_statuses, key=lambda x: x.freshness):
        freshness_pct = f"{cs.freshness:.0%}"
        if cs.is_stale:
            f_color = "red"
        elif is_approaching_stale(cs):
            f_color = "yellow"
        else:
            f_color = "green"

        status = cs.last_check.status if cs.last_check else "N/A"
        s_color = STATUS_RICH_COLORS.get(status, "bright_black")

        days = str(cs.days_since_check) if cs.days_since_check is not None else "—"
        next_due = cs.next_due[:10] if cs.next_due else "—"

        table.add_row(
            cs.control.id,
            cs.control.title[:30] + ("..." if len(cs.control.title) > 30 else ""),
            f"[{f_color}]{freshness_pct}[/{f_color}]",
            f"[{s_color}]{status}[/{s_color}]",
            days,
            next_due,
        )

    c.print(table)
    c.print()


def render_control_detail(cs: ControlStatus, console: Console | None = None) -> None:
    """Render detailed view of a single control."""
    c = console or Console()
    control = cs.control

    status = cs.last_check.status if cs.last_check else "NOT_CHECKED"
    status_color = STATUS_RICH_COLORS.get(status, "bright_black")
    severity_color = SEVERITY_RICH_COLORS.get(control.severity, "white")

    score_text = f"Score: {cs.last_check.score:.0%}" if cs.last_check else "Not checked"

    panel_text = (
        f"[bold]{control.id}[/bold] — {control.title}\n"
        f"[{severity_color}]{control.severity}[/{severity_color}] | "
        f"[{status_color}]{status}[/{status_color}] | "
        f"{score_text}\n"
        f"\n[cyan]CFR Reference:[/cyan] {control.cfr_reference}"
        f"\n[cyan]Category:[/cyan] {control.category}"
        f"\n[cyan]Frequency:[/cyan] {control.frequency}"
        f"\n[cyan]Decay Period:[/cyan] {control.freshness_decay_days} days"
        f"\n[cyan]Freshness:[/cyan] {cs.freshness:.0%}"
        f"\n\n[cyan]Description:[/cyan]\n{control.description}"
        f"\n\n[cyan]Evidence Required:[/cyan]\n{control.evidence_required}"
        f"\n\n[cyan]Remediation Guidance:[/cyan]\n{control.remediation_guidance}"
    )

    c.print()
    c.print(Panel(
        panel_text,
        title="[bold]Control Detail[/bold]",
        border_style="cyan",
        width=80,
    ))

    if cs.last_check and cs.last_check.findings:
        c.print()
        for finding in cs.last_check.findings:
            f_color = SEVERITY_RICH_COLORS.get(finding.severity, "white")
            c.print(Panel(
                f"[{f_color} bold]{finding.severity}:[/{f_color} bold] {finding.title}\n"
                f"{finding.description}\n\n"
                f"[cyan]Remediation:[/cyan] {finding.remediation}",
                border_style=f_color,
                width=78,
            ))

    if cs.last_check and cs.last_check.evidence:
        c.print()
        c.print("[cyan]Evidence Collected:[/cyan]")
        for key, value in cs.last_check.evidence.items():
            c.print(f"  {key}: {value}")

    c.print()
