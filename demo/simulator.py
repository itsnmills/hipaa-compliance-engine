"""Demo mode simulator — simulates Midwest Family Dental environment."""

from __future__ import annotations

from engine.config import load_config


def get_demo_config() -> dict:
    """Load the demo configuration for Midwest Family Dental.

    Returns:
        Configuration dictionary for demo mode.
    """
    return load_config(demo=True)


def print_demo_banner() -> None:
    """Print the demo mode banner."""
    from rich.console import Console
    from rich.panel import Panel

    console = Console()
    console.print()
    console.print(Panel(
        "[bold cyan]DEMO MODE[/bold cyan]\n\n"
        "[white]Simulating:[/white] [bold]Midwest Family Dental[/bold]\n"
        "[white]Type:[/white] Small dental practice (18 staff)\n"
        "[white]Environment:[/white] On-prem servers + Azure cloud\n"
        "[white]EHR:[/white] Open Dental\n\n"
        "[dim]This demo uses simulated data to demonstrate the compliance engine.\n"
        "No real systems are being scanned.[/dim]",
        title="[bold]VerifAI Security — HIPAA Compliance Engine[/bold]",
        border_style="cyan",
        width=70,
    ))
    console.print()
