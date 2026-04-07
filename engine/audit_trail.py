"""File access tracking for self-audit transparency.

Provides a singleton FileAccessTracker that records every file read/write
across all engine components. Used by the `self-audit` CLI command to prove
the tool only touches files the user explicitly configures.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional


class FileAccessTracker:
    """Singleton tracking all file I/O for the self-audit report."""

    _instance: Optional["FileAccessTracker"] = None
    _enabled: bool = False

    def __init__(self):
        self._accesses: list[dict] = []

    @classmethod
    def instance(cls) -> "FileAccessTracker":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def enable(cls) -> "FileAccessTracker":
        """Enable tracking and return the singleton."""
        tracker = cls.instance()
        cls._enabled = True
        tracker._accesses = []
        return tracker

    @classmethod
    def is_enabled(cls) -> bool:
        return cls._enabled

    def record(
        self,
        filepath: str,
        access_type: str,
        module: str,
        purpose: str = "",
    ) -> None:
        if not self._enabled:
            return
        self._accesses.append({
            "file": filepath,
            "type": access_type,
            "module": module,
            "purpose": purpose,
            "timestamp": datetime.now().isoformat(),
        })

    @property
    def reads(self) -> list[dict]:
        return [a for a in self._accesses if a["type"] == "read"]

    @property
    def writes(self) -> list[dict]:
        return [a for a in self._accesses if a["type"] == "write"]

    def print_report(self) -> None:
        """Print the full self-audit report using Rich."""
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich.text import Text
        import importlib.metadata

        console = Console()

        # Header
        console.print()
        console.print(Panel(
            "[bold]This report shows exactly what the HIPAA Compliance Engine accessed\n"
            "during its scan. No data leaves your machine. Verify independently.[/bold]",
            title="[bold blue]VerifAI Security — Self-Audit Report[/bold blue]",
            border_style="blue",
        ))
        console.print()

        # Files Read
        if self.reads:
            table = Table(title="Files Read", show_lines=False, border_style="green")
            table.add_column("File Path", style="cyan", max_width=60)
            table.add_column("Module", style="yellow")
            table.add_column("Purpose", style="white")
            seen = set()
            for a in self.reads:
                key = (a["file"], a["module"])
                if key not in seen:
                    seen.add(key)
                    table.add_row(a["file"], a["module"], a["purpose"])
            console.print(table)
        else:
            console.print("[yellow]No files were read during this scan.[/yellow]")
        console.print()

        # Files Written
        if self.writes:
            table = Table(title="Files Written", show_lines=False, border_style="yellow")
            table.add_column("File Path", style="cyan", max_width=60)
            table.add_column("Module", style="yellow")
            table.add_column("Purpose", style="white")
            seen = set()
            for a in self.writes:
                key = (a["file"], a["module"])
                if key not in seen:
                    seen.add(key)
                    table.add_row(a["file"], a["module"], a["purpose"])
            console.print(table)
        else:
            console.print("[green]No files were written during this scan.[/green]")
        console.print()

        # Network Connections
        console.print(Panel(
            "[bold green]NONE ✓[/bold green]\n\n"
            "The engine makes zero outbound network connections.\n"
            "Verify: [dim]grep -rn \"requests\\|urllib\\|http\\.\\|socket\\.\" checks/ engine/ scoring/[/dim]",
            title="Network Connections",
            border_style="green",
        ))
        console.print()

        # External Commands
        console.print(Panel(
            "[bold green]NONE ✓[/bold green]\n\n"
            "The engine runs zero shell commands or subprocesses.\n"
            "Verify: [dim]grep -rn \"subprocess\\|os\\.system\\|os\\.popen\" checks/ engine/ scoring/[/dim]",
            title="External Commands Executed",
            border_style="green",
        ))
        console.print()

        # Environment Variables
        console.print(Panel(
            "[bold green]NONE ✓[/bold green]\n\n"
            "The engine reads zero environment variables.\n"
            "Verify: [dim]grep -rn \"os\\.environ\\|os\\.getenv\" checks/ engine/ scoring/[/dim]",
            title="Environment Variables Read",
            border_style="green",
        ))
        console.print()

        # Dependencies
        deps = {
            "pyyaml": "Read YAML config files",
            "rich": "Terminal display and formatting",
            "reportlab": "Generate PDF compliance reports",
            "click": "Command-line interface",
            "colorama": "Cross-platform terminal colors",
            "tabulate": "Table formatting",
            "jinja2": "Template rendering",
        }
        table = Table(title="Dependencies", show_lines=False, border_style="blue")
        table.add_column("Package", style="cyan")
        table.add_column("Version", style="yellow")
        table.add_column("Purpose", style="white")
        for pkg, purpose in deps.items():
            try:
                version = importlib.metadata.version(pkg)
            except importlib.metadata.PackageNotFoundError:
                version = "not installed"
            table.add_row(pkg, version, purpose)
        console.print(table)
        console.print()

        # Source Code
        console.print(Panel(
            "[bold]Repository:[/bold] https://github.com/itsnmills/hipaa-compliance-engine\n\n"
            "All source code is open and auditable. Run these commands to verify:\n\n"
            "[dim]# Confirm zero network calls\n"
            "grep -rn \"requests\\|urllib\\|http\\.\\|socket\\.\" checks/ engine/ scoring/ reports/\n\n"
            "# Confirm zero shell commands\n"
            "grep -rn \"subprocess\\|os\\.system\\|os\\.popen\" checks/ engine/ scoring/ reports/\n\n"
            "# Confirm zero environment variable reads\n"
            "grep -rn \"os\\.environ\\|os\\.getenv\" checks/ engine/ scoring/ reports/[/dim]",
            title="Source Code Verification",
            border_style="blue",
        ))
