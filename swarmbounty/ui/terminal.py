"""Terminal UI helpers for SwarmBounty."""

import json
from typing import Dict, List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax


class TerminalUI:
    def __init__(self, console: Console, yolo_mode: bool = False):
        self.console = console
        self.yolo_mode = yolo_mode

    def confirm(self, question: str, default: bool = True) -> bool:
        if self.yolo_mode:
            return True
        yn = "Y/n" if default else "y/N"
        self.console.print(f"[yellow]? {question} [{yn}][/yellow] ", end="")
        ans = input().strip().lower()
        if not ans:
            return default
        return ans in ("y", "yes")

    def suggest_and_confirm(self, action: str, details: str,
                            alternatives: List[str] = None) -> str:
        """Show a suggested action and let user modify/accept/skip."""
        if self.yolo_mode:
            self.console.print(f"[dim]  → YOLO: {action}[/dim]")
            return "accept"

        self.console.print(Panel(
            f"[bold]Suggested action:[/bold] {action}\n\n"
            f"[dim]{details}[/dim]",
            style="yellow"
        ))

        if alternatives:
            for i, alt in enumerate(alternatives, 1):
                self.console.print(f"  [dim]{i}. {alt}[/dim]")

        self.console.print(
            "[dim]  [a]ccept / [s]kip / [m]odify / [q]uit hunt: [/dim]", end=""
        )
        ans = input().strip().lower()
        if not ans or ans == "a":
            return "accept"
        elif ans == "s":
            return "skip"
        elif ans == "q":
            return "quit"
        elif ans == "m" or ans.isdigit():
            return f"modify:{ans}"
        return "accept"

    def display_finding(self, finding: Dict):
        sev = finding.get("severity", "Unknown")
        colors = {"Critical": "red", "High": "red", "Medium": "yellow",
                  "Low": "green", "Informational": "blue"}
        color = colors.get(sev, "white")

        self.console.print(Panel(
            f"[bold {color}]{sev}[/bold {color}] - {finding.get('vuln_class', 'Unknown')}\n"
            f"ID: {finding.get('id', '?')}\n"
            f"Endpoint: [yellow]{finding.get('endpoint', 'N/A')}[/yellow]\n"
            f"Parameter: {finding.get('parameter', 'N/A')}\n\n"
            f"{finding.get('description', '')}",
            title=f"[bold]Finding {finding.get('id', '?')}[/bold]",
            style=color
        ))

    def display_chains(self, chains: List[Dict]):
        if not chains:
            self.console.print("[dim]No chains found.[/dim]")
            return

        for chain in chains:
            self.console.print(Panel(
                f"[bold magenta]{chain.get('chain_name', 'Chain')}[/bold magenta]\n\n"
                f"Severity: {chain.get('combined_severity', '?')} | "
                f"Multiplier: [green]{chain.get('payout_multiplier', '?')}[/green]\n\n"
                f"{chain.get('narrative', '')}",
                style="magenta"
            ))

    def display_session_summary(self, session: Dict):
        findings = session.get("findings", [])
        table = Table(title=f"Session: {session['id']}", style="cyan")
        table.add_column("ID", style="dim")
        table.add_column("Vuln Class", style="yellow")
        table.add_column("Severity", style="red")
        table.add_column("Endpoint")
        table.add_column("Validated", style="green")
        table.add_column("Report-Ready", style="green")

        for f in findings:
            table.add_row(
                f.get("id", "?"),
                f.get("vuln_class", "?"),
                f.get("severity", "?"),
                (f.get("endpoint") or "")[:40],
                "✓" if f.get("validated") else "✗",
                "✓" if f.get("report_worthy") else "✗"
            )

        self.console.print(table)
        self.console.print(f"\n[dim]Target: {session['target']} | "
                           f"Chains: {len(session.get('chains', []))}[/dim]")
