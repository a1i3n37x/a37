# src/alienrecon/core/interaction_handler.py
"""User interaction and display management."""

import logging
from typing import Any, Optional

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.status import Status
from rich.syntax import Syntax
from rich.table import Table

logger = logging.getLogger(__name__)


class InteractionHandler:
    """Handles user interactions and display formatting."""

    def __init__(self):
        self.console = Console()

    def display_welcome(self, target: Optional[str] = None) -> None:
        """Display welcome message."""
        if target:
            message = f"## Welcome to Alien Recon\n\n**Target:** {target}\n\nReady to begin reconnaissance!"
        else:
            message = "## Welcome to Alien Recon\n\nAI-augmented reconnaissance framework for CTF and security testing."

        self.console.print(Panel(Markdown(message), title="🛸 Alien Recon", border_style="green"))

    def display_session_status(self, session_data: dict[str, Any]) -> None:
        """Display current session status."""
        table = Table(title="Session Status", show_header=True, header_style="bold magenta")
        table.add_column("Property", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")

        # Add session data
        table.add_row("Target", session_data.get("target", "Not set"))
        table.add_row("Open Ports", str(session_data.get("open_ports", 0)))
        table.add_row("Discovered Subdomains", str(session_data.get("discovered_subdomains", 0)))
        table.add_row("Web Findings", str(session_data.get("web_findings", 0)))
        table.add_row("CTF Context", "Yes" if session_data.get("has_ctf_context") else "No")
        table.add_row("Task Queue", str(session_data.get("task_queue_size", 0)))
        table.add_row("Active Plan", "Yes" if session_data.get("has_active_plan") else "No")

        self.console.print(table)

    def display_tool_result(self, tool_name: str, result: dict[str, Any]) -> None:
        """Display tool execution result."""
        if result.get("success"):
            self.console.print(f"\n[green]✓[/green] {tool_name} completed successfully")

            # Display key findings
            if "summary" in result:
                self.console.print(Panel(result["summary"], title="Summary", border_style="green"))

            if "data" in result and isinstance(result["data"], dict):
                # Format data based on tool type
                if tool_name == "nmap" and "hosts" in result["data"]:
                    self._display_nmap_results(result["data"])
                elif tool_name == "nikto" and "vulnerabilities" in result["data"]:
                    self._display_nikto_results(result["data"])
                else:
                    # Generic data display
                    self._display_generic_data(result["data"])
        else:
            self.console.print(f"\n[red]✗[/red] {tool_name} failed")
            if "error" in result:
                self.console.print(f"[red]Error:[/red] {result['error']}")

    def _display_nmap_results(self, data: dict[str, Any]) -> None:
        """Display Nmap scan results."""
        for host in data.get("hosts", []):
            self.console.print(f"\n[cyan]Host:[/cyan] {host['address']}")

            if host.get("ports"):
                table = Table(show_header=True, header_style="bold")
                table.add_column("Port", style="green")
                table.add_column("State", style="yellow")
                table.add_column("Service", style="cyan")
                table.add_column("Version", style="white")

                for port in host["ports"]:
                    table.add_row(
                        str(port["port"]),
                        port["state"],
                        port.get("service", ""),
                        port.get("version", "")
                    )

                self.console.print(table)

    def _display_nikto_results(self, data: dict[str, Any]) -> None:
        """Display Nikto scan results."""
        vulns = data.get("vulnerabilities", [])
        if vulns:
            self.console.print(f"\n[yellow]Found {len(vulns)} potential issues:[/yellow]")
            for vuln in vulns[:10]:  # Show first 10
                self.console.print(f"  • {vuln}")
            if len(vulns) > 10:
                self.console.print(f"  ... and {len(vulns) - 10} more")

    def _display_generic_data(self, data: dict[str, Any]) -> None:
        """Display generic data structure."""
        for key, value in data.items():
            if isinstance(value, list | dict) and value:
                self.console.print(f"\n[cyan]{key}:[/cyan]")
                if isinstance(value, list):
                    for item in value[:5]:  # Show first 5 items
                        self.console.print(f"  • {item}")
                    if len(value) > 5:
                        self.console.print(f"  ... and {len(value) - 5} more")
                else:
                    self.console.print(f"  {value}")
            elif value:
                self.console.print(f"[cyan]{key}:[/cyan] {value}")

    def prompt_confirmation(self, message: str, default: bool = False) -> bool:
        """Prompt user for confirmation."""
        return Confirm.ask(message, default=default)

    def prompt_input(self, message: str, default: Optional[str] = None) -> str:
        """Prompt user for text input."""
        return Prompt.ask(message, default=default)

    def display_error(self, message: str) -> None:
        """Display an error message."""
        self.console.print(f"[bold red]Error:[/bold red] {message}")

    def display_warning(self, message: str) -> None:
        """Display a warning message."""
        self.console.print(f"[bold yellow]Warning:[/bold yellow] {message}")

    def display_info(self, message: str) -> None:
        """Display an info message."""
        self.console.print(f"[bold blue]Info:[/bold blue] {message}")

    def display_success(self, message: str) -> None:
        """Display a success message."""
        self.console.print(f"[bold green]Success:[/bold green] {message}")

    def display_ai_message(self, message: str) -> None:
        """Display AI assistant message."""
        self.console.print(Panel(Markdown(message), title="🤖 AI Assistant", border_style="blue"))

    def display_command(self, command: str) -> None:
        """Display a command that will be executed."""
        syntax = Syntax(command, "bash", theme="monokai", line_numbers=False)
        self.console.print(Panel(syntax, title="Command", border_style="yellow"))

    def create_status(self, message: str) -> Status:
        """Create a status spinner."""
        return self.console.status(message, spinner="dots")

    def display_plan_summary(self, plan: dict[str, Any]) -> None:
        """Display a summary of a reconnaissance plan."""
        self.console.print(f"\n[cyan]Plan:[/cyan] {plan['name']}")
        self.console.print(f"[cyan]Description:[/cyan] {plan['description']}")
        self.console.print(f"[cyan]Steps:[/cyan] {len(plan['steps'])}")

        # Show steps
        for i, step in enumerate(plan['steps']):
            tool = step['tool']
            desc = step.get('description', f"Run {tool}")
            self.console.print(f"  {i+1}. {desc}")

    def display_tool_proposals(self, proposals: list[dict[str, Any]]) -> None:
        """Display proposed tools for execution."""
        self.console.print("\n[cyan]Proposed Tools:[/cyan]")

        for i, proposal in enumerate(proposals):
            tool = proposal.get("tool", "unknown")
            args = proposal.get("args", {})
            reason = proposal.get("reason", "")

            self.console.print(f"\n{i+1}. [yellow]{tool}[/yellow]")
            if reason:
                self.console.print(f"   [dim]Reason: {reason}[/dim]")

            # Show key arguments
            if args:
                arg_str = ", ".join(f"{k}={v}" for k, v in args.items() if k != "arguments")
                self.console.print(f"   [dim]Args: {arg_str}[/dim]")

    def clear_screen(self) -> None:
        """Clear the console screen."""
        self.console.clear()
