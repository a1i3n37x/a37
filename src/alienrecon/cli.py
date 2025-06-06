# src/alienrecon/cli.py
import logging
import os
import shutil
from pathlib import Path
from typing import Optional

import openai
import typer
import yaml
from rich.console import Console
from rich.panel import Panel

from alienrecon.core.config import (
    API_KEY,
    DEFAULT_PASSWORD_LIST,
    DEFAULT_WORDLIST,
    TOOL_PATHS,
)

# Ensure this import path is correct after file moves
from alienrecon.core.session import SessionController

app = typer.Typer(
    name="alienrecon",
    help="👽 Alien Recon: AI-guided CTF Assistant for reconnaissance.",
    add_completion=False,
    no_args_is_help=True,
    # rich_markup_mode=None,  # Keep this for stability
)

manual_app = typer.Typer(
    help="Manual/advanced tool commands. These bypass the assistant and session features."
)
app.add_typer(
    manual_app,
    name="manual",
    help="Advanced: Run tools directly (no assistant/session features)",
)

cli_console = Console()  # For messages directly from the CLI framework

# Configure basic logging for the CLI module itself.
# SessionController will have its own logger.
# Logging will be reconfigured in main_callback based on user input
module_logger = logging.getLogger("alienrecon.cli")

# Global session controller instance for CLI commands that need persistence
session_controller: Optional[SessionController] = None


@app.callback()
def main(ctx: typer.Context):
    """
    Alien Recon: Start without arguments to launch the assistant-driven recon session.
    """
    if ctx.invoked_subcommand is None:
        from alienrecon.core.session import SessionController

        sc = SessionController()
        sc.run_assistant_session()


@app.command()
def init(
    ctf: Optional[str] = typer.Option(
        None,
        "--ctf",
        help="Initialize a CTF box environment using the specified box identifier (e.g., 'thm_basic_pentesting')",
    ),
):
    """
    Initialize Alien Recon workspace or a specific CTF box environment.

    Without --ctf: Creates the basic .alienrecon/ workspace directory.
    With --ctf: Sets up a mission folder and context for the specified CTF box.
    """
    if ctf:
        _init_ctf_environment(ctf)
    else:
        _init_workspace()


def _init_workspace():
    """Initialize basic Alien Recon workspace."""
    workspace_dir = ".alienrecon"
    if not os.path.exists(workspace_dir):
        os.makedirs(workspace_dir)
        cli_console.print(
            f"[green]Created workspace directory: {workspace_dir}[/green]"
        )
    else:
        cli_console.print(
            f"[yellow]Workspace directory already exists: {workspace_dir}[/yellow]"
        )
    module_logger.info("`init` command executed.")


def _init_ctf_environment(box_identifier: str):
    """Initialize CTF box environment with metadata and mission folder."""
    try:
        # Get package directory to find CTF metadata
        package_dir = Path(__file__).parent
        ctf_data_dir = package_dir / "data" / "ctf_info"
        templates_dir = package_dir / "data" / "templates"

        # Look for metadata file
        metadata_file = ctf_data_dir / f"{box_identifier}.yaml"
        if not metadata_file.exists():
            cli_console.print(
                f"[red]Error: CTF metadata file not found: {metadata_file}[/red]"
            )
            cli_console.print("[yellow]Available CTF boxes:[/yellow]")
            if ctf_data_dir.exists():
                for yaml_file in ctf_data_dir.glob("*.yaml"):
                    box_name = yaml_file.stem
                    cli_console.print(f"  - {box_name}")
            else:
                cli_console.print("  [dim]No CTF metadata files found[/dim]")
            return

        # Load CTF metadata
        with open(metadata_file) as f:
            metadata = yaml.safe_load(f)

        # Create mission folder
        mission_folder = Path(f"./a37_missions/{box_identifier}")
        mission_folder.mkdir(parents=True, exist_ok=True)

        cli_console.print(f"[green]Created mission folder:[/green] {mission_folder}")

        # Display CTF information
        box_name = metadata.get("box_name", box_identifier)
        platform = metadata.get("platform", "Unknown")
        cli_console.print(
            Panel.fit(
                f"[bold cyan]CTF Box Initialized[/bold cyan]\n"
                f"Box: [bold]{box_name}[/bold]\n"
                f"Platform: {platform}\n"
                f"Mission Folder: {mission_folder}",
                border_style="cyan",
                title="🚀 Mission Started",
            )
        )

        # Display VPN instructions if present
        vpn_url = metadata.get("vpn_instructions_url")
        if vpn_url:
            cli_console.print(
                Panel.fit(
                    f"[yellow]🔧 VPN Setup Required[/yellow]\n"
                    f"Please set up your VPN connection before proceeding:\n"
                    f"[link={vpn_url}]{vpn_url}[/link]",
                    border_style="yellow",
                )
            )

        # Copy notes template if specified
        notes_template_path = metadata.get("notes_template_path")
        if notes_template_path:
            template_file = templates_dir / notes_template_path
            if template_file.exists():
                target_notes = mission_folder / "notes.md"
                shutil.copy2(template_file, target_notes)
                cli_console.print(
                    f"[green]Copied notes template to:[/green] {target_notes}"
                )
            else:
                cli_console.print(
                    f"[yellow]Warning: Notes template not found: {template_file}[/yellow]"
                )

        # Display expected services hint if available
        expected_services = metadata.get("expected_key_services", [])
        if expected_services:
            services_text = ", ".join(expected_services)
            cli_console.print(f"[dim]💡 Expected key services: {services_text}[/dim]")

        # Update session controller with CTF context
        sc = SessionController()
        sc.set_ctf_context(metadata, box_identifier)
        sc.save_session()

        cli_console.print(
            "\n[bold green]✅ CTF environment ready![/bold green]\n"
            "[dim]Next steps:[/dim]\n"
            f"  1. [cyan]cd {mission_folder}[/cyan]  # Navigate to mission folder\n"
            "  2. [cyan]alienrecon recon --target <TARGET_IP>[/cyan]  # Start reconnaissance with your target IP\n"
            "     [dim](or [cyan]poetry run alienrecon recon --target <TARGET_IP>[/cyan] if using Poetry)[/dim]\n"
            "  3. Take notes in notes.md as you progress"
        )

        module_logger.info(
            f"`init --ctf {box_identifier}` command executed successfully."
        )

    except Exception as e:
        cli_console.print(f"[red]Error initializing CTF environment: {e}[/red]")
        module_logger.error(f"Error in _init_ctf_environment: {e}", exc_info=True)


@app.command()
def target(
    target_address: str = typer.Argument(
        ...,  # Required argument
        help="The IP address or domain name to make the current session target.",
    ),
    ctx: typer.Context = typer.Option(None, hidden=True),
):
    """
    Set/update the primary target for the *next* recon session.
    Now persists the target using session persistence.
    """
    sc = (
        ctx.obj["session_controller"]
        if ctx and "session_controller" in ctx.obj
        else SessionController()
    )
    sc.set_target(target_address)
    sc.save_session()
    cli_console.print(
        f"[green]Target set and saved:[/green] {target_address}. "
        "Use `recon --target ...` to start a session with this target."
    )
    module_logger.info(
        f"`target` command executed, target set and saved: {target_address}"
    )


@app.command()
def status(ctx: typer.Context = typer.Option(None, hidden=True)):
    """
    Show current session status (target, mode, chat history length).
    """
    sc = (
        ctx.obj["session_controller"]
        if ctx and "session_controller" in ctx.obj
        else SessionController()
    )
    sc.display_session_status()
    cli_console.print(f"[dim]Chat history length: {len(sc.chat_history)}[/dim]")
    module_logger.info("`status` command executed.")


@app.command()
def save(ctx: typer.Context = typer.Option(None, hidden=True)):
    """
    Manually save the current session state.
    """
    sc = (
        ctx.obj["session_controller"]
        if ctx and "session_controller" in ctx.obj
        else SessionController()
    )
    sc.save_session()
    cli_console.print("[green]Session state saved.[/green]")
    module_logger.info("`save` command executed.")


@app.command()
def load(ctx: typer.Context = typer.Option(None, hidden=True)):
    """
    Reload session state from disk.
    """
    sc = (
        ctx.obj["session_controller"]
        if ctx and "session_controller" in ctx.obj
        else SessionController()
    )
    sc.load_session()
    cli_console.print("[green]Session state loaded from disk.[/green]")
    module_logger.info("`load` command executed.")


@app.command()
def clear(ctx: typer.Context = typer.Option(None, hidden=True)):
    """
    Clear/reset the current session state (target, chat history, mode).
    """
    sc = (
        ctx.obj["session_controller"]
        if ctx and ctx.obj and "session_controller" in ctx.obj
        else SessionController()
    )
    sc.current_target = None
    sc.chat_history = []
    sc.is_novice_mode = True
    sc.save_session()
    cli_console.print("[yellow]Session state cleared.[/yellow]")
    module_logger.info("`clear` command executed.")


@app.command()
def cache(
    action: str = typer.Argument(
        "status",
        help="Action to perform: status, clear, invalidate",
    ),
    tool: Optional[str] = typer.Option(
        None,
        "--tool",
        "-t",
        help="Specific tool to target (for invalidate action)",
    ),
):
    """
    Manage result cache (view stats, clear cache, etc.).
    """
    from alienrecon.core.cache import get_cache

    cache_instance = get_cache()

    if action == "status":
        stats = cache_instance.get_stats()
        cli_console.print(
            Panel.fit(
                f"[bold cyan]Cache Statistics[/bold cyan]\n"
                f"Total Entries: {stats['total_entries']}\n"
                f"Active: [green]{stats['active_entries']}[/green]\n"
                f"Expired: [red]{stats['expired_entries']}[/red]",
                border_style="cyan",
            )
        )

        if stats["tools"]:
            cli_console.print("\n[bold]Tool Breakdown:[/bold]")
            for tool_name, tool_stats in stats["tools"].items():
                cli_console.print(
                    f"  {tool_name}: "
                    f"[green]{tool_stats['active']} active[/green], "
                    f"[red]{tool_stats['expired']} expired[/red] "
                    f"(total: {tool_stats['total']})"
                )

    elif action == "clear" or action == "invalidate":
        if tool:
            cache_instance.invalidate(tool)
            cli_console.print(f"[yellow]Cache cleared for tool: {tool}[/yellow]")
        else:
            cache_instance.invalidate()
            cli_console.print("[yellow]All cache entries cleared.[/yellow]")

    else:
        cli_console.print(f"[red]Unknown action: {action}[/red]")
        cli_console.print("Valid actions: status, clear, invalidate")

    module_logger.info(f"`cache {action}` command executed.")


@app.command()
def recon(
    target_address: Optional[str] = typer.Option(
        None,
        "--target",
        "-t",
        help=(
            "Target IP or domain for this reconnaissance session. "
            "If omitted, will use the last saved target from your session."
        ),
    ),
    novice_mode: bool = typer.Option(
        True,  # Default to novice mode
        "--novice/--expert",
        help=("Guidance level: --novice (more prompts) or --expert (fewer prompts)."),
    ),
):
    """Start reconnaissance on the specified target."""
    module_logger.info(
        f"Recon command initiated with target: {target_address}, "
        f"novice_mode: {novice_mode}"
    )

    # Always load session to get the last saved target if needed
    sc = SessionController()
    session_target = sc.get_current_target()

    # If --target is provided, use it and update session
    if target_address:
        sc.set_target(target_address)
        sc.set_novice_mode(novice_mode)
    # If not provided, use the session target if available
    elif session_target:
        target_address = session_target
        sc.set_novice_mode(novice_mode)
        cli_console.print(
            f"[yellow]No --target provided. Using saved session target: [cyan]{target_address}[/cyan][/yellow]"
        )
    else:
        cli_console.print(
            "[bold red]Error: Target address is required for reconnaissance. "
            "Please set a target with 'alienrecon target <address>' or use --target <address>.[/bold red]"
        )
        module_logger.error(
            "Recon command called without a target address and no saved session target."
        )
        raise typer.Exit(code=1)

    try:
        module_logger.info(
            f"Starting interactive reconnaissance for {sc.get_current_target()}"
        )
        sc.start_interactive_recon_session()  # This will contain the main loop

    except RuntimeError as e:
        cli_console.print(f"[bold red]Session Initialization Error: {e}[/bold red]")
        module_logger.error(
            f"RuntimeError during SessionController init or recon: {e}", exc_info=True
        )
        raise typer.Exit(code=1)
    except Exception as e:
        module_logger.critical(
            "An unexpected critical error occurred during CLI recon command.",
            exc_info=True,
        )
        cli_console.print(
            f"[bold red]An unexpected critical error occurred in CLI: {e}[/bold red]"
        )
        raise typer.Exit(code=1)


@app.command()
def quick_recon(
    target_address: str = typer.Option(
        ...,
        "--target",
        "-t",
        help="Target IP address for the quick reconnaissance sequence",
    ),
):
    """
    Perform a standardized quick reconnaissance sequence on a target.

    This command executes a predefined, beginner-friendly reconnaissance workflow:
    1. Initial Nmap SYN scan (top 1000 ports)
    2. Service detection scan on discovered open ports
    3. Directory enumeration on discovered web services
    4. Nikto vulnerability scan on discovered web services

    Each step requires user confirmation before execution, maintaining educational value.
    """
    try:
        from alienrecon.core.session import SessionController

        sc = SessionController()
        sc.set_target(target_address)
        sc.set_novice_mode(True)  # Quick recon is designed for beginners

        cli_console.print(
            Panel.fit(
                f"[bold cyan]🚀 Quick Reconnaissance Starting[/bold cyan]\n"
                f"Target: [bold]{target_address}[/bold]\n"
                f"Mode: Guided beginner sequence\n\n"
                f"[dim]This will execute a predefined reconnaissance workflow.[/dim]\n"
                f"[dim]Each step requires your confirmation before execution.[/dim]",
                border_style="cyan",
                title="Quick Recon",
            )
        )

        # Execute the quick recon sequence
        sc.execute_quick_recon_sequence()

    except Exception as e:
        cli_console.print(f"[red]Error during quick reconnaissance: {e}[/red]")
        module_logger.error(f"Error in quick_recon command: {e}", exc_info=True)


@app.command()
def doctor():
    """
    Run a self-test to check tool dependencies, API connectivity, and environment health.
    """
    cli_console.print(
        Panel.fit(
            "[bold magenta]👽 Alien Recon Doctor: System Self-Test[/bold magenta]",
            border_style="magenta",
        )
    )
    checks = []
    # Tool checks
    required_tools = [
        ("nmap", "Nmap 🛰️"),
        ("nikto", "Nikto 🦠"),
        ("enum4linux-ng", "enum4linux-ng 📁"),
        ("hydra", "Hydra 🐍"),
    ]
    for tool, label in required_tools:
        path = TOOL_PATHS.get(tool)
        if path and os.path.exists(path) and os.access(path, os.X_OK):
            checks.append(
                (f"[bold green]✔ {label} found[/bold green] ([dim]{path}[/dim])", True)
            )
        else:
            checks.append((f"[bold red]✖ {label} NOT found[/bold red]", False))
    # Wordlist/password list checks
    if DEFAULT_WORDLIST and os.path.exists(DEFAULT_WORDLIST):
        checks.append(
            (
                f"[bold green]✔ Directory wordlist found[/bold green] ([dim]{DEFAULT_WORDLIST}[/dim])",
                True,
            )
        )
    else:
        checks.append(
            (
                f"[bold red]✖ Directory wordlist NOT found[/bold red] ([dim]{DEFAULT_WORDLIST or 'Not Set'}[/dim])",
                False,
            )
        )
    if DEFAULT_PASSWORD_LIST and os.path.exists(DEFAULT_PASSWORD_LIST):
        checks.append(
            (
                f"[bold green]✔ Hydra password list found[/bold green] ([dim]{DEFAULT_PASSWORD_LIST}[/dim])",
                True,
            )
        )
    else:
        checks.append(
            (
                f"[bold red]✖ Hydra password list NOT found[/bold red] ([dim]{DEFAULT_PASSWORD_LIST or 'Not Set'}[/dim])",
                False,
            )
        )
    # OpenAI API key check
    if API_KEY:
        checks.append(("[bold green]✔ OPENAI_API_KEY set[/bold green]", True))
        # Try OpenAI connectivity
        try:
            client = openai.OpenAI(api_key=API_KEY)
            client.models.list()
            checks.append(
                ("[bold green]✔ OpenAI API connectivity OK[/bold green]", True)
            )
        except Exception as e:
            checks.append(
                (
                    f"[bold red]✖ OpenAI API connectivity FAILED[/bold red] ([dim]{e}[/dim])",
                    False,
                )
            )
    else:
        checks.append(("[bold red]✖ OPENAI_API_KEY NOT set[/bold red]", False))
    # Print results
    all_ok = all(ok for _, ok in checks)
    for msg, _ in checks:
        cli_console.print(msg)
    cli_console.print(
        "\n"
        + (
            "[bold green]All systems go! Alien Recon is ready for launch. 🚀[/bold green]"
            if all_ok
            else "[bold red]Some checks failed. See above for details and remediation advice.[/bold red]"
        )
    )
    # Remediation advice
    if not all_ok:
        cli_console.print(
            Panel.fit(
                "[bold yellow]Remediation Tips:[/bold yellow]\n"
                "- Install missing tools with your package manager (e.g., apt install nmap nikto enum4linux-ng hydra)\n"
                "- Set or fix your OPENAI_API_KEY in your .env or environment\n"
                "- Download missing wordlists (e.g., SecLists for directory enumeration, rockyou.txt for Hydra)\n"
                "- Check your internet connection if OpenAI API fails\n"
                "- See the README for more help!",
                border_style="yellow",
            )
        )
    else:
        cli_console.print(
            "[bold cyan]👽 Doctor check complete. Happy hacking![/bold cyan]"
        )


@manual_app.command()
def nmap(
    target: str = typer.Argument(
        ..., help="Target IP address or hostname for Nmap scan."
    ),
    arguments: str = typer.Option(
        "-sV -T4", help="Nmap arguments (e.g., '-sV -T4 -p 80,443')"
    ),
    save: bool = typer.Option(False, help="Save results to results directory."),
):
    """
    [Advanced] Run Nmap directly. This bypasses the assistant and session features.
    """
    try:
        from alienrecon.core.session import SessionController

        sc = SessionController()
        if not sc.nmap_tool:
            cli_console.print(
                "[bold red]Nmap tool is not available (not installed or misconfigured).[/bold red]"
            )
            raise typer.Exit(code=1)
        result = sc.nmap_tool.execute(target=target, arguments=arguments)
        cli_console.print(f"[green]Nmap result:[/green] {result['scan_summary']}")
        findings = result.get("findings")
        if findings:
            from pprint import pformat

            cli_console.print("[bold yellow]Findings:[/bold yellow]")
            cli_console.print(pformat(findings))
        if result.get("status") == "failure" or result.get("error"):
            if result.get("raw_stdout"):
                cli_console.print("[dim]Raw stdout:[/dim]")
                cli_console.print(result["raw_stdout"])
            if result.get("raw_stderr"):
                cli_console.print("[dim]Raw stderr:[/dim]")
                cli_console.print(result["raw_stderr"])
        if save:
            import json
            import os

            os.makedirs("results", exist_ok=True)
            fname = f"results/nmap_{target.replace('.', '_')}.json"
            with open(fname, "w") as f:
                json.dump(result, f, indent=2)
            cli_console.print(f"[cyan]Results saved to {fname}[/cyan]")
    except Exception as e:
        cli_console.print(f"[bold red]Error running Nmap: {e}[/bold red]")
        raise typer.Exit(code=1)


@manual_app.command()
def nikto(
    target: str = typer.Argument(
        ..., help="Target IP address or hostname for Nikto scan."
    ),
    port: int = typer.Option(80, help="Port to scan (e.g., 80, 443)"),
    nikto_arguments: str = typer.Option(
        "", help="Additional Nikto arguments (optional)"
    ),
    save: bool = typer.Option(False, help="Save results to results directory."),
):
    """
    [Advanced] Run a Nikto scan directly. This bypasses the assistant and session features.
    """
    try:
        from alienrecon.core.session import SessionController

        sc = SessionController()
        if not sc.nikto_tool:
            cli_console.print(
                "[bold red]Nikto tool is not available (not installed or misconfigured).[/bold red]"
            )
            raise typer.Exit(code=1)
        result = sc.nikto_tool.execute(
            target=target, port=port, nikto_arguments=nikto_arguments
        )
        cli_console.print(f"[green]Nikto result:[/green] {result['scan_summary']}")
        findings = result.get("findings")
        if findings:
            from pprint import pformat

            cli_console.print("[bold yellow]Findings:[/bold yellow]")
            cli_console.print(pformat(findings))
        if result.get("status") == "failure" or result.get("error"):
            if result.get("raw_stdout"):
                cli_console.print("[dim]Raw stdout:[/dim]")
                cli_console.print(result["raw_stdout"])
            if result.get("raw_stderr"):
                cli_console.print("[dim]Raw stderr:[/dim]")
                cli_console.print(result["raw_stderr"])
        if save:
            import json
            import os

            os.makedirs("results", exist_ok=True)
            fname = f"results/nikto_{target.replace('.', '_')}_{port}.json"
            with open(fname, "w") as f:
                json.dump(result, f, indent=2)
            cli_console.print(f"[cyan]Results saved to {fname}[/cyan]")
    except Exception as e:
        cli_console.print(f"[bold red]Error running Nikto: {e}[/bold red]")
        raise typer.Exit(code=1)


@manual_app.command()
def hydra(
    target: str = typer.Argument(
        ..., help="Target IP address or hostname for Hydra scan."
    ),
    port: int = typer.Option(22, help="Port to scan (e.g., 22, 21, 80)"),
    service_protocol: str = typer.Option(
        ..., help="Hydra service module (e.g., 'ssh', 'ftp', 'http-get')"
    ),
    username: str = typer.Option(..., help="Username to brute-force."),
    password_list: str = typer.Option(
        None, help="Path to password list (default: system default)"
    ),
    path: str = typer.Option(None, help="Path for HTTP services (e.g., /login)"),
    threads: int = typer.Option(4, help="Number of threads (default: 4)"),
    hydra_options: str = typer.Option("", help="Additional Hydra options (optional)"),
    save: bool = typer.Option(False, help="Save results to results directory."),
):
    """
    [Advanced] Run a Hydra brute-force scan directly. This bypasses the assistant and session features.
    """
    try:
        from alienrecon.core.session import SessionController

        sc = SessionController()
        if not sc.hydra_tool:
            cli_console.print(
                "[bold red]Hydra tool is not available (not installed or misconfigured).[/bold red]"
            )
            raise typer.Exit(code=1)
        kwargs = {
            "target": target,
            "port": port,
            "service_protocol": service_protocol,
            "username": username,
            "password_list": password_list,
            "path": path,
            "threads": threads,
            "hydra_options": hydra_options,
        }
        result = sc.hydra_tool.execute(
            **{k: v for k, v in kwargs.items() if v is not None}
        )
        cli_console.print(f"[green]Hydra result:[/green] {result['scan_summary']}")
        findings = result.get("findings")
        if findings:
            from pprint import pformat

            cli_console.print("[bold yellow]Findings:[/bold yellow]")
            cli_console.print(pformat(findings))
        if result.get("status") == "failure" or result.get("error"):
            if result.get("raw_stdout"):
                cli_console.print("[dim]Raw stdout:[/dim]")
                cli_console.print(result["raw_stdout"])
            if result.get("raw_stderr"):
                cli_console.print("[dim]Raw stderr:[/dim]")
                cli_console.print(result["raw_stderr"])
        if save:
            import json
            import os

            os.makedirs("results", exist_ok=True)
            fname = f"results/hydra_{target.replace('.', '_')}_{port}_{service_protocol}.json"
            with open(fname, "w") as f:
                json.dump(result, f, indent=2)
            cli_console.print(f"[cyan]Results saved to {fname}[/cyan]")
    except Exception as e:
        cli_console.print(f"[bold red]Error running Hydra: {e}[/bold red]")
        raise typer.Exit(code=1)


@manual_app.command()
def smb(
    target: str = typer.Argument(
        ..., help="Target IP address or hostname for SMB/enum4linux-ng scan."
    ),
    enum_arguments: str = typer.Option(
        "-A", help="Arguments for enum4linux-ng (default: -A)"
    ),
    save: bool = typer.Option(False, help="Save results to results directory."),
):
    """
    [Advanced] Run an SMB/enum4linux-ng scan directly. This bypasses the assistant and session features.
    """
    try:
        from alienrecon.core.session import SessionController

        sc = SessionController()
        if not sc.smb_tool:
            cli_console.print(
                "[bold red]SMB/enum4linux-ng tool is not available (not installed or misconfigured).[/bold red]"
            )
            raise typer.Exit(code=1)
        result = sc.smb_tool.execute(target=target, enum_arguments=enum_arguments)
        cli_console.print(
            f"[green]SMB/enum4linux-ng result:[/green] {result['scan_summary']}"
        )
        findings = result.get("findings")
        if findings:
            from pprint import pformat

            cli_console.print("[bold yellow]Findings:[/bold yellow]")
            cli_console.print(pformat(findings))
        if result.get("status") == "failure" or result.get("error"):
            if result.get("raw_stdout"):
                cli_console.print("[dim]Raw stdout:[/dim]")
                cli_console.print(result["raw_stdout"])
            if result.get("raw_stderr"):
                cli_console.print("[dim]Raw stderr:[/dim]")
                cli_console.print(result["raw_stderr"])
        if save:
            import json
            import os

            os.makedirs("results", exist_ok=True)
            fname = f"results/smb_{target.replace('.', '_')}.json"
            with open(fname, "w") as f:
                json.dump(result, f, indent=2)
            cli_console.print(f"[cyan]Results saved to {fname}[/cyan]")
    except Exception as e:
        cli_console.print(f"[bold red]Error running SMB/enum4linux-ng: {e}[/bold red]")
        raise typer.Exit(code=1)


@manual_app.command()
def http_fetch(
    url: str = typer.Argument(
        ..., help="Full URL to fetch (e.g., http://target.com/index.html)"
    ),
    timeout: int = typer.Option(15, help="Request timeout in seconds (default: 15)"),
    save: bool = typer.Option(False, help="Save results to results directory."),
):
    """
    [Advanced] Fetch and analyze the HTML/text content of a web page directly.
    This bypasses the assistant and session features.
    """
    try:
        from alienrecon.core.session import SessionController

        sc = SessionController()
        if not sc.http_fetcher_tool:
            cli_console.print(
                "[bold red]HTTP fetcher tool is not available (not installed or misconfigured).[/bold red]"
            )
            raise typer.Exit(code=1)
        result = sc.http_fetcher_tool.execute(url_to_fetch=url, timeout=timeout)
        cli_console.print(f"[green]HTTP Fetch result:[/green] {result['scan_summary']}")
        findings = result.get("findings")
        if findings:
            from pprint import pformat

            cli_console.print("[bold yellow]Findings:[/bold yellow]")
            cli_console.print(pformat(findings))
        if result.get("status") == "failure" or result.get("error"):
            if result.get("raw_stdout"):
                cli_console.print("[dim]Raw stdout:[/dim]")
                cli_console.print(result["raw_stdout"])
            if result.get("raw_stderr"):
                cli_console.print("[dim]Raw stderr:[/dim]")
                cli_console.print(result["raw_stderr"])
        if save:
            import json
            import os

            os.makedirs("results", exist_ok=True)
            import re as _re

            fname = f"results/httpfetch_{_re.sub(r'[^a-zA-Z0-9]', '_', url)}.json"
            with open(fname, "w") as f:
                json.dump(result, f, indent=2)
            cli_console.print(f"[cyan]Results saved to {fname}[/cyan]")
    except Exception as e:
        cli_console.print(f"[bold red]Error running HTTP fetch: {e}[/bold red]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
