# src/alienrecon/cli.py
import logging
import os
from typing import Optional

import openai
import typer
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

cli_console = Console()  # For messages directly from the CLI framework

# Configure basic logging for the CLI module itself.
# SessionController will have its own logger.
# Logging will be reconfigured in main_callback based on user input
module_logger = logging.getLogger("alienrecon.cli")

# Global session controller instance for CLI commands that need persistence
session_controller: Optional[SessionController] = None


@app.callback()
def main_callback(
    ctx: typer.Context,
    log_level: str = typer.Option(
        "INFO",
        "--log-level",
        "-l",
        help="Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
        case_sensitive=False,
    ),
):
    """
    Alien Recon AI Assistant.
    This callback can be used for context shared across all commands.
    """
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        cli_console.print(
            f"[bold red]Invalid log level: {log_level}. Defaulting to INFO.[/bold red]"
        )
        numeric_level = logging.INFO
        log_level = "INFO"  # for the logger message

    # Reconfigure root logger
    # For DEBUG, use a more detailed format
    if numeric_level == logging.DEBUG:
        log_format = "%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d): %(message)s"
    else:
        log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    logging.basicConfig(
        level=numeric_level,
        format=log_format,
        datefmt="%Y-%m-%d %H:%M:%S",
        force=True,  # Force reconfiguration
    )
    # Log the effective log level being used by the application's root logger
    logging.getLogger().info(f"Logging level set to {log_level.upper()}")

    global session_controller
    session_controller = SessionController()
    ctx.obj = {"session_controller": session_controller}
    module_logger.debug("Main CLI callback invoked, logging configured.")


@app.command()
def init():
    """
    Initialize Alien Recon workspace (creates .alienrecon/ directory).
    """
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
        if ctx and "session_controller" in ctx.obj
        else SessionController()
    )
    sc.current_target = None
    sc.chat_history = []
    sc.is_novice_mode = True
    sc.save_session()
    cli_console.print("[yellow]Session state cleared.[/yellow]")
    module_logger.info("`clear` command executed.")


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
        ("gobuster", "Gobuster 🚪"),
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
                f"[bold green]✔ Gobuster wordlist found[/bold green] ([dim]{DEFAULT_WORDLIST}[/dim])",
                True,
            )
        )
    else:
        checks.append(
            (
                f"[bold red]✖ Gobuster wordlist NOT found[/bold red] ([dim]{DEFAULT_WORDLIST or 'Not Set'}[/dim])",
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
                "- Install missing tools with your package manager (e.g., apt install nmap gobuster nikto enum4linux-ng hydra)\n"
                "- Set or fix your OPENAI_API_KEY in your .env or environment\n"
                "- Download missing wordlists (e.g., SecLists for Gobuster, rockyou.txt for Hydra)\n"
                "- Check your internet connection if OpenAI API fails\n"
                "- See the README for more help!",
                border_style="yellow",
            )
        )
    else:
        cli_console.print(
            "[bold cyan]👽 Doctor check complete. Happy hacking![/bold cyan]"
        )


if __name__ == "__main__":
    app()
