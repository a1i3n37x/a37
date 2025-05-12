# src/alienrecon/cli.py
import logging
from typing import Optional

import typer
from rich.console import Console

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
logging.basicConfig(
    level=logging.INFO,  # Or logging.DEBUG for more verbose output during dev
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
module_logger = logging.getLogger("alienrecon.cli")


@app.callback()
def main_callback(ctx: typer.Context):
    """
    Alien Recon AI Assistant.
    This callback can be used for context shared across all commands.
    """
    # For now, SessionController is instantiated per 'recon' command.
    # If we need persistent state across 'target' and 'recon' calls
    # within one CLI invocation, we'd use ctx.obj.
    module_logger.debug("Main CLI callback invoked.")


@app.command()
def init():
    """
    Initialize Alien Recon workspace (Planned Feature).
    """
    cli_console.print(
        "[cyan]Initialize Alien Recon workspace... (Not yet fully implemented)[/cyan]"
    )
    # Future: Create .alienrecon directory, default config, check tool paths etc.
    # Could also call a method on SessionController if init needs session state.
    # For example:
    # try:
    #     sc = SessionController() # A temporary one just for init tasks
    #     sc.perform_initialization_checks()
    # except RuntimeError as e:
    #     cli_console.print(f"[bold red]Initialization failed: {e}[/bold red]")
    #     raise typer.Exit(code=1)
    module_logger.info("`init` command executed (stub).")


@app.command()
def target(
    target_address: str = typer.Argument(
        ...,  # Required argument
        help="The IP address or domain name to make the current session target.",
    ),
):
    """
    Set/update the primary target for the *next* recon session.
    (This command is a placeholder until session state persistence is added.
    For now, use `recon --target <addr>` for each recon run.)
    """
    # This command currently doesn't instantiate SessionController as it doesn't
    # persist state. It's a note for the user.
    cli_console.print(
        f"[green]Target noted:[/green] {target_address}. "
        "Use `recon --target ...` to start a session with this target."
    )
    module_logger.info(f"`target` command executed, target noted: {target_address}")


@app.command()
def recon(
    target_address: Optional[str] = typer.Option(
        None,
        "--target",
        "-t",
        help=(
            "Target IP or domain for this reconnaissance session. "
            "This is currently a mandatory option for the recon command."
        ),
    ),
    auto: bool = typer.Option(
        False,
        "--auto",
        "-a",
        help="Enable automatic chained scanning (Planned for Phase 3).",
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
        f"auto: {auto}, novice_mode: {novice_mode}"
    )

    if not target_address:
        cli_console.print(
            "[bold red]Error: Target address is required for reconnaissance. "
            "Please use the --target <address> option.[/bold red]"
        )
        module_logger.error("Recon command called without a target address.")
        raise typer.Exit(code=1)

    try:
        # Each 'recon' call gets a fresh SessionController for now
        sc = SessionController()
        sc.set_target(target_address)
        sc.set_novice_mode(novice_mode)

        if auto:
            module_logger.info(
                f"Starting auto reconnaissance for {sc.get_current_target()}"
            )
            sc.start_auto_recon()  # This is currently a stub
        else:
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


if __name__ == "__main__":
    # This allows running `python src/alienrecon/cli.py` directly for simple testing
    # The `poetry run alienrecon` command uses the entry point defined in pyproject.toml
    app()
