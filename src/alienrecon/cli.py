# src/alienrecon/cli.py
import logging

import typer
from rich.console import Console

# This import will be added/used once SessionController is created and moved
# from alienrecon.core.session import SessionController

app = typer.Typer(
    name="alienrecon",
    help="👽 Alien Recon: AI-guided CTF Assistant for reconnaissance.",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode=None,
)

cli_console = Console()

# Basic logging for the CLI module itself.
# More sophisticated logging will be handled by SessionController or a
# dedicated logging setup.
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


@app.callback()
def main_callback(ctx: typer.Context):
    """
    Alien Recon AI Assistant.
    Base command, context setup happens here if needed by all subcommands.
    """
    pass


@app.command()
def init():
    """
    Initialize Alien Recon workspace or a specific CTF challenge (Planned).
    """
    cli_console.print("[cyan]TODO: Initialize Alien Recon workspace.[/cyan]")


@app.command()
def target(
    target_address: str = typer.Argument(
        ...,
        help="The IP address or domain name to target.",
    ),
):
    """
    Set or update the primary target for the current session.
    (Note: This command will interact with SessionController once implemented)
    """
    cli_console.print(f"[green]Target set to:[/green] {target_address}")
    cli_console.print(
        "[grey50](This currently only notes the target. "
        "Persistence will be added with SessionController.)[/grey50]"
    )


@app.command()
def recon(
    target_address: str | None = typer.Option(
        None,
        "--target",
        "-t",
        help=(
            "Target IP or domain name. If not provided, will use current "
            "session target (once implemented)."
        ),
    ),
    auto: bool = typer.Option(
        False,
        "--auto",
        "-a",
        help="Enable automatic chained scanning (Planned for Phase 3).",
    ),
    novice_mode: bool = typer.Option(
        True,
        "--novice/--expert",
        help=(
            "Guidance level: --novice (detailed prompts) or --expert "
            "(batch/fewer prompts)."
        ),
    ),
):
    """
    Start reconnaissance on the current or specified target.
    """
    cli_console.print("[yellow]Reconnaissance Parameters:[/yellow]")
    if target_address:
        cli_console.print(f"  [bold]Specified Target:[/bold] {target_address}")
    else:
        cli_console.print(
            "  [bold]Specified Target:[/bold] [grey50]None (will use session "
            "target - TODO)[/grey50]"
        )

    cli_console.print(
        f"  [bold]Mode:[/bold] {'Automatic (TODO)' if auto else 'Interactive (TODO)'}"
    )
    cli_console.print(
        f"  [bold]Guidance:[/bold] {'Novice' if novice_mode else 'Expert'}"
    )
    cli_console.print("-" * 30)

    # Placeholder for SessionController logic:
    #
    # try:
    #     sc = SessionController()
    # except RuntimeError as e:
    #     cli_console.print(f"[bold red]Initialization Error: {e}[/bold red]")
    #     raise typer.Exit(code=1)
    #
    # effective_target = target_address or sc.get_current_target()
    # if not effective_target:
    #     cli_console.print(
    #         "[bold red]Error: No target specified or set. Use --target "
    #         "<address> or the 'target' command.[/bold red]"
    #      )
    #     raise typer.Exit(code=1)
    #
    # sc.set_target(effective_target)
    # sc.set_novice_mode(novice_mode)
    #
    # if auto:
    #     cli_console.print(
    #         f"[cyan]Starting [bold]auto[/bold] reconnaissance on: "
    #         f"{effective_target}[/cyan]"
    #     )
    #     # sc.start_auto_recon()
    # else:
    #     cli_console.print(
    #         f"[cyan]Starting [bold]interactive[/bold] reconnaissance on: "
    #         f"{effective_target}[/cyan]"
    #     )
    #     # sc.start_interactive_recon()
    #
    cli_console.print(
        "[bold magenta]TODO: Implement SessionController integration and "
        "recon logic.[/bold magenta]"
    )


if __name__ == "__main__":
    app()
