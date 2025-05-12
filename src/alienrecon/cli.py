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

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


@app.callback()
def main_callback(ctx: typer.Context):
    pass


@app.command()
def init():
    cli_console.print("[cyan]TODO: Initialize Alien Recon workspace.[/cyan]")


@app.command()
def target(
    target_address: str = typer.Argument(  # Keep as required
        ...,
        help="The IP address or domain name to target.",
    ),
):
    cli_console.print(f"[green]Target set to:[/green] {target_address}")
    cli_console.print(
        "[grey50](This currently only notes the target. "
        "Persistence will be added with SessionController.)[/grey50]"
    )


@app.command()
def recon(
    # Change str | None to Optional[str]
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
    cli_console.print(
        "[bold magenta]TODO: Implement SessionController integration and "
        "recon logic.[/bold magenta]"
    )


if __name__ == "__main__":
    app()
