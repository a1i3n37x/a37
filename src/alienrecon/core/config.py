# src/alienrecon/core/config.py
import logging
import os
import shutil
import sys

import openai
from dotenv import load_dotenv
from rich.console import Console

# BasicConfig is now handled by cli.py's main_callback
# logging.basicConfig(
#     level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
# )
console = Console()
load_dotenv()

# --- API Keys ---
API_KEY = os.getenv("OPENAI_API_KEY")
if not API_KEY:
    console.print(
        "[bold red]Error: OPENAI_API_KEY not found in .env file or "
        "environment variables.[/bold red]"
    )
    sys.exit(1)

# --- Default Wordlist Configuration ---
DEFAULT_WORDLIST_PATH_ENV = os.getenv("ALIENRECON_WORDLIST")
DEFAULT_WORDLIST = (
    DEFAULT_WORDLIST_PATH_ENV
    or "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt"
)
if not os.path.exists(DEFAULT_WORDLIST):
    logging.warning(  # This is fine as WARNING
        f"Default wordlist not found at '{DEFAULT_WORDLIST}'. "
        "Gobuster scans might fail or use an internal default unless "
        "a wordlist is specified per scan."
    )

# --- Tool Paths ---
TOOL_PATHS = {
    "nmap": shutil.which("nmap"),
    "gobuster": shutil.which("gobuster"),
    "nikto": shutil.which("nikto"),
    "enum4linux-ng": shutil.which("enum4linux-ng"),
}


def check_tool(tool_name):
    path = TOOL_PATHS.get(tool_name)
    if not path:
        logging.warning(  # This is fine as WARNING
            f"{tool_name.capitalize()} not found in PATH. Associated scans might fail."
        )
        return False
    return True


def initialize_openai_client():
    try:
        client = openai.OpenAI(api_key=API_KEY)
        client.models.list()
        logging.info("OpenAI client initialized and connection verified.")
        return client
    except openai.AuthenticationError:
        console.print(
            "[bold red]OpenAI Authentication Error: Invalid API Key. "
            "Please check your OPENAI_API_KEY environment variable.[/bold red]"
        )
        sys.exit(1)  # Critical error
    except Exception as e:
        logging.error(f"Failed to initialize OpenAI client: {e}", exc_info=True)
        console.print(f"[bold red]Error initializing OpenAI client: {e}[/bold red]")
        sys.exit(1)  # Critical error


# --- Function to handle old argparse logic if needed by CLI directly ---
# This is IF you still want a global -w/--wordlist flag for the whole app,
# managed by Typer at the top level, not by config.py on import.
# For now, we removed the argparse from running on import.
# If you want a CLI flag for wordlist, add it as a Typer option in cli.py.
