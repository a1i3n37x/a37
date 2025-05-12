# alienrecon/config.py
import argparse
import logging
import os
import shutil
import sys

import openai  # Needed for initialize_openai_client exception handling
from dotenv import load_dotenv
from rich.console import Console  # Needed for printing warnings/errors

# --- Basic Setup ---
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
console = Console()  # You might want a central console object later
load_dotenv()

# --- API Keys ---
API_KEY = os.getenv("OPENAI_API_KEY")
if not API_KEY:
    console.print(
        "[bold red]Error: OPENAI_API_KEY not found in .env file or "
        "environment variables.[/bold red]"
    )
    sys.exit(1)

# --- Argument Parsing ---
parser = argparse.ArgumentParser(description="Alien Recon: AI-guided CTF Assistant")
parser.add_argument(
    "-w",
    "--wordlist",
    # Consider making the default None and checking later if needed
    default="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    help="Default path to the Gobuster wordlist.",
)
args = parser.parse_args()
DEFAULT_WORDLIST = args.wordlist

# Check if the default wordlist exists (optional here, could be checked when
# tool needs it)
if not os.path.exists(DEFAULT_WORDLIST):
    console.print(
        f"[bold orange_red1]Warning:[/bold orange_red1] Default wordlist not "
        f"found at '{DEFAULT_WORDLIST}'. Gobuster scans might fail unless "
        f"specified otherwise."
    )
    # Decide if this should be a fatal error or just a warning

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
        logging.warning(
            f"{tool_name.capitalize()} not found in PATH. Skipping associated scans."
        )
        # Consider if Console should be passed in or handled differently
        console.print(
            f"[bold orange_red1]Warning: Required tool '{tool_name}' not found "
            f"in PATH. Associated actions will fail.[/bold orange_red1]"
        )
        return False
    return True


# --- OpenAI Client Initialization ---
def initialize_openai_client():
    try:
        client = openai.OpenAI(api_key=API_KEY)
        client.models.list()  # Test connection
        # We might want to return the client instead of printing success here
        logging.info("OpenAI client initialized and connection verified.")
        return client
    except openai.AuthenticationError:
        console.print(
            "[bold red]OpenAI Authentication Error: Invalid API Key.[/bold red]"
        )
        sys.exit(1)
    except Exception as e:
        logging.error(f"Failed to initialize OpenAI client: {e}", exc_info=True)
        console.print(f"[bold red]Error initializing OpenAI client: {e}[/bold red]")
        sys.exit(1)
