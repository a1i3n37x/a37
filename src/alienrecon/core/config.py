import logging
import os
import shutil
import sys

import openai
from dotenv import load_dotenv
from rich.console import Console

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

# --- Default Wordlist Configuration (for Gobuster) ---
DEFAULT_WORDLIST_PATH_ENV = os.getenv("ALIENRECON_WORDLIST")
DEFAULT_WORDLIST = (
    DEFAULT_WORDLIST_PATH_ENV or "/usr/share/seclists/Discovery/Web-Content/common.txt"
)
if not os.path.exists(DEFAULT_WORDLIST):
    logging.warning(
        f"Default Gobuster wordlist not found at '{DEFAULT_WORDLIST}'. "
        "Gobuster scans might fail or use an internal default unless "
        "a wordlist is specified per scan."
    )

# --- Default Password List Configuration (for Hydra) ---
DEFAULT_PASSWORD_LIST_PATH_ENV = os.getenv("ALIENRECON_PASSWORD_LIST")
_try_default_passlist_paths = [
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou-20.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
    "/usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt",
    # Common Kali path if SecLists isn't as structured
    "/usr/share/wordlists/rockyou.txt",  # Larger, but common
]
_found_default_passlist = None
for p_path in _try_default_passlist_paths:
    if os.path.exists(p_path):
        _found_default_passlist = p_path
        break

if DEFAULT_PASSWORD_LIST_PATH_ENV and os.path.exists(DEFAULT_PASSWORD_LIST_PATH_ENV):
    DEFAULT_PASSWORD_LIST = DEFAULT_PASSWORD_LIST_PATH_ENV
    logging.info(f"Using user-defined default password list: {DEFAULT_PASSWORD_LIST}")
elif _found_default_passlist:
    DEFAULT_PASSWORD_LIST = _found_default_passlist
    logging.info(f"Using system default password list: {DEFAULT_PASSWORD_LIST}")
else:
    DEFAULT_PASSWORD_LIST = None  # Explicitly None if no suitable default found
    logging.warning(
        "Could not find a common default password list (checked SecLists common paths and rockyou.txt). "
        "Hydra will require a password list to be specified by the user or AI, or it may fail."
    )

if DEFAULT_PASSWORD_LIST and not os.path.exists(DEFAULT_PASSWORD_LIST):
    logging.error(  # Elevated to error if a path was determined but file doesn't exist
        f"FATAL: Default password list was set to '{DEFAULT_PASSWORD_LIST}' but it does NOT exist. "
        "Hydra scans requiring a default list will fail."
    )
    DEFAULT_PASSWORD_LIST = None  # Invalidate if not found


# --- Tool Paths ---
# Define known common paths as fallbacks if shutil.which fails
KNOWN_TOOL_FALLBACK_PATHS = {
    "nmap": "/usr/bin/nmap",
    "gobuster": "/usr/bin/gobuster",  # Or e.g. /usr/local/bin/gobuster
    "nikto": "/usr/bin/nikto",  # Or sometimes /opt/nikto/program/nikto.pl (would need wrapper for .pl)
    "enum4linux-ng": "/usr/bin/enum4linux-ng",  # Or enum4linux-ng.py if that's the executable
    "hydra": "/usr/bin/hydra",
}

TOOL_PATHS = {}
for tool_name, fallback_path in KNOWN_TOOL_FALLBACK_PATHS.items():
    found_path_which = shutil.which(tool_name)
    if found_path_which:
        TOOL_PATHS[tool_name] = found_path_which
        logging.debug(f"Tool '{tool_name}' found via shutil.which: {found_path_which}")
    elif os.path.exists(fallback_path) and os.access(fallback_path, os.X_OK):
        TOOL_PATHS[tool_name] = fallback_path
        logging.info(
            f"Tool '{tool_name}' not in PATH via shutil.which, using known fallback: {fallback_path}"
        )
    else:
        TOOL_PATHS[tool_name] = (
            None  # Explicitly None if not found by which and fallback doesn't exist/is not executable
        )
        logging.warning(
            f"Tool '{tool_name}' not found by shutil.which, and its fallback path "
            f"'{fallback_path}' either does not exist or is not executable. "
            f"This tool will be unavailable unless path is manually corrected or set in environment."
        )


def check_tool(
    tool_name,
):  # This function is less critical now that CommandTool handles path checks robustly
    path = TOOL_PATHS.get(tool_name)
    if not path:
        # This log might be redundant if CommandTool logs it, but can be kept for a config-level check
        # logging.warning(
        #     f"Configuration check: Tool '{tool_name.capitalize()}' path not resolved. Associated scans might fail."
        # )
        return False
    return True


def initialize_openai_client():
    try:
        client = openai.OpenAI(api_key=API_KEY)
        # Test connection by listing models (lightweight call)
        client.models.list()
        logging.info("OpenAI client initialized and connection verified.")
        return client
    except openai.AuthenticationError:
        console.print(
            "[bold red]OpenAI Authentication Error: Invalid API Key. "
            "Please check your OPENAI_API_KEY environment variable.[/bold red]"
        )
        sys.exit(1)
    except openai.APIConnectionError as e:
        logging.error(f"OpenAI API Connection Error: {e}", exc_info=True)
        console.print(f"[bold red]OpenAI API Connection Error: {e}[/bold red]")
        sys.exit(1)
    except Exception as e:  # Catch any other openai client init errors
        logging.error(f"Failed to initialize OpenAI client: {e}", exc_info=True)
        console.print(f"[bold red]Error initializing OpenAI client: {e}[/bold red]")
        sys.exit(1)
