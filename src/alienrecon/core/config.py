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

# --- Enhanced Wordlist Configuration ---
DEFAULT_WORDLIST_PATH_ENV = os.getenv("ALIENRECON_WORDLIST")

# Define named wordlist sets for different purposes
WORDLIST_SETS = {
    "directory": {
        "fast": [
            "src/alienrecon/wordlists/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/dirb/wordlists/common.txt",
        ],
        "comprehensive": [
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt",
            "/usr/share/dirb/wordlists/big.txt",
        ],
        "default": [
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
            "/usr/share/dirb/wordlists/small.txt",
        ],
    },
    "dns": {
        "fast": [
            "src/alienrecon/wordlists/dns-fast-clean.txt",
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        ],
        "comprehensive": [
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
            "/usr/share/seclists/Discovery/DNS/fierce-hostlist.txt",
        ],
        "default": [
            "src/alienrecon/wordlists/dns-fast-clean.txt",
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
        ],
    },
    "parameters": {
        "fast": [
            "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
            "/usr/share/seclists/Discovery/Web-Content/api_endpoints.txt",
        ],
        "comprehensive": [
            "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt",
            "/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
        ],
        "default": [
            "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
        ],
    },
}


def find_wordlist(category: str, preference: str = "default") -> str:
    """
    Find the best available wordlist for a given category and preference.

    Args:
        category: Category of wordlist (directory, dns, parameters)
        preference: Preference level (fast, default, comprehensive)

    Returns:
        Path to the first available wordlist, or None if none found
    """
    if category not in WORDLIST_SETS:
        logging.warning(f"Unknown wordlist category: {category}")
        return None

    if preference not in WORDLIST_SETS[category]:
        logging.warning(
            f"Unknown preference '{preference}' for category '{category}', using 'default'"
        )
        preference = "default"

    wordlist_paths = WORDLIST_SETS[category][preference]

    for path in wordlist_paths:
        if os.path.exists(path):
            logging.debug(f"Found {category} wordlist ({preference}): {path}")
            return path

    # Fallback to other preferences if preferred not found
    for fallback_pref in ["default", "fast", "comprehensive"]:
        if fallback_pref != preference and fallback_pref in WORDLIST_SETS[category]:
            for path in WORDLIST_SETS[category][fallback_pref]:
                if os.path.exists(path):
                    logging.info(
                        f"Using fallback {category} wordlist ({fallback_pref}): {path}"
                    )
                    return path

    logging.warning(f"No {category} wordlist found for any preference level")
    return None


# Set default wordlists using the new system
DEFAULT_WORDLIST = (
    DEFAULT_WORDLIST_PATH_ENV
    if DEFAULT_WORDLIST_PATH_ENV and os.path.exists(DEFAULT_WORDLIST_PATH_ENV)
    else find_wordlist("directory", "default")
)

if not DEFAULT_WORDLIST:
    logging.warning(
        "No default directory wordlist found. Directory enumeration scans might fail unless "
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
    "nikto": "/usr/bin/nikto",  # Or sometimes /opt/nikto/program/nikto.pl (would need wrapper for .pl)
    "enum4linux-ng": "/usr/bin/enum4linux-ng",  # Or enum4linux-ng.py if that's the executable
    "hydra": "/usr/bin/hydra",
    "ffuf": "/usr/bin/ffuf",  # Added ffuf
    "openssl": "/usr/bin/openssl",  # Added openssl for SSL certificate inspection
    "curl": "/usr/bin/curl",  # Added curl for HTTP SSL probing
    "searchsploit": "/usr/bin/searchsploit",  # Added searchsploit for exploit database searches
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
