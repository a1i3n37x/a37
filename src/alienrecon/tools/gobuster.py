import logging
import os
import re

from ..core.config import DEFAULT_WORDLIST  # Import default wordlist from config
from ..core.types import ToolResult

# Import base class and utilities
from .base import CommandTool

logger = logging.getLogger(__name__)


class GobusterTool(CommandTool):
    """
    Tool wrapper for executing Gobuster directory/file enumeration scans.
    """

    name: str = "gobuster"
    description: str = (
        "Performs directory and file brute-forcing on web servers using Gobuster."
    )
    executable_name: str = "gobuster"

    # Default Gobuster settings (can be overridden via kwargs if needed)
    # Updated to include 201 and 401 as per our findings
    DEFAULT_STATUS_CODES = "200,201,204,301,302,307,401,403"
    DEFAULT_THREADS = "50"

    def build_command(
        self,
        target_ip: str,
        port: int,
        wordlist: str | None = None,
        status_codes: str | None = None,
        **kwargs,
    ) -> list[str]:  # Added status_codes parameter
        """
        Constructs the Gobuster command arguments.

        Args:
            target_ip: The target IP address or hostname.
            port: The target port number.
            wordlist: Optional path to a specific wordlist. Uses default if None.
            status_codes: Optional comma-separated string of status codes to show.
            **kwargs: Additional optional arguments (e.g., threads).

        Returns:
            A list of strings for the Gobuster command (excluding the executable).

        Raises:
            ValueError: If target_ip or port is missing.
            FileNotFoundError: If the specified or default wordlist cannot be found.
        """
        if not target_ip:
            raise ValueError("Target IP must be provided for Gobuster.")
        if not port:
            raise ValueError("Port must be provided for Gobuster.")

        wordlist_to_use = wordlist or DEFAULT_WORDLIST
        if (
            not wordlist_to_use
        ):  # Should ideally not happen if DEFAULT_WORDLIST is well-defined
            # This case implies DEFAULT_WORDLIST itself might be None or empty
            raise FileNotFoundError(
                "No specific wordlist provided and no default wordlist configured or found."
            )
        if not os.path.exists(wordlist_to_use):
            # Attempt to expand user-specific paths like ~
            expanded_path = os.path.expanduser(wordlist_to_use)
            if os.path.exists(expanded_path):
                wordlist_to_use = expanded_path
            else:  # If still not found
                # If it was the default list that wasn't found
                if wordlist_to_use == DEFAULT_WORDLIST or (
                    wordlist and wordlist_to_use == os.path.expanduser(wordlist)
                ):
                    # Log clearly if default is missing, but allow execution if Hydra has internal lists
                    logging.error(
                        f"CRITICAL: Wordlist for Gobuster not found at '{wordlist_to_use}'. Gobuster will likely fail."
                    )
                    raise FileNotFoundError(
                        f"Gobuster wordlist not found at '{wordlist_to_use}'. Cannot run Gobuster."
                    )
                else:  # User specified a list that doesn't exist
                    logging.warning(
                        f"Specified wordlist '{wordlist}' not found. Attempting "
                        f"default '{DEFAULT_WORDLIST}'."
                    )
                    if not DEFAULT_WORDLIST or not os.path.exists(DEFAULT_WORDLIST):
                        raise FileNotFoundError(
                            f"Specified wordlist '{wordlist}' not found, and default "
                            f"wordlist '{DEFAULT_WORDLIST}' also not found/configured."
                        )
                    wordlist_to_use = DEFAULT_WORDLIST

        protocol = "https" if port in [443, 8443] else "http"
        target_url = f"{protocol}://{target_ip}:{port}"

        status_codes_to_use = status_codes or self.DEFAULT_STATUS_CODES
        threads = str(
            kwargs.get("threads", self.DEFAULT_THREADS)
        )  # Ensure threads is a string

        command_args = [
            "dir",
            "-u",
            target_url,
            "-w",
            wordlist_to_use,
            "-t",
            threads,
            "-q",  # Quiet mode to reduce noise
            "-s",
            status_codes_to_use,
            "-b",
            "",  # Don't blacklist any status codes by default with -b
            "--no-error",  # Suppress error messages for non-existent paths
        ]

        # Add extensions if provided, e.g. -x .php,.txt
        extensions = kwargs.get("extensions")
        if extensions:
            command_args.extend(["-x", extensions])

        logger.debug(f"Using Gobuster wordlist: {wordlist_to_use}")
        logger.debug(f"Built Gobuster command args: {command_args}")
        return command_args

    def parse_output(
        self, stdout: str | None, stderr: str | None, **kwargs
    ) -> ToolResult:
        target_ip = kwargs.get("target_ip")
        port = kwargs.get("port")
        target_url_context = (
            f"http(s)://{target_ip}:{port}" if target_ip and port else "Unknown Target"
        )
        result: ToolResult = {
            "tool_name": self.name,
            "status": "success",
            "scan_summary": f"Gobuster scan results for {target_url_context}",
            "findings": [],
        }
        if stderr:
            result["status"] = "failure"
            result["scan_summary"] = (
                f"Gobuster scan for {target_url_context} failed or produced no output."
            )
            result["error"] = stderr.strip()
            if stdout:
                result["raw_stdout"] = stdout[:5000]
            if stderr:
                result["raw_stderr"] = stderr[:5000]
            return result
        if not stdout:
            result["status"] = "failure"
            result["scan_summary"] = (
                f"Gobuster scan for {target_url_context} produced no output."
            )
            result["error"] = "No standard output received from Gobuster."
            return result
        findings = []
        # Example line: /admin (Status: 301) [Size: 0] [--> http://10.10.10.10/admin/]
        line_re = re.compile(r"^(?P<path>/\S*) \(Status: (?P<status>\d{3})\)")
        for line in stdout.splitlines():
            match = line_re.match(line.strip())
            if match:
                findings.append(
                    {
                        "path": match.group("path"),
                        "status": match.group("status"),
                    }
                )
        if findings:
            result["findings"] = findings
            result["status"] = "success"
        else:
            result["status"] = "failure"
            result["scan_summary"] = (
                f"Gobuster scan for {target_url_context} produced no output."
            )
            result["error"] = "No valid results parsed from Gobuster output."
        return result
