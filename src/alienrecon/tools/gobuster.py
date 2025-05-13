# src/alienrecon/tools/gobuster.py
import logging  # <-- Add this
import os
from typing import Any

from ..core.config import DEFAULT_WORDLIST
from .base import CommandTool

logger = logging.getLogger(__name__)  # <-- Add this


class GobusterTool(CommandTool):
    name: str = "gobuster"
    description: str = (
        "Performs directory and file brute-forcing on web servers using Gobuster."
    )
    executable_name: str = "gobuster"

    DEFAULT_STATUS_CODES = "200,204,301,302,307,403"
    DEFAULT_THREADS = "50"

    def build_command(
        self, target_ip: str, port: int, wordlist: str | None = None, **kwargs
    ) -> list[str]:
        if not target_ip:
            raise ValueError("Target IP must be provided for Gobuster.")
        if not port:
            raise ValueError("Port must be provided for Gobuster.")

        wordlist_to_use = wordlist or DEFAULT_WORDLIST
        if not wordlist_to_use:
            raise FileNotFoundError(
                "No specific wordlist provided and no default wordlist configured."
            )
        if not os.path.exists(wordlist_to_use):
            if wordlist_to_use == DEFAULT_WORDLIST:
                raise FileNotFoundError(
                    f"Default wordlist not found at '{DEFAULT_WORDLIST}'. "
                    f"Cannot run Gobuster."
                )
            else:
                logging.warning(  # Use logging directly here as logger might not be instantiated if called elsewhere
                    f"Specified wordlist '{wordlist}' not found. Attempting "
                    f"default '{DEFAULT_WORDLIST}'."
                )
                if not DEFAULT_WORDLIST or not os.path.exists(DEFAULT_WORDLIST):
                    raise FileNotFoundError(
                        f"Specified wordlist '{wordlist}' not found, and default "
                        f"wordlist '{DEFAULT_WORDLIST}' also not found."
                    )
                wordlist_to_use = DEFAULT_WORDLIST

        protocol = "https" if port in [443, 8443] else "http"
        target_url = f"{protocol}://{target_ip}:{port}"
        status_codes = kwargs.get("status_codes", self.DEFAULT_STATUS_CODES)
        threads = kwargs.get("threads", self.DEFAULT_THREADS)

        command_args = [
            "dir",
            "-u",
            target_url,
            "-w",
            wordlist_to_use,
            "-t",
            str(threads),
            "-q",
            "-s",
            status_codes,
            "-b",
            "",
            "--no-error",
        ]
        # Now logger is defined
        logger.debug(f"Using wordlist: {wordlist_to_use}")
        logger.debug(f"Built Gobuster command args: {command_args}")
        return command_args

    def parse_output(
        self, stdout: str | None, stderr: str | None, **kwargs
    ) -> dict[str, Any]:
        # Keep the original full parsing logic here from your file
        # ... (ensure the full, correct parsing logic is present)
        # Example structure:
        target_ip = kwargs.get("target_ip")
        port = kwargs.get("port")
        target_url_context = (
            f"http(s)://{target_ip}:{port}" if target_ip and port else "Unknown Target"
        )

        if stderr and "status-codes-blacklist" in stderr and "are both set" in stderr:
            return {
                "scan_summary": f"Gobuster scan related to {target_url_context} failed...",
                "error": stderr,
                "findings": [],
            }
        elif stderr and not stdout:
            return {
                "scan_summary": f"Gobuster scan related to {target_url_context} failed.",
                "error": stderr,
                "findings": [],
            }

        findings = []
        # ... (rest of the original parsing logic)

        summary = f"Gobuster scan related to {target_url_context} completed."
        # ... (construct summary based on findings)

        result_dict = {"scan_summary": summary, "findings": findings}
        if stderr and not stdout:
            result_dict["error"] = stderr

        return result_dict
