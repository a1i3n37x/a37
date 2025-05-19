import logging
import os
import re
from typing import Any

from ..core.config import DEFAULT_WORDLIST  # Import default wordlist from config

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
    ) -> dict[str, Any]:
        """
        Parses Gobuster text output into a structured dictionary.
        Now explicitly includes the status code in the findings.
        """
        target_ip = kwargs.get("target_ip")
        port = kwargs.get("port")
        target_url_context = (
            f"http(s)://{target_ip}:{port}" if target_ip and port else "Unknown Target"
        )

        # Check for common Gobuster errors first
        if stderr:
            if "status-codes and status-codes-blacklist are both set" in stderr:
                return {
                    "scan_summary": f"Gobuster scan for {target_url_context} failed due to conflicting status code arguments.",
                    "error": stderr.strip(),
                    "suggestion": "Ensure that status_codes (-s) and status_codes_blacklist (-b) are not used in a conflicting manner if custom arguments are passed.",
                    "findings": [],
                }
            # Other specific Gobuster errors can be checked here
            # For now, if stderr exists and stdout is empty, assume failure
            if not stdout:
                return {
                    "scan_summary": f"Gobuster scan for {target_url_context} failed or produced no output.",
                    "error": stderr.strip(),
                    "findings": [],
                }
            else:  # stderr might contain warnings even on success
                logger.warning(
                    f"Gobuster for {target_url_context} reported to stderr: {stderr[:200]}"
                )

        findings = []
        count = 0
        limit = 100  # Increased limit slightly
        truncated = False

        raw_url_base = ""
        if target_ip and port:
            protocol = "https" if port in [443, 8443] else "http"
            raw_url_base = f"{protocol}://{target_ip}:{port}"

        if stdout:
            # Gobuster output line format:
            # /path (Status: CODE) [Size: SIZE] --> /redirect_url (if 301/302)
            # We need to capture path, status, and optionally size/redirect.
            # Regex: ^\s*(/[^\s\(]+(?:\.\w+)?)\s*\(Status:\s*(\d+)\)(?:\s*\[Size:\s*(\d+)\])?(?:\s*\[-->\s*([^\s]+)\])?
            # Breakdown:
            # ^\s*                  -> Start of line, optional leading space
            # (/[^\s\(]+(?:\.\w+)?) -> Group 1: Path (starts with /, no space/paren, optionally ends with .ext)
            # \s*\(Status:\s*(\d+)\) -> Group 2: Status code (e.g., (Status: 200))
            # (?:\s*\[Size:\s*(\d+)\])? -> Optional Group 3: Size (e.g., [Size: 1234])
            # (?:\s*\[-->\s*([^\s]+)\])?-> Optional Group 4: Redirect URL (e.g., [--> http://new.url/])

            # Simpler initial regex just for path and status, then refine
            # line_pattern = re.compile(r"^\s*(?P<path>[^\s(]+)\s*\(Status:\s*(?P<status>\d+)\)")
            # More robust pattern:
            line_pattern = re.compile(
                r"^(?P<path>[^ \t(]+)"  # Path: non-space, non-tab, non-( characters
                r"\s*\(Status:\s*(?P<status>\d{3})\)"  # Status: (Status: XXX)
                r"(?:\s*\[Size:\s*(?P<size>\d+)\])?"  # Optional Size: [Size: NNN]
                r"(?:\s*\[-->\s*(?P<redirect>[^\]]+)\])?"  # Optional Redirect: [--> URL]
            )

            output_lines = stdout.strip().splitlines()
            for line_content in output_lines:
                line = line_content.strip()
                if not line or line.startswith(
                    ("#", "==", "Progress:", "[-]", "[+]")
                ):  # Skip comments/progress
                    continue

                if count >= limit:
                    truncated = True
                    break

                match = line_pattern.match(line)
                if match:
                    path_found = match.group("path").strip()
                    # Ensure path starts with a slash if it's not a full URL already (Gobuster usually outputs relative paths)
                    if not path_found.startswith(
                        ("http://", "https://")
                    ) and not path_found.startswith("/"):
                        path_found = "/" + path_found

                    status_found = match.group("status")
                    item = {"path": path_found, "status": status_found}

                    if raw_url_base and path_found.startswith("/"):
                        item["full_url"] = f"{raw_url_base.rstrip('/')}{path_found}"
                    else:  # If path_found is already a full URL or no base
                        item["full_url"] = path_found

                    if match.group("size"):
                        item["size"] = match.group("size")
                    if match.group("redirect"):
                        item["redirect_to"] = match.group("redirect").strip()

                    findings.append(item)
                    count += 1
                elif (
                    "(Status:" in line
                ):  # Fallback for lines that might not perfectly match but contain status
                    logger.debug(
                        f"Gobuster line with '(Status:' but not fully matched by regex: {line}"
                    )
                    # Try a simpler extraction if main regex fails for some lines
                    simple_match = re.search(r"^(.+?)\s+\(Status:\s*(\d+)\)", line)
                    if simple_match:
                        path_simple = simple_match.group(1).strip()
                        if not path_simple.startswith(
                            ("http://", "https://")
                        ) and not path_simple.startswith("/"):
                            path_simple = "/" + path_simple
                        status_simple = simple_match.group(2)
                        findings.append(
                            {
                                "path": path_simple,
                                "status": status_simple,
                                "full_url": f"{raw_url_base.rstrip('/')}{path_simple}"
                                if raw_url_base
                                else path_simple,
                                "comment": "Parsed with fallback regex",
                            }
                        )
                        count += 1
                    else:
                        findings.append(
                            {"raw_unparsed_finding": line}
                        )  # Store raw if no parse
                        count += 1

        summary = f"Gobuster scan for {target_url_context} completed."
        if stderr and not (
            len(findings) > 0 and "error" not in findings
        ):  # Don't override summary if findings exist and no major error
            summary += " Scan completed with potential issues noted in stderr."

        if findings:
            actual_findings_count = sum(
                1 for f in findings if "raw_unparsed_finding" not in f
            )
            if actual_findings_count > 0:
                summary += f" Found {actual_findings_count} potential paths/files."
            elif any("raw_unparsed_finding" in f for f in findings):
                summary += " Some output lines could not be fully parsed."
            else:  # No actual findings parsed
                summary += " No standard paths/files parsed from output."
        elif not stderr:  # No findings and no error in stderr
            summary += " No findings reported by Gobuster."

        if truncated:
            summary += f" (Results limited to first {limit} findings)."

        result_dict = {"scan_summary": summary, "findings": findings}
        if (
            stderr and "error" not in result_dict
        ):  # If stderr exists and we haven't already set a specific error field
            result_dict["stderr_output"] = stderr.strip()

        return result_dict
