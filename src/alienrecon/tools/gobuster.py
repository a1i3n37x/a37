# alienrecon/tools/gobuster.py
import os
import logging
import re
import json
from typing import Any, Dict, List, Optional

# Import base class and utilities
from .base import CommandTool
from ..config import console, DEFAULT_WORDLIST # Import default wordlist from config

class GobusterTool(CommandTool):
    """
    Tool wrapper for executing Gobuster directory/file enumeration scans.
    """
    name: str = "gobuster"
    description: str = "Performs directory and file brute-forcing on web servers using Gobuster."
    executable_name: str = "gobuster"

    # Default Gobuster settings (can be overridden via kwargs if needed)
    DEFAULT_STATUS_CODES = "200,204,301,302,307,403"
    DEFAULT_THREADS = "50"

    def build_command(self, target_ip: str, port: int, wordlist: Optional[str] = None, **kwargs) -> List[str]:
        """
        Constructs the Gobuster command arguments.

        Args:
            target_ip: The target IP address or hostname.
            port: The target port number.
            wordlist: Optional path to a specific wordlist. Uses default if None.
            **kwargs: Additional optional arguments (e.g., threads, status_codes).

        Returns:
            A list of strings for the Gobuster command (excluding the executable).

        Raises:
            ValueError: If target_ip or port is missing.
            FileNotFoundError: If the specified or default wordlist cannot be found.
        """
        if not target_ip: raise ValueError("Target IP must be provided for Gobuster.")
        if not port: raise ValueError("Port must be provided for Gobuster.")

        # Determine wordlist to use
        wordlist_to_use = wordlist or DEFAULT_WORDLIST
        if not wordlist_to_use:
            raise FileNotFoundError("No specific wordlist provided and no default wordlist configured.")
        if not os.path.exists(wordlist_to_use):
            # If specified wordlist not found, check if it was the default
            if wordlist_to_use == DEFAULT_WORDLIST:
                 raise FileNotFoundError(f"Default wordlist not found at '{DEFAULT_WORDLIST}'. Cannot run Gobuster.")
            else:
                 # If user specified a non-existent one, try falling back to default
                 logging.warning(f"Specified wordlist '{wordlist}' not found. Attempting default '{DEFAULT_WORDLIST}'.")
                 if not DEFAULT_WORDLIST or not os.path.exists(DEFAULT_WORDLIST):
                      raise FileNotFoundError(f"Specified wordlist '{wordlist}' not found, and default wordlist '{DEFAULT_WORDLIST}' also not found.")
                 wordlist_to_use = DEFAULT_WORDLIST # Use default as fallback

        # Determine protocol and build URL
        protocol = "https" if port in [443, 8443] else "http"
        target_url = f"{protocol}://{target_ip}:{port}"

        # Get settings, using defaults if not provided in kwargs
        status_codes = kwargs.get("status_codes", self.DEFAULT_STATUS_CODES)
        threads = kwargs.get("threads", self.DEFAULT_THREADS)

        # Build command list
        command_args = [
            "dir", # Gobuster mode
            "-u", target_url,
            "-w", wordlist_to_use,
            "-t", str(threads),
            "-q", # Quiet mode (less console noise)
            "-s", status_codes, # Show specific statuses
            "-b", "", # Explicitly disable status code blacklist as suggested by error message
            "--no-error" # Suppress connection errors in output
        ]
        logging.info(f"Using wordlist: {wordlist_to_use}")
        logging.debug(f"Built Gobuster command args: {command_args}")
        return command_args

    def parse_output(self, stdout: Optional[str], stderr: Optional[str], **kwargs) -> Dict[str, Any]:
        """
        Parses Gobuster text output into a structured dictionary.

        Args:
            stdout: Raw text output from Gobuster execution.
            stderr: Error output from Gobuster or run_command.
            **kwargs: Original arguments (target_ip, port) for context.

        Returns:
            A dictionary containing the parsed scan results or error information.
        """
        target_ip = kwargs.get("target_ip")
        port = kwargs.get("port")
        target_url_context = f"http(s)://{target_ip}:{port}" if target_ip and port else "Unknown Target"

        # Handle execution failure indicated by stderr and lack of stdout
        # Check if the specific argument parsing error occurred
        if stderr and "status-codes-blacklist" in stderr and "are both set" in stderr:
             # Provide a more specific error summary for this known issue
             return {
                "scan_summary": f"Gobuster scan related to {target_url_context} failed due to conflicting status code arguments.",
                "error": stderr,
                "suggestion": "Try running again. If the error persists, check Gobuster version compatibility or manually adjust arguments.",
                "findings": []
            }
        elif stderr and not stdout:
            # General failure
            return {
                "scan_summary": f"Gobuster scan related to {target_url_context} failed.",
                "error": stderr,
                "findings": []
            }


        findings = []
        count = 0
        limit = 50 # Limit results for LLM context window
        truncated = False

        # Determine base URL for constructing full paths
        raw_url_base = ""
        if target_ip and port:
            protocol = "https" if port in [443, 8443] else "http"
            raw_url_base = f"{protocol}://{target_ip}:{port}"

        # Process stdout if available
        if stdout:
            output_lines = stdout.strip().splitlines()
            for line in output_lines:
                line = line.strip()
                # Skip empty lines, comments, progress, etc.
                if not line or line.startswith(("#", "==", "Progress:", "[-]", "[+]")): continue
                if count >= limit:
                    truncated = True
                    break

                # Regex for Gobuster v3 format: Path (Status: CODE) [Size: N] [--> Redirect]
                match = re.search(r"^(.+?)\s+\(Status:\s*(\d+)\)", line)
                if match:
                    path = match.group(1).strip()
                    # Ensure path starts with a slash if it's relative
                    if not path.startswith(("http://", "https://")) and not path.startswith("/"):
                        path = "/" + path
                    status = match.group(2)
                    # Construct full URL if possible and base is known
                    full_url = f"{raw_url_base.rstrip('/')}{path}" if raw_url_base and path.startswith('/') else path
                    findings.append({"url_or_path": full_url, "status": status})
                    count += 1
                elif "(Status:" in line: # Fallback for lines that might contain status but not match perfectly
                    findings.append({"raw": line}) # Keep raw line if parsing fails but seems relevant
                    count += 1

        # Construct summary message
        if stderr: # Scan ran but also had errors/warnings in stderr
            summary = f"Gobuster scan related to {target_url_context} completed with potential issues."
            # Add stderr as a warning finding if not already captured as the main error
            findings.append({"warning": f"Scan stderr reported: {stderr.strip()}"})
        else:
            summary = f"Gobuster scan related to {target_url_context} completed."

        if findings:
            actual_findings_count = sum(1 for f in findings if 'raw' not in f and 'warning' not in f)
            if actual_findings_count > 0:
                summary += f" Found {actual_findings_count} potential paths/files."
            elif any('warning' in f for f in findings):
                 summary += " No standard paths/files parsed, but warnings were reported."
            else: # Only raw findings
                 summary += " No standard paths/files parsed, but raw output present."
        elif not stderr: # No findings and no error means scan likely found nothing
            summary += " No findings reported."

        if truncated: summary += f" (Results limited to first {limit} findings)."

        result_dict = {"scan_summary": summary, "findings": findings}
        # Add error key only if stderr was the *primary* indicator of failure (no stdout)
        if stderr and not stdout:
             result_dict["error"] = stderr # Already added to summary above

        return result_dict

