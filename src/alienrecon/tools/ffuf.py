"""
FFUF (Fuzz Faster U Fool) Tool Wrapper

This module provides a tool wrapper for FFUF to perform various fuzzing tasks:
- Virtual host discovery via Host header fuzzing
- Directory and file enumeration
- Parameter fuzzing
- POST data fuzzing
"""

import json
import logging
import os
import re
from typing import Optional
from urllib.parse import urlparse

from ..core.config import DEFAULT_WORDLIST
from ..core.types import ToolResult
from .base import CommandTool

logger = logging.getLogger(__name__)


class FFUFTool(CommandTool):
    """
    Tool wrapper for executing FFUF (Fuzz Faster U Fool) fuzzing scans.
    """

    name: str = "ffuf"
    description: str = "Performs web application fuzzing using FFUF for vhost discovery, directory enumeration, and parameter fuzzing."
    executable_name: str = "ffuf"

    def build_command(
        self,
        mode: str = "vhost",
        url: str = None,
        ip: str = None,
        domain: str = None,
        port: int = None,
        wordlist: str = None,
        threads: int = 40,
        timeout: int = 10,
        filter_size: Optional[int] = None,
        filter_words: Optional[int] = None,
        filter_lines: Optional[int] = None,
        match_codes: Optional[list[int]] = None,
        extensions: Optional[list[str]] = None,
        method: str = "GET",
        data: Optional[str] = None,
        headers: Optional[dict] = None,
        **kwargs,
    ) -> list[str]:
        """
        Constructs the FFUF command arguments.

        Args:
            mode: Fuzzing mode - 'vhost', 'dir', 'param', 'post'
            url: Target URL (for dir/param/post modes)
            ip: Target IP (for vhost mode)
            domain: Domain for vhost fuzzing
            port: Target port
            wordlist: Path to wordlist file
            threads: Number of concurrent threads
            timeout: Request timeout in seconds
            filter_size: Filter responses by size
            filter_words: Filter responses by word count
            filter_lines: Filter responses by line count
            match_codes: HTTP status codes to match
            extensions: File extensions for directory fuzzing
            method: HTTP method
            data: POST data for POST fuzzing
            headers: Additional HTTP headers
            **kwargs: Additional arguments

        Returns:
            List of command arguments for FFUF

        Raises:
            ValueError: If required arguments are missing
            FileNotFoundError: If wordlist cannot be found
        """

        # Determine wordlist
        if wordlist:
            wordlist_to_use = wordlist
        elif mode in ["vhost", "dns"]:
            # Use DNS-optimized wordlist for vhost/subdomain fuzzing
            script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            custom_fast_wordlist = os.path.join(
                script_dir, "wordlists", "dns-fast-clean.txt"
            )

            dns_wordlists = [
                custom_fast_wordlist,
                "/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt",
                "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            ]
            wordlist_to_use = None
            for wl in dns_wordlists:
                if os.path.exists(wl):
                    wordlist_to_use = wl
                    break
            if not wordlist_to_use:
                wordlist_to_use = (
                    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
                )
        else:
            # Use default directory wordlist
            wordlist_to_use = (
                DEFAULT_WORDLIST
                or "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            )

        # Verify wordlist exists
        if not os.path.exists(wordlist_to_use):
            expanded_path = os.path.expanduser(wordlist_to_use)
            if os.path.exists(expanded_path):
                wordlist_to_use = expanded_path
            else:
                raise FileNotFoundError(
                    f"FFUF wordlist not found at '{wordlist_to_use}'. Cannot run FFUF."
                )

        # Base command arguments
        command_args = [
            "-w",
            wordlist_to_use,
            "-t",
            str(threads),
            "-timeout",
            str(timeout),
            "-o",
            "-",  # Output to stdout
            "-of",
            "json",  # JSON output format for easier parsing
            "-noninteractive",  # Non-interactive mode
            "-s",  # Silent mode to suppress banner and other non-JSON output
        ]

        # Mode-specific arguments
        if mode == "vhost":
            if not ip or not domain:
                raise ValueError("IP and domain must be provided for FFUF vhost mode.")

            port = port or 80
            protocol = "https" if port in [443, 8443] else "http"
            target_url = f"{protocol}://{ip}:{port}"

            command_args.extend(
                [
                    "-u",
                    target_url,
                    "-H",
                    f"Host: FUZZ.{domain}",
                ]
            )

            if filter_size is not None:
                command_args.extend(["-fs", str(filter_size)])
            else:
                # Auto-calibrate if no specific filter size is given for vhost
                command_args.append("-ac")

        elif mode == "dir":
            if not url:
                raise ValueError("URL must be provided for FFUF directory mode.")

            # Ensure URL ends with /FUZZ for directory fuzzing
            if not url.endswith("/"):
                url += "/"
            if "FUZZ" not in url:
                url += "FUZZ"

            command_args.extend(["-u", url])

            # Add extensions if provided
            if extensions:
                ext_list = ",".join(extensions)
                command_args.extend(["-e", ext_list])

        elif mode == "param":
            if not url:
                raise ValueError("URL must be provided for FFUF parameter mode.")

            # Parameter fuzzing - assume URL contains FUZZ placeholder
            if "FUZZ" not in url:
                # Add FUZZ as a parameter if not present
                separator = "&" if "?" in url else "?"
                url += f"{separator}FUZZ=test"

            command_args.extend(["-u", url])

        elif mode == "post":
            if not url or not data:
                raise ValueError("URL and data must be provided for FFUF POST mode.")

            command_args.extend(
                [
                    "-u",
                    url,
                    "-X",
                    "POST",
                    "-d",
                    data,
                ]
            )

        else:
            raise ValueError(f"Unsupported FFUF mode: {mode}")

        # Add HTTP method if not default
        if method and method.upper() != "GET" and mode != "post":
            command_args.extend(["-X", method.upper()])

        # Add match codes
        if match_codes:
            code_list = ",".join(map(str, match_codes))
            command_args.extend(["-mc", code_list])
        else:
            # Default match codes for web fuzzing
            command_args.extend(["-mc", "200,201,202,204,301,302,307,401,403"])

        # Add filters
        if filter_words:
            command_args.extend(["-fw", str(filter_words)])
        if filter_lines:
            command_args.extend(["-fl", str(filter_lines)])

        # Add custom headers
        if headers:
            for key, value in headers.items():
                command_args.extend(["-H", f"{key}: {value}"])

        # Add SSL options for HTTPS
        if (ip and port in [443, 8443]) or (url and url.startswith("https://")):
            command_args.append("-k")  # Ignore SSL certificate errors

        logger.debug(f"Built FFUF {mode} command args: {command_args}")
        return command_args

    def parse_output(
        self, stdout: str | None, stderr: str | None, mode: str = "vhost", **kwargs
    ) -> ToolResult:
        """
        Parse FFUF JSON output and return structured results.
        """
        target_context = kwargs.get("url") or kwargs.get("ip") or "Unknown Target"
        scan_summary = f"FFUF {mode} scan results for {target_context}:"

        result: ToolResult = {
            "tool_name": self.name,
            "status": "success",
            "scan_summary": scan_summary,
            "findings": {},
        }

        if stderr and "error" in stderr.lower():
            result["status"] = "failure"
            result["scan_summary"] = f"FFUF {mode} scan for {target_context} failed."
            result["error"] = stderr
            result["findings"] = {}
            return result

        if not stdout or not stdout.strip():
            result["status"] = "failure"
            result["scan_summary"] = (
                f"FFUF {mode} scan for {target_context} produced no valid output."
            )
            result["error"] = "No output or only whitespace received from FFUF stdout."
            result["findings"] = {}
            return result

        try:
            content_to_parse = stdout.strip()

            first_brace = content_to_parse.find("{")
            last_brace = content_to_parse.rfind("}")

            if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
                json_candidate = content_to_parse[first_brace : last_brace + 1]
                try:
                    data = json.loads(json_candidate)
                    results = data.get("results", [])

                    if mode == "vhost":
                        # Parse virtual host results
                        vhosts = []
                        for item in results:
                            vhost_name = self._extract_vhost_from_request(item)
                            if vhost_name:
                                vhosts.append(
                                    {
                                        "vhost": vhost_name,
                                        "status_code": item.get("status", 0),
                                        "size": item.get("length", 0),
                                        "words": item.get("words", 0),
                                        "lines": item.get("lines", 0),
                                        "url": item.get("url", ""),
                                    }
                                )

                        result["findings"] = {"vhosts": vhosts}
                        result["scan_summary"] = (
                            f"FFUF vhost scan found {len(vhosts)} virtual hosts."
                        )
                        if not vhosts and not data.get(
                            "commandline"
                        ):  # Check if results are empty but no error in ffuf
                            result["scan_summary"] += (
                                " No distinct virtual hosts found with current settings."
                            )

                    elif mode == "dir":
                        # Parse directory enumeration results
                        directories = []
                        for item in results:
                            path = self._extract_path_from_url(item.get("url", ""))
                            if path:
                                directories.append(
                                    {
                                        "path": path,
                                        "url": item.get("url", ""),
                                        "status_code": item.get("status", 0),
                                        "size": item.get("length", 0),
                                        "words": item.get("words", 0),
                                        "lines": item.get("lines", 0),
                                    }
                                )

                        result["findings"] = {"directories": directories}
                        result["scan_summary"] = (
                            f"FFUF directory scan found {len(directories)} directories/files."
                        )

                    elif mode in ["param", "post"]:
                        # Parse parameter fuzzing results
                        parameters = []
                        for item in results:
                            param_value = self._extract_param_from_request(item)
                            if param_value:
                                parameters.append(
                                    {
                                        "parameter": param_value,
                                        "status_code": item.get("status", 0),
                                        "size": item.get("length", 0),
                                        "words": item.get("words", 0),
                                        "lines": item.get("lines", 0),
                                        "url": item.get("url", ""),
                                    }
                                )

                        result["findings"] = {"parameters": parameters}
                        result["scan_summary"] = (
                            f"FFUF parameter scan found {len(parameters)} interesting parameters."
                        )

                    # Add statistics if available
                    if "commandline" in data:
                        result["command_used"] = " ".join(
                            data["commandline"]
                        )  # ffuf provides this as a list
                    if "time" in data:
                        result["scan_time"] = data["time"]

                    # If results list is empty, reflect that in summary
                    if not results and result["status"] == "success":
                        result["scan_summary"] = (
                            f"FFUF {mode} scan completed for {target_context}. No findings matched the criteria."
                        )

                    return result

                except json.JSONDecodeError as e:
                    logger.warning(
                        f"JSONDecodeError with candidate string. Error: {e}. Candidate: '{json_candidate[:200]}...'"
                    )
                    # Fall through to raw parsing
                    pass  # Will be caught by the outer try-except or fall to raw parsing below

            # If JSON delimiting/parsing failed, try raw output parsing as a last resort
            logger.warning(
                f"Could not find or parse valid JSON structure in FFUF output. Raw output processing will be attempted. Output: \\n{stdout[:500]}"
            )
            result["status"] = "partial"
            result["error"] = (
                "Failed to parse structured JSON output from FFUF. Displaying raw findings."
            )
            result["findings"] = self._parse_raw_output(stdout, mode)  # original stdout
            result["raw_stdout"] = stdout  # Add raw output if parsing failed
            return result

        except Exception as e:
            logger.error(f"Error parsing FFUF output: {e}")
            result["status"] = "failure"
            result["error"] = str(e)
            result["findings"] = {}
            return result

    def _extract_vhost_from_request(self, item: dict) -> str:
        """Extract virtual host name from FFUF result item."""
        # Look for Host header in the request
        input_data = item.get("input", {})
        if "FUZZ" in input_data:
            return input_data["FUZZ"]

        # Fallback: try to extract from URL or headers
        if "Host:" in str(item):
            # Extract from headers if visible
            host_match = re.search(r"Host:\s*([^\s,]+)", str(item))
            if host_match:
                return host_match.group(1)

        # Last resort: try to parse the URL if it contains one
        try:
            parsed = urlparse(item.get("url", ""))
            return parsed.path
        except Exception:
            # Fallback to simple extraction
            if "/" in item.get("url", ""):
                return item.get("url", "").split("/")[-1]
            return "unknown"

    def _extract_path_from_url(self, url: str) -> str:
        """Extract path from URL for directory enumeration."""
        try:
            parsed = urlparse(url)
            return parsed.path
        except Exception:
            # Fallback to simple extraction
            if "/" in url:
                return "/" + url.split("/", 3)[-1] if len(url.split("/")) > 3 else "/"
            return url

    def _extract_param_from_request(self, item: dict) -> str:
        """Extract parameter value from FFUF result item."""
        input_data = item.get("input", {})
        if "FUZZ" in input_data:
            return input_data["FUZZ"]
        return ""

    def _parse_raw_output(self, output: str, mode: str) -> dict:
        """Fallback parser for non-JSON output."""
        findings_list = []
        structured_findings = {}

        lines = output.split("\n")

        # Try to find structured lines first (e.g., with Status, Size)
        for line in lines:
            if (
                "Status:" in line and "Size:" in line
            ):  # Basic check for a more structured ffuf raw line
                # This part would need more fleshing out if we wanted to extract details from generic raw lines
                findings_list.append({"raw_line_info": line.strip()})

        if not findings_list:  # If no structured lines were found, treat lines as direct findings based on mode
            if mode == "vhost":
                # For vhost, each non-empty line is likely a vhost name
                raw_vhosts = [line.strip() for line in lines if line.strip()]
                findings_list = [{"vhost": v} for v in raw_vhosts]
                structured_findings = {"vhosts": findings_list}
            elif mode == "dir":
                # For dir, each non-empty line might be a path
                raw_paths = [line.strip() for line in lines if line.strip()]
                findings_list = [{"path": p} for p in raw_paths]  # Basic structure
                structured_findings = {"directories": findings_list}
            else:  # General fallback for other modes
                generic_findings = [line.strip() for line in lines if line.strip()]
                findings_list = [{"value": f} for f in generic_findings]
                structured_findings = {"generic_findings": findings_list}
        else:  # If structured raw lines were found (e.g. containing Status/Size)
            if mode == "vhost":
                structured_findings = {"vhosts_raw_info": findings_list}
            elif mode == "dir":
                structured_findings = {"directories_raw_info": findings_list}
            else:
                structured_findings = {"generic_raw_info": findings_list}

        logger.debug(
            f"Fallback raw parser produced for mode '{mode}': {structured_findings}"
        )
        return structured_findings
