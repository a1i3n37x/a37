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
        target_ip: str = None,
        port: int = None,
        wordlist: str | None = None,
        status_codes: str | None = None,
        mode: str = "dir",
        domain: str = None,
        **kwargs,
    ) -> list[str]:
        """
        Constructs the Gobuster command arguments.

        Args:
            target_ip: The target IP address or hostname (for dir mode).
            port: The target port number (for dir mode).
            wordlist: Optional path to a specific wordlist. Uses default if None.
            status_codes: Optional comma-separated string of status codes to show (dir mode).
            mode: 'dir' for directory brute-force, 'dns' for subdomain enumeration, 'vhost' for virtual host discovery.
            domain: The domain to enumerate subdomains for (dns mode).
            **kwargs: Additional optional arguments (e.g., threads).

        Returns:
            A list of strings for the Gobuster command (excluding the executable).

        Raises:
            ValueError: If required arguments are missing.
            FileNotFoundError: If the specified or default wordlist cannot be found.
        """
        # Use mode-appropriate default wordlist if none specified
        if wordlist:
            wordlist_to_use = wordlist
        elif mode in ["dns", "vhost"]:
            # For DNS and vhost modes, use DNS-specific wordlist (try smaller/faster options first)
            # Get the directory where this script is located to find our custom wordlist
            script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            custom_fast_wordlist = os.path.join(
                script_dir, "wordlists", "dns-fast-clean.txt"
            )

            dns_wordlists = [
                custom_fast_wordlist,  # Our ultra-fast custom list (~50 entries)
                "/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt",  # ~2000 entries
                "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",  # 5000 entries
                "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",  # 20000 entries (original)
            ]
            wordlist_to_use = None
            for wl in dns_wordlists:
                if os.path.exists(wl):
                    wordlist_to_use = wl
                    break
            if not wordlist_to_use:
                # Fallback to the original large one
                wordlist_to_use = (
                    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
                )
        else:
            # For directory mode, use the configured default
            wordlist_to_use = DEFAULT_WORDLIST
        if not wordlist_to_use:
            raise FileNotFoundError(
                "No specific wordlist provided and no default wordlist configured or found."
            )

        # Try to resolve wordlist path
        if not os.path.exists(wordlist_to_use):
            expanded_path = os.path.expanduser(wordlist_to_use)
            if os.path.exists(expanded_path):
                wordlist_to_use = expanded_path
            else:
                # Try resolving relative to the default wordlist directory if short name
                if (
                    "/" not in wordlist_to_use
                    and DEFAULT_WORDLIST
                    and "/" in DEFAULT_WORDLIST
                ):
                    default_dir = os.path.dirname(DEFAULT_WORDLIST)
                    candidate = os.path.join(default_dir, wordlist_to_use)
                    if os.path.exists(candidate):
                        wordlist_to_use = candidate
                    else:
                        raise FileNotFoundError(
                            f"Gobuster wordlist not found at '{wordlist_to_use}' or '{candidate}'. Cannot run Gobuster."
                        )
                else:
                    raise FileNotFoundError(
                        f"Gobuster wordlist not found at '{wordlist_to_use}'. Cannot run Gobuster."
                    )

        # Use higher thread count for DNS and vhost modes by default
        if mode in ["dns", "vhost"]:
            threads = str(
                kwargs.get("threads", "150")
            )  # Even higher default for DNS/vhost speed
        else:
            threads = str(kwargs.get("threads", self.DEFAULT_THREADS))

        if mode == "dns":
            if not domain:
                raise ValueError("Domain must be provided for Gobuster DNS mode.")
            command_args = [
                "-q",  # Quiet mode for cleaner output
                "dns",
                "-d",
                domain,
                "-w",
                wordlist_to_use,
                "-t",
                threads,
                "--timeout",
                "5s",  # 5 second timeout for CTF environments
            ]

            # Add DNS server option if provided
            dns_server = kwargs.get("dns_server")
            if dns_server:
                command_args.extend(["-r", dns_server])
            logger.debug(f"Built Gobuster DNS command args: {command_args}")
            print(
                "[DEBUG] Gobuster DNS command:", [self.executable_name] + command_args
            )
            return command_args

        if mode == "vhost":
            # Virtual host discovery mode (like ffuf with Host headers)
            if not target_ip:
                raise ValueError("Target IP must be provided for Gobuster vhost mode.")
            if not domain:
                raise ValueError("Domain must be provided for Gobuster vhost mode.")

            # Determine protocol
            port = kwargs.get(
                "port", 443
            )  # Default to 443 for vhost mode (HTTPS is more common in CTFs)
            protocol = "https" if int(port) in [443, 8443] else "http"
            target_url = f"{protocol}://{target_ip}:{port}"

            command_args = [
                "-q",  # Quiet mode for cleaner output
                "vhost",
                "-u",
                target_url,
                "-w",
                wordlist_to_use,
                "-t",
                threads,
                "--timeout",
                "5s",  # 5 second timeout
                "--domain",
                domain,  # The base domain to append to wordlist entries
            ]

            # Add ignore cert errors for HTTPS
            if port in [443, 8443]:
                command_args.append("-k")

            logger.debug(f"Built Gobuster vhost command args: {command_args}")
            print(
                "[DEBUG] Gobuster vhost command:", [self.executable_name] + command_args
            )
            return command_args

        # Directory mode (default)
        if not target_ip:
            raise ValueError("Target IP must be provided for Gobuster dir mode.")
        if not port:
            raise ValueError("Port must be provided for Gobuster dir mode.")

        protocol = "https" if port in [443, 8443] else "http"
        target_url = f"{protocol}://{target_ip}:{port}"
        status_codes_to_use = status_codes or self.DEFAULT_STATUS_CODES

        command_args = [
            "dir",
            "-u",
            target_url,
            "-w",
            wordlist_to_use,
            "-t",
            threads,
            "-q",
            "-s",
            status_codes_to_use,
            "-b",
            "",
            "--no-error",
        ]

        extensions = kwargs.get("extensions")
        if extensions:
            command_args.extend(["-x", extensions])
        if kwargs.get("ignore_cert_errors"):
            command_args.append("-k")

        logger.debug(f"Using Gobuster wordlist: {wordlist_to_use}")
        logger.debug(f"Built Gobuster dir command args: {command_args}")
        print("[DEBUG] Gobuster dir command:", [self.executable_name] + command_args)
        return command_args

    def parse_output(
        self, stdout: str | None, stderr: str | None, mode: str = "dir", **kwargs
    ) -> ToolResult:
        result: ToolResult = {
            "tool_name": self.name,
            "status": "success",
            "scan_summary": "Gobuster scan results",
            "findings": [],
        }
        if stderr:
            result["status"] = "failure"
            result["scan_summary"] = "Gobuster scan failed or produced no output."
            result["error"] = stderr.strip()
            if stdout:
                result["raw_stdout"] = stdout[:5000]
            if stderr:
                result["raw_stderr"] = stderr[:5000]
            return result
        if not stdout:
            result["status"] = "failure"
            result["scan_summary"] = "Gobuster scan produced no output."
            result["error"] = "No standard output received from Gobuster."
            return result
        findings = []
        if mode == "dns":
            # Example line: Found: admin.example.com
            dns_re = re.compile(r"^Found: (\S+)")
            for line in stdout.splitlines():
                match = dns_re.match(line.strip())
                if match:
                    findings.append({"subdomain": match.group(1)})
            result["scan_summary"] = "Gobuster DNS (subdomain) scan results"
        elif mode == "vhost":
            # Example line: Found: blog.futurevera.thm (Status: 200) [Size: 3838]
            vhost_re = re.compile(r"^Found: (\S+) \(Status: (\d{3})\)")
            for line in stdout.splitlines():
                match = vhost_re.match(line.strip())
                if match:
                    findings.append({"vhost": match.group(1), "status": match.group(2)})
            result["scan_summary"] = "Gobuster vhost (virtual host) scan results"
        else:
            # Directory mode (default)
            target_ip = kwargs.get("target_ip")
            port = kwargs.get("port")
            target_url_context = (
                f"http(s)://{target_ip}:{port}"
                if target_ip and port
                else "Unknown Target"
            )
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
            result["scan_summary"] = f"Gobuster scan results for {target_url_context}"
        if findings:
            result["findings"] = findings
            result["status"] = "success"
        else:
            # For DNS and vhost modes, finding nothing is still a successful result
            if mode in ["dns", "vhost"]:
                result["status"] = "success"
                scan_type = "subdomains" if mode == "dns" else "virtual hosts"
                result["scan_summary"] = (
                    f"Gobuster {mode} scan completed - no {scan_type} found"
                )
                result["findings"] = []
            else:
                result["status"] = "failure"
                result["scan_summary"] += (
                    ". No valid results parsed from Gobuster output."
                )
                result["error"] = "No valid results parsed from Gobuster output."
        return result
