"""
LLM-Aware Tool Functions

This module provides dedicated, purpose-built functions for each tool's specific use cases.
Each function has clear parameters, guardrails, and returns structured, parsed data.

These functions are designed to be directly callable by LLMs with proper parameter validation
and intelligent defaults.
"""

import logging
from typing import Optional, Union

from ..core.config import DEFAULT_WORDLIST
from .ffuf import FFUFTool
from .gobuster import GobusterTool
from .nikto import NiktoTool
from .nmap import NmapTool

logger = logging.getLogger(__name__)


# =============================================================================
# FFUF Functions (To be implemented when FFUF tool is created)
# =============================================================================


def ffuf_vhost_enum(
    ip: str,
    domain: str,
    wordlist: Optional[str] = None,
    threads: int = 40,
    filter_size: Optional[int] = None,
    timeout: int = 10,
    port: int = 443,
) -> dict:
    """
    Enumerate virtual hosts via Host header fuzzing on target IP.

    Args:
        ip: Target IP address (must be a numeric IP, e.g., 10.10.10.10, not a domain name)
        domain: Base domain to test subdomains against (e.g., 'futurevera.thm')
        wordlist: Path to subdomain wordlist (uses DNS-optimized default if None)
        threads: Number of concurrent threads
        filter_size: Filter out responses of this size (auto-detect baseline if None)
        timeout: Request timeout in seconds
        port: Target port (default: 443)

    Returns:
        Dict with parsed findings, including list of discovered virtual hosts
    """
    try:
        ffuf = FFUFTool()
        if not ffuf.executable_path:
            return {
                "tool": "ffuf",
                "mode": "vhost_enum",
                "status": "failure",
                "error": "FFUF executable not found",
                "findings": [],
            }

        # Execute the scan
        result = ffuf.execute(
            mode="vhost",
            ip=ip,
            domain=domain,
            port=port,
            wordlist=wordlist,
            threads=threads,
            timeout=timeout,
            filter_size=filter_size,
        )

        # Parse and structure the response
        findings = []
        if result.get("status") == "success" and "findings" in result:
            vhosts = result["findings"].get("vhosts", [])
            findings = [vhost.get("vhost", "") for vhost in vhosts if "vhost" in vhost]

        return {
            "tool": "ffuf",
            "mode": "vhost_enum",
            "status": result.get("status", "unknown"),
            "findings": findings,
            "scan_summary": result.get("scan_summary", ""),
            "raw_output": result.get("raw_stdout", "")[:1000]
            if result.get("raw_stdout")
            else None,
            "error": result.get("error"),
        }

    except Exception as e:
        logger.error(f"Error in ffuf_vhost_enum: {e}")
        return {
            "tool": "ffuf",
            "mode": "vhost_enum",
            "status": "failure",
            "error": str(e),
            "findings": [],
        }


def ffuf_dir_enum(
    url: str,
    wordlist: Optional[str] = DEFAULT_WORDLIST,
    extensions: Optional[list[str]] = None,
    match_codes: Optional[list[int]] = None,
    filter_size: Optional[int] = None,
    threads: int = 40,
) -> dict:
    """
    Enumerate directories and files on a web server.

    Args:
        url: Target URL (e.g., 'https://10.10.10.10')
        wordlist: Path to directory wordlist (defaults to system-configured DEFAULT_WORDLIST)
        extensions: List of file extensions to test (e.g., ['php', 'txt', 'html'])
        match_codes: HTTP status codes to include (default: [200, 301, 403])
        filter_size: Filter out responses of this size
        threads: Number of concurrent threads

    Returns:
        Dict with parsed findings, including discovered directories and files
    """
    try:
        ffuf = FFUFTool()
        if not ffuf.executable_path:
            return {
                "tool": "ffuf",
                "mode": "dir_enum",
                "status": "failure",
                "error": "FFUF executable not found",
                "findings": [],
            }

        if match_codes is None:
            match_codes = [200, 301, 403]

        # Execute the scan
        result = ffuf.execute(
            mode="dir",
            url=url,
            wordlist=wordlist,
            extensions=extensions,
            match_codes=match_codes,
            filter_size=filter_size,
            threads=threads,
        )

        # Parse and structure the response
        findings = []
        if result.get("status") == "success" and "findings" in result:
            directories = result["findings"].get("directories", [])
            findings = [
                {
                    "path": item.get("path", ""),
                    "url": item.get("url", ""),
                    "status_code": item.get("status_code"),
                    "size": item.get("size"),
                }
                for item in directories
            ]

        return {
            "tool": "ffuf",
            "mode": "dir_enum",
            "status": result.get("status", "unknown"),
            "findings": findings,
            "scan_summary": result.get("scan_summary", ""),
            "raw_output": result.get("raw_stdout", "")[:1000]
            if result.get("raw_stdout")
            else None,
            "error": result.get("error"),
        }

    except Exception as e:
        logger.error(f"Error in ffuf_dir_enum: {e}")
        return {
            "tool": "ffuf",
            "mode": "dir_enum",
            "status": "failure",
            "error": str(e),
            "findings": [],
        }


def ffuf_param_fuzz(
    url: str,
    param_name: str,
    wordlist: Optional[str] = None,
    method: str = "GET",
    threads: int = 40,
) -> dict:
    """
    Fuzz a specific parameter for common values.

    Args:
        url: Target URL with parameter placeholder
        param_name: Name of the parameter to fuzz
        wordlist: Path to parameter values wordlist
        method: HTTP method (GET or POST)
        threads: Number of concurrent threads

    Returns:
        Dict with parsed findings, including interesting parameter values
    """
    try:
        ffuf = FFUFTool()
        if not ffuf.executable_path:
            return {
                "tool": "ffuf",
                "mode": "param_fuzz",
                "status": "failure",
                "error": "FFUF executable not found",
                "findings": [],
            }

        # Ensure URL has parameter placeholder
        if "FUZZ" not in url:
            separator = "&" if "?" in url else "?"
            url += f"{separator}{param_name}=FUZZ"

        # Execute the scan
        result = ffuf.execute(
            mode="param", url=url, wordlist=wordlist, method=method, threads=threads
        )

        # Parse and structure the response
        findings = []
        if result.get("status") == "success" and "findings" in result:
            parameters = result["findings"].get("parameters", [])
            findings = [
                {
                    "parameter": item.get("parameter", ""),
                    "status_code": item.get("status_code"),
                    "size": item.get("size"),
                }
                for item in parameters
            ]

        return {
            "tool": "ffuf",
            "mode": "param_fuzz",
            "status": result.get("status", "unknown"),
            "findings": findings,
            "scan_summary": result.get("scan_summary", ""),
            "raw_output": result.get("raw_stdout", "")[:1000]
            if result.get("raw_stdout")
            else None,
            "error": result.get("error"),
        }

    except Exception as e:
        logger.error(f"Error in ffuf_param_fuzz: {e}")
        return {
            "tool": "ffuf",
            "mode": "param_fuzz",
            "status": "failure",
            "error": str(e),
            "findings": [],
        }


# =============================================================================
# Gobuster Functions
# =============================================================================


def gobuster_dns_enum(
    domain: str,
    wordlist: Optional[str] = None,
    threads: int = 50,
    dns_server: Optional[str] = None,
    timeout: int = 5,
) -> dict:
    """
    Enumerate subdomains using Gobuster DNS mode.

    Args:
        domain: Target domain (e.g., 'futurevera.thm')
        wordlist: Path to subdomain wordlist (uses DNS-optimized default if None)
        threads: Number of concurrent threads
        dns_server: Specific DNS server to use (often target IP in CTFs)
        timeout: DNS query timeout in seconds

    Returns:
        Dict with parsed findings, including list of discovered subdomains
    """
    try:
        gobuster = GobusterTool()
        if not gobuster.executable_path:
            return {
                "tool": "gobuster",
                "mode": "dns_enum",
                "status": "failure",
                "error": "Gobuster executable not found",
                "findings": [],
            }

        # Execute the scan
        result = gobuster.execute(
            mode="dns",
            domain=domain,
            wordlist=wordlist,
            threads=threads,
            dns_server=dns_server,
            timeout=f"{timeout}s",
        )

        # Parse and structure the response
        findings = []
        if result.get("status") == "success" and "findings" in result:
            subdomains = result["findings"].get("subdomains", [])
            findings = [
                subdomain["subdomain"]
                for subdomain in subdomains
                if "subdomain" in subdomain
            ]

        return {
            "tool": "gobuster",
            "mode": "dns_enum",
            "status": result.get("status", "unknown"),
            "findings": findings,
            "scan_summary": result.get("scan_summary", ""),
            "raw_output": result.get("raw_stdout", "")[:1000]
            if result.get("raw_stdout")
            else None,
            "error": result.get("error"),
        }

    except Exception as e:
        logger.error(f"Error in gobuster_dns_enum: {e}")
        return {
            "tool": "gobuster",
            "mode": "dns_enum",
            "status": "failure",
            "error": str(e),
            "findings": [],
        }


def gobuster_dir_enum(
    url: str,
    wordlist: Optional[str] = None,
    extensions: Optional[list[str]] = None,
    threads: int = 50,
    status_codes: Optional[str] = None,
) -> dict:
    """
    Enumerate directories and files using Gobuster directory mode.

    Args:
        url: Target URL (e.g., 'https://10.10.10.10:443')
        wordlist: Path to directory wordlist (uses default if None)
        extensions: List of file extensions to test (e.g., ['php', 'txt'])
        threads: Number of concurrent threads
        status_codes: Comma-separated status codes to show (default: "200,201,204,301,302,307,401,403")

    Returns:
        Dict with parsed findings, including discovered directories and files
    """
    try:
        gobuster = GobusterTool()
        if not gobuster.executable_path:
            return {
                "tool": "gobuster",
                "mode": "dir_enum",
                "status": "failure",
                "error": "Gobuster executable not found",
                "findings": [],
            }

        # Parse URL to extract IP and port
        from urllib.parse import urlparse

        parsed = urlparse(url)
        target_ip = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # Execute the scan
        result = gobuster.execute(
            mode="dir",
            target_ip=target_ip,
            port=port,
            wordlist=wordlist,
            threads=threads,
            status_codes=status_codes,
            extensions=extensions,
        )

        # Parse and structure the response
        findings = []
        if result.get("status") == "success" and "findings" in result:
            directories = result["findings"].get("directories", [])
            findings = [
                {
                    "path": item.get("url", item.get("path", "")),
                    "status_code": item.get("status_code"),
                    "size": item.get("size"),
                }
                for item in directories
            ]

        return {
            "tool": "gobuster",
            "mode": "dir_enum",
            "status": result.get("status", "unknown"),
            "findings": findings,
            "scan_summary": result.get("scan_summary", ""),
            "raw_output": result.get("raw_stdout", "")[:1000]
            if result.get("raw_stdout")
            else None,
            "error": result.get("error"),
        }

    except Exception as e:
        logger.error(f"Error in gobuster_dir_enum: {e}")
        return {
            "tool": "gobuster",
            "mode": "dir_enum",
            "status": "failure",
            "error": str(e),
            "findings": [],
        }


def gobuster_vhost_enum(
    ip: str,
    domain: str,
    wordlist: Optional[str] = None,
    port: int = 80,
    threads: int = 50,
) -> dict:
    """
    Enumerate virtual hosts using Gobuster vhost mode.

    Args:
        ip: Target IP address
        domain: Base domain to test subdomains against
        wordlist: Path to subdomain wordlist (uses DNS-optimized default if None)
        port: Target port (default: 80)
        threads: Number of concurrent threads

    Returns:
        Dict with parsed findings, including discovered virtual hosts
    """
    try:
        gobuster = GobusterTool()
        if not gobuster.executable_path:
            return {
                "tool": "gobuster",
                "mode": "vhost_enum",
                "status": "failure",
                "error": "Gobuster executable not found",
                "findings": [],
            }

        # Execute the scan
        result = gobuster.execute(
            mode="vhost",
            target_ip=ip,
            domain=domain,
            port=port,
            wordlist=wordlist,
            threads=threads,
        )

        # Parse and structure the response
        findings = []
        if result.get("status") == "success" and "findings" in result:
            vhosts = result["findings"].get("vhosts", [])
            findings = [vhost.get("vhost", "") for vhost in vhosts if "vhost" in vhost]

        return {
            "tool": "gobuster",
            "mode": "vhost_enum",
            "status": result.get("status", "unknown"),
            "findings": findings,
            "scan_summary": result.get("scan_summary", ""),
            "raw_output": result.get("raw_stdout", "")[:1000]
            if result.get("raw_stdout")
            else None,
            "error": result.get("error"),
        }

    except Exception as e:
        logger.error(f"Error in gobuster_vhost_enum: {e}")
        return {
            "tool": "gobuster",
            "mode": "vhost_enum",
            "status": "failure",
            "error": str(e),
            "findings": [],
        }


# =============================================================================
# Nmap Functions
# =============================================================================


def nmap_scan(
    ip: str,
    ports: Optional[str] = None,
    top_ports: Optional[int] = 1000,  # Default to top 1000 TCP if ports is None
    scan_type: str = "SYN",  # Default to SYN scan
    service_detection: bool = False,
    os_detection: bool = False,
    run_scripts: Union[
        bool, list[str], None
    ] = None,  # None means no script-related flags by default
    timing_template: str = "T4",
    custom_arguments: Optional[str] = None,
    timeout_seconds: int = 300,  # Nmap's default is not fixed, but this is a reasonable timeout for LLM calls.
) -> dict:
    """
    Performs flexible Nmap scans. Specify scan type, ports, service/OS detection, scripts, and custom arguments.
    """
    try:
        nmap_tool = NmapTool()
        if not nmap_tool.executable_path:
            return {
                "tool": "nmap",
                "mode": "flexible_scan",
                "status": "failure",
                "error": "Nmap executable not found",
                "findings": {},
            }

        args_list = []

        # Scan type
        scan_type_map = {
            "SYN": "-sS",
            "TCP_Connect": "-sT",
            "UDP": "-sU",
            "Ping_Sweep": "-sn",  # Note: -sn disables port scanning, so many other options become moot.
            "Aggressive": "-A",  # Includes -sV, -O, -sC, --traceroute
        }
        if scan_type in scan_type_map:
            args_list.append(scan_type_map[scan_type])
        else:  # Fallback or if user provides direct Nmap scan type like -sX
            args_list.append(
                scan_type if scan_type.startswith("-s") else "-sS"
            )  # Default to SYN if invalid named type

        # Port specification
        if scan_type != "Ping_Sweep":  # Port scanning options are irrelevant for -sn
            if ports:
                args_list.extend(["-p", ports])
            elif top_ports is not None:  # Nmap's --top-ports
                args_list.extend(["--top-ports", str(top_ports)])
            # If neither ports nor top_ports is given, Nmap scans its default (top 1000 TCP or all for UDP if -sU)

        # Service and OS detection
        if service_detection and scan_type != "Ping_Sweep":
            args_list.append("-sV")
        if os_detection and scan_type != "Ping_Sweep":
            args_list.append("-O")

        # Script scanning
        if run_scripts is not None and scan_type != "Ping_Sweep":
            if isinstance(run_scripts, bool) and run_scripts:
                args_list.append("-sC")  # Default scripts
            elif isinstance(run_scripts, list) and run_scripts:
                args_list.extend(["--script", ",".join(run_scripts)])
            # If run_scripts is False, no script flags are added.

        # Timing template
        if timing_template in [f"T{i}" for i in range(6)]:
            args_list.append(f"-{timing_template}")
        else:
            args_list.append("-T4")  # Default to T4 if invalid

        # Custom arguments - ensure they are parsed safely
        if custom_arguments:
            import shlex

            try:
                # Split custom arguments and extend the list
                # This helps prevent injection if custom_arguments were mishandled,
                # though primary trust is on NmapTool's execution model.
                parsed_custom_args = shlex.split(custom_arguments)
                args_list.extend(parsed_custom_args)
            except Exception as e:
                logger.warning(
                    f"Could not parse custom_arguments string: '{custom_arguments}'. Error: {e}. Ignoring."
                )

        # Join arguments into a string for NmapTool
        nmap_args_str = " ".join(args_list)

        logger.debug(f"Constructed Nmap arguments: {nmap_args_str} for target {ip}")

        # Execute Nmap scan
        # NmapTool.execute itself adds -oX - and handles XML parsing.
        # The timeout here is for the subprocess.run call within NmapTool.run_command
        result = nmap_tool.execute(
            target=ip,
            arguments=nmap_args_str,
            # timeout=timeout_seconds # NmapTool's run_command has its own timeout, consider if this is needed here
        )

        # Structure the response
        # The 'findings' from NmapTool are already parsed from XML.
        return {
            "tool": "nmap",
            "mode": scan_type,  # Reflect the primary scan type used
            "status": result.get("status", "unknown"),
            "findings": result.get("findings", {}),
            "scan_summary": result.get(
                "scan_summary", f"Nmap {scan_type} scan for {ip} completed."
            ),
            "command_used": f"nmap {nmap_args_str} {ip} -oX -",  # Reconstruct approximate command for user display
            "raw_output": result.get("raw_stdout", "")[:2000]
            if result.get("raw_stdout")
            else None,  # Limit raw output
            "error": result.get("error"),
        }

    except Exception as e:
        logger.error(f"Error in nmap_scan function: {e}", exc_info=True)
        return {
            "tool": "nmap",
            "mode": "flexible_scan",
            "status": "failure",
            "error": str(e),
            "findings": {},
        }


# =============================================================================
# Nikto Functions
# =============================================================================


def nikto_scan(
    ip_or_url: str, port: Optional[int] = None, ssl: Optional[bool] = None
) -> dict:
    """
    Perform a Nikto web server vulnerability scan.

    Args:
        ip_or_url: Target IP address or URL
        port: Target port (auto-detected from URL if not provided)
        ssl: Use SSL/TLS (auto-detected if not provided)

    Returns:
        Dict with vulnerability scan results
    """
    try:
        nikto_tool = NiktoTool()
        if not nikto_tool.executable_path:
            return {
                "tool": "nikto",
                "mode": "vulnerability_scan",
                "status": "failure",
                "error": "Nikto executable not found",
                "findings": [],
            }

        # If it looks like a URL, parse it
        if ip_or_url.startswith(("http://", "https://")):
            from urllib.parse import urlparse

            parsed = urlparse(ip_or_url)
            target = parsed.hostname
            port = port or parsed.port or (443 if parsed.scheme == "https" else 80)
            ssl = ssl if ssl is not None else (parsed.scheme == "https")
        else:
            target = ip_or_url
            port = port or 80
            ssl = ssl if ssl is not None else (port in [443, 8443])

        # Execute Nikto scan
        result = nikto_tool.execute(
            target=target, port=port, nikto_arguments="-ssl" if ssl else ""
        )

        # Parse and structure the response
        findings = []
        if result.get("status") == "success" and "findings" in result:
            vulnerabilities = result["findings"].get("vulnerabilities", [])
            findings = [
                {
                    "id": vuln.get("id", ""),
                    "method": vuln.get("method", ""),
                    "uri": vuln.get("uri", ""),
                    "description": vuln.get("description", ""),
                }
                for vuln in vulnerabilities
            ]

        return {
            "tool": "nikto",
            "mode": "vulnerability_scan",
            "status": result.get("status", "unknown"),
            "findings": findings,
            "scan_summary": result.get("scan_summary", ""),
            "raw_output": result.get("raw_stdout", "")[:1000]
            if result.get("raw_stdout")
            else None,
            "error": result.get("error"),
        }

    except Exception as e:
        logger.error(f"Error in nikto_scan: {e}")
        return {
            "tool": "nikto",
            "mode": "vulnerability_scan",
            "status": "failure",
            "error": str(e),
            "findings": [],
        }


# =============================================================================
# Function Registry for LLM Integration
# =============================================================================

LLM_TOOL_FUNCTIONS = {
    # FFUF functions (placeholder until implemented)
    "ffuf_vhost_enum": {
        "function": ffuf_vhost_enum,
        "description": "Enumerate virtual hosts via Host header fuzzing on target IP.",
        "parameters": {
            "ip": {
                "type": "string",
                "description": "Target IP address (must be a numeric IP, e.g., 10.10.10.10, not a domain name)",
            },
            "domain": {
                "type": "string",
                "description": "Base domain to test subdomains against",
            },
            "wordlist": {
                "type": "string",
                "description": "Path to subdomain wordlist (optional)",
                "default": "src/alienrecon/wordlists/dns-fast-clean.txt",
            },
            "threads": {
                "type": "integer",
                "description": "Number of concurrent threads",
                "default": 40,
            },
            "filter_size": {
                "type": "integer",
                "description": "Filter out responses of this size (optional)",
            },
            "timeout": {
                "type": "integer",
                "description": "Request timeout in seconds",
                "default": 10,
            },
            "port": {"type": "integer", "description": "Target port", "default": 443},
        },
        "required": ["ip", "domain"],
    },
    "ffuf_dir_enum": {
        "function": ffuf_dir_enum,
        "description": "Enumerate directories and files on a web server.",
        "parameters": {
            "url": {"type": "string", "description": "Target URL"},
            "wordlist": {
                "type": "string",
                "description": "Path to directory wordlist (defaults to system-configured wordlist)",
                "default": DEFAULT_WORDLIST,
            },
            "extensions": {
                "type": "array",
                "description": "List of file extensions to test (optional)",
                "items": {"type": "string"},
            },
            "match_codes": {
                "type": "array",
                "description": "HTTP status codes to include (optional)",
                "items": {"type": "integer"},
            },
            "filter_size": {
                "type": "integer",
                "description": "Filter out responses of this size (optional)",
            },
            "threads": {
                "type": "integer",
                "description": "Number of concurrent threads",
                "default": 40,
            },
        },
        "required": ["url"],
    },
    # Gobuster functions
    "gobuster_dns_enum": {
        "function": gobuster_dns_enum,
        "description": "Enumerate subdomains using Gobuster DNS mode.",
        "parameters": {
            "domain": {"type": "string", "description": "Target domain"},
            "wordlist": {
                "type": "string",
                "description": "Path to subdomain wordlist (optional)",
            },
            "threads": {
                "type": "integer",
                "description": "Number of concurrent threads",
                "default": 50,
            },
            "dns_server": {
                "type": "string",
                "description": "Specific DNS server to use (optional)",
            },
            "timeout": {
                "type": "integer",
                "description": "DNS query timeout in seconds",
                "default": 5,
            },
        },
        "required": ["domain"],
    },
    "gobuster_dir_enum": {
        "function": gobuster_dir_enum,
        "description": "Enumerate directories and files using Gobuster.",
        "parameters": {
            "url": {"type": "string", "description": "Target URL"},
            "wordlist": {
                "type": "string",
                "description": "Path to directory wordlist (optional)",
            },
            "extensions": {
                "type": "array",
                "description": "List of file extensions to test (optional)",
                "items": {"type": "string"},
            },
            "threads": {
                "type": "integer",
                "description": "Number of concurrent threads",
                "default": 50,
            },
            "status_codes": {
                "type": "string",
                "description": "Comma-separated status codes to show (optional)",
            },
        },
        "required": ["url"],
    },
    "gobuster_vhost_enum": {
        "function": gobuster_vhost_enum,
        "description": "Enumerate virtual hosts using Gobuster vhost mode.",
        "parameters": {
            "ip": {
                "type": "string",
                "description": "Target IP address (must be a numeric IP, e.g., 10.10.10.10, not a domain name)",
            },
            "domain": {
                "type": "string",
                "description": "Base domain to test subdomains against",
            },
            "wordlist": {
                "type": "string",
                "description": "Path to subdomain wordlist (optional)",
                "default": "src/alienrecon/wordlists/dns-fast-clean.txt",
            },
            "port": {"type": "integer", "description": "Target port", "default": 443},
            "threads": {
                "type": "integer",
                "description": "Number of concurrent threads",
                "default": 50,
            },
        },
        "required": ["ip", "domain"],
    },
    # Nmap functions (REPLACED)
    "nmap_scan": {
        "function": nmap_scan,
        "description": "Performs flexible Nmap scans. Specify scan type, ports, service/OS detection, scripts, and custom arguments.",
        "parameters": {
            "ip": {
                "type": "string",
                "description": "Target IP address (must be a numeric IP, e.g., 10.10.10.10, not a domain name)",
            },
            "ports": {
                "type": "string",
                "description": "Ports to scan (e.g., '22,80,443', '1-1000', 'U:53'). Default: Nmap top 1000 TCP if 'top_ports' is also unset.",
                "optional": True,
            },
            "top_ports": {
                "type": "integer",
                "description": "Scan the top N most common ports (e.g., 100, 1000). Overrides 'ports' if both are set.",
                "default": 1000,
                "optional": True,
            },
            "scan_type": {
                "type": "string",
                "description": "Type of Nmap scan.",
                "enum": ["SYN", "TCP_Connect", "UDP", "Ping_Sweep", "Aggressive"],
                "default": "SYN",
            },
            "service_detection": {
                "type": "boolean",
                "description": "Enable service and version detection (-sV).",
                "default": False,
                "optional": True,
            },
            "os_detection": {
                "type": "boolean",
                "description": "Enable OS detection (-O). May require privileges.",
                "default": False,
                "optional": True,
            },
            "run_scripts": {
                "type": "object",  # Representing a Union: boolean OR array of strings
                # The actual Python function will handle the Union type.
                # For schema, one common way is to describe it as object and detail in description,
                # or use anyOf if supported and clear. For simplicity here, 'object' with good description.
                "description": "Enable default scripts (-sC if true), or provide a list of script names/categories (e.g., ['vuln', 'http-title']). Set to false or omit to disable.",
                "properties": {  # This is a common way to hint at union structure for some LLMs
                    "use_default_scripts": {
                        "type": "boolean",
                        "description": "Set to true for -sC.",
                    },
                    "specific_scripts": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "e.g., ['smb-os-discovery', 'http-enum']",
                    },
                },
                "optional": True,  # Default is effectively None/False (no script flags added)
            },
            "timing_template": {
                "type": "string",
                "description": "Nmap timing template (T0-T5).",
                "enum": ["T0", "T1", "T2", "T3", "T4", "T5"],
                "default": "T4",
            },
            "custom_arguments": {
                "type": "string",
                "description": "Any additional Nmap arguments (e.g., '--reason -Pn'). Use with caution.",
                "optional": True,
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Timeout for the Nmap command execution in seconds.",
                "default": 300,
                "optional": True,
            },
        },
        "required": ["ip"],
    },
    # Nikto functions
    "nikto_scan": {
        "function": nikto_scan,
        "description": "Perform a Nikto web server vulnerability scan.",
        "parameters": {
            "ip_or_url": {"type": "string", "description": "Target IP address or URL"},
            "port": {"type": "integer", "description": "Target port (optional)"},
            "ssl": {"type": "boolean", "description": "Use SSL/TLS (optional)"},
        },
        "required": ["ip_or_url"],
    },
}
