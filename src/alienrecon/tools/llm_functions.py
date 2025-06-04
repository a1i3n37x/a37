"""
LLM-Aware Tool Functions

This module provides dedicated, purpose-built functions for each tool's specific use cases.
Each function has clear parameters, guardrails, and returns structured, parsed data.

These functions are designed to be directly callable by LLMs with proper parameter validation
and intelligent defaults.
"""

import logging
import os
from typing import Optional, Union

from ..core.cache import cache_result
from ..core.config import DEFAULT_WORDLIST
from .ffuf import FFUFTool
from .http_ssl_probe import HTTPSSLProbeTool
from .nikto import NiktoTool
from .nmap import NmapTool
from .ssl_inspector import SSLInspectorTool

logger = logging.getLogger(__name__)

# Determine default common wordlist (common.txt) alongside DEFAULT_WORDLIST
DEFAULT_COMMON_WORDLIST = os.path.join(
    os.path.dirname(DEFAULT_WORDLIST) if DEFAULT_WORDLIST else "", "common.txt"
)

# =============================================================================
# FFUF Functions (To be implemented when FFUF tool is created)
# =============================================================================


@cache_result(ttl=3600)  # 1 hour cache for vhost enumeration
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


@cache_result(ttl=1800)  # 30 minute cache for directory enumeration
def ffuf_dir_enum(
    url: str,
    wordlist: Optional[str] = DEFAULT_COMMON_WORDLIST,
    extensions: Optional[list[str]] = None,
    match_codes: Optional[list[int]] = None,
    filter_size: Optional[int] = None,
    threads: int = 40,
) -> dict:
    """
    Enumerate directories and files on a web server.

    Args:
        url: Target URL (e.g., 'https://10.10.10.10')
        wordlist: Path to directory wordlist (defaults to common.txt if present, else system default)
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
# Nmap Functions
# =============================================================================


@cache_result(
    ttl=3600, ignore_params=["timeout_seconds"]
)  # 1 hour cache for nmap, ignore timeout param
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


@cache_result(ttl=3600)  # 1 hour cache for nikto vulnerability scans
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
# SSL Certificate Inspection Functions
# =============================================================================


@cache_result(ttl=3600)  # 1 hour cache for SSL certificate inspection
def inspect_ssl_certificate(
    ip: str,
    port: int = 443,
    hostname_for_sni: Optional[str] = None,
    timeout: int = 30,
) -> dict:
    """
    Inspect SSL certificate to extract certificate details like CN and SANs.

    This function is particularly useful for discovering virtual host names from
    certificate Common Name (CN) and Subject Alternative Names (SANs), especially
    in CTF scenarios where certificate errors or mismatches reveal target hostnames.

    Args:
        ip: Target IP address (must be a numeric IP, e.g., 10.10.10.10)
        port: Target port (default: 443)
        hostname_for_sni: Hostname to use for SNI (Server Name Indication), useful when you suspect a specific hostname
        timeout: Connection timeout in seconds

    Returns:
        Dict with certificate details including CN, SANs, issuer, and validity information
    """
    try:
        ssl_inspector = SSLInspectorTool()
        if not ssl_inspector.executable_path:
            return {
                "tool": "ssl_inspector",
                "mode": "certificate_inspection",
                "status": "failure",
                "error": "OpenSSL executable not found",
                "findings": [],
            }

        # Execute the SSL certificate inspection
        result = ssl_inspector.execute(
            ip=ip,
            port=port,
            hostname_for_sni=hostname_for_sni,
            timeout=timeout,
        )

        # Parse and structure the response
        findings = {}
        if result.get("status") in ["success", "partial"] and "findings" in result:
            if "certificate" in result["findings"]:
                cert_info = result["findings"]["certificate"]
                findings = {
                    "common_name": cert_info.get("common_name"),
                    "subject_alt_names": cert_info.get("subject_alt_names", []),
                    "issuer": cert_info.get("issuer"),
                    "not_before": cert_info.get("not_before"),
                    "not_after": cert_info.get("not_after"),
                    "serial_number": cert_info.get("serial_number"),
                }
            elif "error_details" in result["findings"]:
                # Include error details that might be informative for CTF scenarios
                findings = {"error_details": result["findings"]["error_details"]}

        return {
            "tool": "ssl_inspector",
            "mode": "certificate_inspection",
            "status": result.get("status", "unknown"),
            "findings": findings,
            "scan_summary": result.get("scan_summary", ""),
            "raw_output": result.get("raw_stdout", "")[:1000]
            if result.get("raw_stdout")
            else None,
            "error": result.get("error"),
        }

    except Exception as e:
        logger.error(f"Error in inspect_ssl_certificate: {e}")
        return {
            "tool": "ssl_inspector",
            "mode": "certificate_inspection",
            "status": "failure",
            "error": str(e),
            "findings": {},
        }


@cache_result(ttl=1800)  # 30 minute cache for HTTP SSL probes
def probe_ssl_errors(
    url: str,
    timeout: int = 10,
    follow_redirects: bool = False,
    user_agent: str = "Mozilla/5.0 (compatible; ssl-probe)",
) -> dict:
    """
    Probe HTTPS connections to capture SSL certificate errors that might reveal correct hostnames.
    This function mimics what gobuster dir does when it encounters SSL certificate errors.

    Particularly useful in CTF scenarios where connecting to an incorrect hostname
    reveals the correct hostname via certificate verification errors.

    Args:
        url: Target URL (e.g., 'https://support.futurevera.thm')
        timeout: Connection timeout in seconds
        follow_redirects: Whether to follow HTTP redirects
        user_agent: User agent string for the request

    Returns:
        Dict with parsed SSL error information and any revealed hostnames
    """
    try:
        probe = HTTPSSLProbeTool()
        if not probe.executable_path:
            return {
                "tool": "http_ssl_probe",
                "mode": "ssl_error_capture",
                "status": "failure",
                "error": "curl executable not found",
                "findings": {},
            }

        # Execute the probe
        result = probe.execute(
            url=url,
            timeout=timeout,
            follow_redirects=follow_redirects,
            user_agent=user_agent,
        )

        # Parse and structure the response for CTF scenarios
        findings = result.get("findings", {})

        # Extract key information that might reveal hostnames
        ssl_errors = findings.get("ssl_errors", {})
        revealed_hostnames = ssl_errors.get("revealed_hostnames", [])
        hostname_mismatch = ssl_errors.get("hostname_mismatch")
        cert_verification_error = ssl_errors.get("certificate_verification_error")

        # Structure the findings for easy consumption
        structured_findings = {
            "ssl_connection_successful": "ssl_handshake" in findings,
            "http_response_received": "http_response" in findings,
        }

        if ssl_errors:
            structured_findings["ssl_error_details"] = ssl_errors

        if revealed_hostnames:
            structured_findings["revealed_hostnames"] = revealed_hostnames

        if hostname_mismatch:
            structured_findings["hostname_mismatch"] = hostname_mismatch

        if cert_verification_error:
            structured_findings["certificate_error"] = cert_verification_error

        return {
            "tool": "http_ssl_probe",
            "mode": "ssl_error_capture",
            "status": result.get("status", "unknown"),
            "findings": structured_findings,
            "scan_summary": result.get("scan_summary", ""),
            "raw_stderr": result.get("raw_stderr", "")[:500]
            if result.get("raw_stderr")
            else None,
            "error": result.get("error"),
        }

    except Exception as e:
        logger.error(f"Error in probe_ssl_errors: {e}")
        return {
            "tool": "http_ssl_probe",
            "mode": "ssl_error_capture",
            "status": "failure",
            "error": str(e),
            "findings": {},
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
                "description": "Path to directory wordlist (defaults to common.txt if present, else system default)",
                "default": DEFAULT_COMMON_WORDLIST,
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
    # SSL Certificate Inspection functions
    "inspect_ssl_certificate": {
        "function": inspect_ssl_certificate,
        "description": "Inspect SSL certificate to extract certificate details like CN and SANs. Particularly useful for discovering virtual host names from certificate information, especially in CTF scenarios where certificate errors or mismatches reveal target hostnames.",
        "parameters": {
            "ip": {
                "type": "string",
                "description": "Target IP address (must be a numeric IP, e.g., 10.10.10.10)",
            },
            "port": {
                "type": "integer",
                "description": "Target port",
                "default": 443,
            },
            "hostname_for_sni": {
                "type": "string",
                "description": "Hostname to use for SNI (Server Name Indication), useful when you suspect a specific hostname",
                "optional": True,
            },
            "timeout": {
                "type": "integer",
                "description": "Connection timeout in seconds",
                "default": 30,
            },
        },
        "required": ["ip"],
    },
    # HTTP SSL Probe functions
    "probe_ssl_errors": {
        "function": probe_ssl_errors,
        "description": "Probe HTTPS connections to capture SSL certificate errors that might reveal correct hostnames. Mimics gobuster dir behavior when SSL certificate errors occur. Particularly useful in CTF scenarios where connecting to an incorrect hostname reveals the correct hostname via certificate verification errors.",
        "parameters": {
            "url": {
                "type": "string",
                "description": "Target URL (e.g., 'https://support.futurevera.thm')",
            },
            "timeout": {
                "type": "integer",
                "description": "Connection timeout in seconds",
                "default": 10,
            },
            "follow_redirects": {
                "type": "boolean",
                "description": "Whether to follow HTTP redirects",
                "default": False,
            },
            "user_agent": {
                "type": "string",
                "description": "User agent string for the request",
                "default": "Mozilla/5.0 (compatible; ssl-probe)",
            },
        },
        "required": ["url"],
    },
}
