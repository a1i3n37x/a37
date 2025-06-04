"""
SSL Certificate Inspector Tool Wrapper

This module provides a tool wrapper for SSL certificate inspection using openssl s_client.
It's designed to extract certificate details like Common Name (CN) and Subject Alternative Names (SANs)
which are particularly useful for discovering virtual host names in CTF scenarios.
"""

import logging
import re
from typing import Optional

from ..core.types import ToolResult
from .base import CommandTool

logger = logging.getLogger(__name__)


class SSLInspectorTool(CommandTool):
    """
    Tool wrapper for executing SSL certificate inspection using openssl s_client.
    """

    name: str = "ssl_inspector"
    description: str = "Inspects SSL certificates to extract certificate details like CN and SANs, useful for discovering virtual hosts."
    executable_name: str = "openssl"

    def build_command(
        self,
        ip: str,
        port: int = 443,
        hostname_for_sni: Optional[str] = None,
        timeout: int = 10,
        **kwargs,
    ) -> list[str]:
        """
        Constructs the openssl s_client command arguments.

        Args:
            ip: Target IP address or hostname
            port: Target port (default: 443)
            hostname_for_sni: Hostname to use for SNI (Server Name Indication)
            timeout: Connection timeout in seconds
            **kwargs: Additional arguments

        Returns:
            List of command arguments for openssl s_client

        Raises:
            ValueError: If required arguments are missing
        """
        if not ip:
            raise ValueError(
                "IP address or hostname must be provided for SSL certificate inspection."
            )

        # Base command arguments for openssl s_client
        command_args = [
            "s_client",
            "-connect",
            f"{ip}:{port}",
            "-timeout",
            "-showcerts",  # Critical for getting full certificate details including SANs
            "-servername",
            hostname_for_sni or ip,  # Use hostname for SNI if provided
            "-verify_return_error",  # This will help capture cert verification errors
        ]

        # Add timeout by sending EOF after connection (non-interactive)
        # We'll pipe an empty input to make it non-interactive
        logger.debug(f"Built openssl s_client command args: {command_args}")
        return command_args

    def parse_output(
        self, stdout: str | None, stderr: str | None, **kwargs
    ) -> ToolResult:
        """
        Parse openssl s_client output and extract certificate details.
        """
        ip = kwargs.get("ip", "Unknown IP")
        port = kwargs.get("port", 443)
        hostname_for_sni = kwargs.get("hostname_for_sni")
        target_context = f"{ip}:{port}"
        if hostname_for_sni and hostname_for_sni != ip:
            target_context += f" (SNI: {hostname_for_sni})"

        result: ToolResult = {
            "tool_name": self.name,
            "status": "success",
            "scan_summary": f"SSL certificate inspection for {target_context}",
            "findings": {},
        }

        # Combine stdout and stderr for analysis since openssl s_client outputs to both
        combined_output = ""
        if stdout:
            combined_output += stdout
        if stderr:
            combined_output += "\n" + stderr
            # Store stderr for diagnostic purposes
            result["raw_stderr"] = stderr[:2000]

        if not combined_output.strip():
            result["status"] = "failure"
            result["scan_summary"] = (
                f"SSL certificate inspection for {target_context} produced no output."
            )
            result["error"] = "No output received from openssl s_client."
            result["findings"] = {}
            return result

        try:
            # Extract certificate information
            cert_info = self._parse_certificate_info(combined_output)

            # Always try to extract error information for CTF scenarios
            error_info = self._extract_error_info(combined_output)

            if not cert_info and not error_info:
                result["status"] = "failure"
                result["scan_summary"] = (
                    f"SSL certificate inspection for {target_context} failed."
                )
                result["error"] = (
                    "Could not extract certificate information or meaningful error details."
                )
                result["findings"] = {}
                return result

            # Build findings based on what we found
            findings = {}
            if cert_info:
                findings["certificate"] = cert_info

            if error_info:
                findings["error_details"] = error_info

                # If we have error details but no cert info, it's a partial success
                if not cert_info:
                    result["status"] = "partial"
                    result["scan_summary"] = (
                        f"SSL connection to {target_context} failed, but extracted error information."
                    )
                    result["error"] = (
                        "SSL connection failed, but error details may be informative for CTF scenarios."
                    )

            result["findings"] = findings

            # Create a summary of findings
            if cert_info:
                cn = cert_info.get("common_name", "N/A")
                sans = cert_info.get("subject_alt_names", [])
                san_count = len(sans) if sans else 0

                result["scan_summary"] = (
                    f"SSL certificate for {target_context}: CN='{cn}', "
                    f"{san_count} Subject Alternative Name(s)"
                )

                if sans:
                    result["scan_summary"] += (
                        f" (SANs: {', '.join(sans[:3])}{'...' if len(sans) > 3 else ''})"
                    )

            # Add error information to summary if present
            if error_info:
                error_summary = []
                if error_info.get("verification_error"):
                    error_summary.append(
                        f"Verification: {error_info['verification_error']}"
                    )
                if error_info.get("expected_hostname"):
                    error_summary.append(f"Expected: {error_info['expected_hostname']}")
                if error_info.get("certificate_subject_in_error"):
                    error_summary.append(
                        f"Cert Subject: {error_info['certificate_subject_in_error']}"
                    )

                if error_summary:
                    if cert_info:
                        result["scan_summary"] += (
                            f" | Errors: {'; '.join(error_summary)}"
                        )
                    else:
                        result["scan_summary"] = (
                            f"SSL errors for {target_context}: {'; '.join(error_summary)}"
                        )

            return result

        except Exception as e:
            logger.error(f"Error parsing SSL certificate output: {e}")
            result["status"] = "failure"
            result["error"] = f"Error parsing SSL certificate output: {str(e)}"
            result["findings"] = {}
            # Include raw output for debugging
            result["raw_stdout"] = stdout[:1000] if stdout else None
            return result

    def _parse_certificate_info(self, output: str) -> dict:
        """
        Extract certificate information from openssl s_client output.
        Enhanced to use the same parsing approach as our successful test script.

        Returns:
            Dictionary containing certificate details
        """
        cert_info = {}

        # Method 1: Parse from the raw s_client output (works for basic info)
        # Extract Common Name (CN) from subject line
        cn_match = re.search(
            r"subject=.*?CN\s*=\s*([^,\n]+)", output, re.IGNORECASE | re.MULTILINE
        )
        if cn_match:
            cert_info["common_name"] = cn_match.group(1).strip()

        # Method 2: If we have the full certificate in PEM format, parse it properly
        # This is the approach that worked in our test script
        cert_start = output.find("-----BEGIN CERTIFICATE-----")
        cert_end = output.find("-----END CERTIFICATE-----")

        if cert_start != -1 and cert_end != -1:
            # Extract the PEM certificate
            cert_pem = output[cert_start : cert_end + len("-----END CERTIFICATE-----")]

            # Parse certificate details using openssl x509 (like our test script)
            try:
                import subprocess

                cert_result = subprocess.run(
                    ["openssl", "x509", "-noout", "-text"],
                    input=cert_pem,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                if cert_result.returncode == 0:
                    cert_details = cert_result.stdout

                    # Extract Subject CN from parsed certificate
                    subject_match = re.search(
                        r"Subject:.*?CN\s*=\s*([^,\n]+)", cert_details, re.IGNORECASE
                    )
                    if subject_match and not cert_info.get("common_name"):
                        cert_info["common_name"] = subject_match.group(1).strip()

                    # Extract Subject Alternative Names from parsed certificate
                    san_section = re.search(
                        r"X509v3 Subject Alternative Name:\s*\n\s*(.+?)(?:\n\s*X509v3|\n\s*\w|\Z)",
                        cert_details,
                        re.IGNORECASE | re.DOTALL,
                    )

                    if san_section:
                        san_text = san_section.group(1)
                        # Extract DNS names from SAN
                        dns_names = re.findall(r"DNS:([^,\s\n]+)", san_text)
                        if dns_names:
                            cert_info["subject_alt_names"] = [
                                name.strip() for name in dns_names
                            ]

                        # Extract IP addresses from SAN
                        ip_addresses = re.findall(r"IP Address:([^,\s\n]+)", san_text)
                        if ip_addresses:
                            if "subject_alt_names" not in cert_info:
                                cert_info["subject_alt_names"] = []
                            cert_info["subject_alt_names"].extend(
                                [f"IP:{ip.strip()}" for ip in ip_addresses]
                            )

            except Exception as parse_error:
                # Fall back to original parsing method if detailed parsing fails
                logger.debug(
                    f"Detailed certificate parsing failed, using fallback: {parse_error}"
                )

                # Fallback: Look for X509v3 Subject Alternative Name section in raw output
                san_section_match = re.search(
                    r"X509v3 Subject Alternative Name:\s*\n\s*(.+?)(?:\n\s*X509v3|\n\s*$|\nDepth:)",
                    output,
                    re.IGNORECASE | re.MULTILINE | re.DOTALL,
                )

                if san_section_match:
                    san_text = san_section_match.group(1)
                    # Extract DNS names from SAN
                    dns_names = re.findall(r"DNS:([^,\s\n]+)", san_text)
                    if dns_names:
                        cert_info["subject_alt_names"] = [
                            name.strip() for name in dns_names
                        ]

                    # Extract IP addresses from SAN
                    ip_addresses = re.findall(r"IP Address:([^,\s\n]+)", san_text)
                    if ip_addresses:
                        if "subject_alt_names" not in cert_info:
                            cert_info["subject_alt_names"] = []
                        cert_info["subject_alt_names"].extend(
                            [f"IP:{ip.strip()}" for ip in ip_addresses]
                        )

        # Extract Issuer
        issuer_match = re.search(
            r"issuer=(.+?)(?:\n|$)", output, re.IGNORECASE | re.MULTILINE
        )
        if issuer_match:
            cert_info["issuer"] = issuer_match.group(1).strip()

        # Extract validity dates
        not_before_match = re.search(r"notBefore=(.+?)(?:\n|$)", output, re.IGNORECASE)
        if not_before_match:
            cert_info["not_before"] = not_before_match.group(1).strip()

        not_after_match = re.search(r"notAfter=(.+?)(?:\n|$)", output, re.IGNORECASE)
        if not_after_match:
            cert_info["not_after"] = not_after_match.group(1).strip()

        # Extract serial number
        serial_match = re.search(r"serial=([A-Fa-f0-9:]+)", output, re.IGNORECASE)
        if serial_match:
            cert_info["serial_number"] = serial_match.group(1).strip()

        return cert_info

    def _extract_error_info(self, output: str) -> dict:
        """
        Extract useful error information from failed SSL connections.
        This can be valuable for CTF scenarios where certificate errors reveal information.
        Enhanced to capture more certificate-related errors that gobuster might encounter.
        """
        error_info = {}

        # Look for verification errors that might reveal hostnames
        verify_error_patterns = [
            r"verify error:num=\d+:(.+?)(?:\n|$)",
            r"Verification error: (.+?)(?:\n|$)",
            r"certificate verify failed: (.+?)(?:\n|$)",
        ]

        for pattern in verify_error_patterns:
            verify_error_match = re.search(pattern, output, re.IGNORECASE)
            if verify_error_match:
                error_info["verification_error"] = verify_error_match.group(1).strip()
                break

        # Look for hostname mismatch errors (multiple patterns)
        hostname_mismatch_patterns = [
            r"hostname mismatch.*?expected\s*[:=]\s*([^\s,\n]+)",
            r"does not match target hostname\s*[:=]?\s*([^\s,\n]+)",
            r"certificate is not valid for\s*[:=]?\s*([^\s,\n]+)",
            r"subject\s+does\s+not\s+match\s+target\s+hostname\s*[:=]?\s*([^\s,\n]+)",
        ]

        for pattern in hostname_mismatch_patterns:
            hostname_mismatch = re.search(pattern, output, re.IGNORECASE)
            if hostname_mismatch:
                error_info["expected_hostname"] = hostname_mismatch.group(1).strip()
                break

        # Look for certificate subject in error context (enhanced patterns)
        subject_patterns = [
            r"certificate.*?subject.*?[:=]\s*([^\n]+)",
            r"subject.*?[:=]\s*([^\n,]+)",
            r"Certificate subject:\s*(.+?)(?:\n|$)",
        ]

        for pattern in subject_patterns:
            if "certificate" in output.lower() and "subject" in output.lower():
                subject_in_error = re.search(pattern, output, re.IGNORECASE)
                if subject_in_error:
                    error_info["certificate_subject_in_error"] = subject_in_error.group(
                        1
                    ).strip()
                    break

        # Capture connection errors that might be informative
        connect_error_patterns = [
            r"connect:errno=\d+",
            r"Connection refused",
            r"timeout",
            r"No route to host",
            r"Name or service not known",
            r"SSL_connect:(.+?)(?:\n|$)",
        ]

        for pattern in connect_error_patterns:
            connect_error_match = re.search(pattern, output, re.IGNORECASE)
            if connect_error_match:
                error_info["connection_error"] = connect_error_match.group(0).strip()
                break

        # Look for certificate chain issues (common in CTF scenarios)
        chain_error_patterns = [
            r"unable to get local issuer certificate",
            r"self signed certificate",
            r"certificate chain too long",
            r"unable to verify the first certificate",
        ]

        for pattern in chain_error_patterns:
            chain_error_match = re.search(pattern, output, re.IGNORECASE)
            if chain_error_match:
                error_info["chain_error"] = chain_error_match.group(0).strip()
                break

        # Extract any certificate details that appear in error messages
        # This is particularly useful when the connection fails but cert details leak through
        cert_details_in_errors = re.findall(
            r"CN\s*=\s*([^,\s\n]+)", output, re.IGNORECASE
        )
        if cert_details_in_errors:
            error_info["certificate_cn_in_errors"] = cert_details_in_errors

        return error_info

    def execute(self, **kwargs) -> ToolResult:
        """
        Override execute to handle the special case of piping empty input to openssl s_client
        to make it non-interactive.
        """
        if not self.executable_path:
            err_msg = (
                f"Tool '{self.name}' ({self.executable_name}) cannot be "
                f"executed because its executable path was not found or is invalid. "
                f"Please ensure '{self.executable_name}' is installed correctly and accessible."
            )
            logger.error(err_msg)
            return {
                "tool_name": self.name,
                "status": "failure",
                "scan_summary": f"{self.name.capitalize()} execution failed: Tool not found.",
                "error": err_msg,
                "findings": {},
            }

        try:
            command_args = self.build_command(**kwargs)
            command = [self.executable_path] + command_args

            # Use a custom execution that pipes empty input to openssl s_client
            import subprocess

            logger.debug(f"Executing SSL inspection command: {' '.join(command)}")

            try:
                # Run openssl s_client with empty input to make it non-interactive
                result = subprocess.run(
                    command,
                    input="",  # Empty input to make it exit after handshake
                    capture_output=True,
                    text=True,
                    timeout=kwargs.get("timeout", 30),
                )
                stdout = result.stdout
                stderr = result.stderr

                # For openssl s_client, non-zero exit codes are common even for successful cert retrieval
                # So we don't treat non-zero exit codes as automatic failures

            except subprocess.TimeoutExpired:
                return {
                    "tool_name": self.name,
                    "status": "failure",
                    "scan_summary": f"SSL inspection timeout for {kwargs.get('ip', 'unknown')}",
                    "error": "SSL inspection timed out",
                    "findings": {},
                }
            except Exception as e:
                return {
                    "tool_name": self.name,
                    "status": "failure",
                    "scan_summary": f"SSL inspection error for {kwargs.get('ip', 'unknown')}",
                    "error": f"Execution error: {str(e)}",
                    "findings": {},
                }

        except Exception as e:
            err_msg = f"Error building command for {self.name}: {e}"
            logger.error(err_msg)
            return {
                "tool_name": self.name,
                "status": "failure",
                "scan_summary": f"{self.name.capitalize()} command build failed.",
                "error": err_msg,
                "findings": {},
            }

        # Parse the output
        try:
            parsed_results = self.parse_output(stdout, stderr, **kwargs)
            parsed_results.setdefault("tool_name", self.name)

            # Add raw output for debugging
            if stdout:
                parsed_results["raw_stdout"] = stdout[:2000]
            if stderr:
                parsed_results["raw_stderr"] = stderr[:2000]

            return parsed_results

        except Exception as e:
            err_msg = f"Error parsing SSL inspection output: {e}"
            logger.error(err_msg, exc_info=True)
            return {
                "tool_name": self.name,
                "status": "failure",
                "scan_summary": f"{self.name.capitalize()} output parsing failed.",
                "error": err_msg,
                "raw_stdout": stdout[:500] if stdout else None,
                "raw_stderr": stderr[:500] if stderr else None,
                "findings": {},
            }
