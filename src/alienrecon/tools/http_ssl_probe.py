"""
HTTP SSL Probe Tool

This tool mimics what gobuster dir does when it encounters SSL certificate errors.
It attempts HTTP/HTTPS connections to specific hostnames and captures certificate
errors that might reveal the correct hostname for a service.
"""

import logging
import re
from urllib.parse import urlparse

from ..core.types import ToolResult
from .base import CommandTool

logger = logging.getLogger(__name__)


class HTTPSSLProbeTool(CommandTool):
    """
    Tool wrapper for probing HTTPS connections and capturing SSL certificate errors
    that might reveal correct hostnames (like gobuster dir behavior).
    """

    name: str = "http_ssl_probe"
    description: str = "Probes HTTPS connections to capture SSL certificate errors that might reveal correct hostnames, similar to gobuster dir behavior."
    executable_name: str = "curl"

    def build_command(
        self,
        url: str,
        timeout: int = 10,
        follow_redirects: bool = False,
        user_agent: str = "Mozilla/5.0 (compatible; ssl-probe)",
        **kwargs,
    ) -> list[str]:
        """
        Constructs the curl command arguments for SSL probing.

        Args:
            url: Target URL (e.g., https://support.futurevera.thm)
            timeout: Connection timeout in seconds
            follow_redirects: Whether to follow HTTP redirects
            user_agent: User agent string
            **kwargs: Additional arguments

        Returns:
            List of command arguments for curl

        Raises:
            ValueError: If required arguments are missing
        """
        if not url:
            raise ValueError("URL must be provided for HTTP SSL probing.")

        # Parse URL to ensure it's properly formatted
        parsed = urlparse(url)
        if not parsed.scheme:
            url = f"https://{url}"

        # Base curl command arguments
        command_args = [
            "-v",  # Verbose output (includes SSL handshake details)
            "--max-time",
            str(timeout),
            "--user-agent",
            user_agent,
            "--connect-timeout",
            str(timeout),
        ]

        if follow_redirects:
            command_args.append("-L")

        # Add the target URL
        command_args.append(url)

        logger.debug(f"Built curl command args: {command_args}")
        return command_args

    def parse_output(
        self, stdout: str | None, stderr: str | None, **kwargs
    ) -> ToolResult:
        """
        Parse curl output and extract SSL certificate error information.
        """
        url = kwargs.get("url", "Unknown URL")

        result: ToolResult = {
            "tool_name": self.name,
            "status": "success",
            "scan_summary": f"HTTP SSL probe for {url}",
            "findings": {},
        }

        # curl outputs SSL handshake details to stderr
        combined_output = ""
        if stdout:
            combined_output += stdout
        if stderr:
            combined_output += "\n" + stderr
            # Store stderr for diagnostic purposes
            result["raw_stderr"] = stderr[:2000]

        if not combined_output.strip():
            result["status"] = "failure"
            result["scan_summary"] = f"HTTP SSL probe for {url} produced no output."
            result["error"] = "No output received from curl."
            result["findings"] = {}
            return result

        try:
            # Extract SSL/certificate information
            ssl_info = self._parse_ssl_handshake_info(combined_output)

            # Extract HTTP response information
            http_info = self._parse_http_response_info(combined_output)

            # Extract error information that might reveal hostnames
            error_info = self._extract_ssl_error_info(combined_output)

            if not ssl_info and not error_info and not http_info:
                result["status"] = "failure"
                result["scan_summary"] = f"HTTP SSL probe for {url} failed."
                result["error"] = "Could not extract SSL, HTTP, or error information."
                result["findings"] = {}
                return result

            # Build findings
            findings = {}
            if ssl_info:
                findings["ssl_handshake"] = ssl_info

            if http_info:
                findings["http_response"] = http_info

            if error_info:
                findings["ssl_errors"] = error_info

                # If we have error details but no successful connection, it's a partial success
                if not ssl_info:
                    result["status"] = "partial"
                    result["scan_summary"] = (
                        f"HTTP SSL probe to {url} failed, but extracted SSL error information."
                    )
                    result["error"] = (
                        "SSL connection failed, but error details may reveal correct hostname."
                    )

            result["findings"] = findings

            # Create a comprehensive summary
            summary_parts = []

            if ssl_info:
                cert_subject = ssl_info.get("certificate_subject", "Unknown")
                summary_parts.append(f"SSL cert: {cert_subject}")

            if http_info:
                status_code = http_info.get("status_code", "Unknown")
                summary_parts.append(f"HTTP {status_code}")

            if error_info:
                if error_info.get("certificate_verification_error"):
                    summary_parts.append(
                        f"Cert error: {error_info['certificate_verification_error']}"
                    )
                if error_info.get("hostname_mismatch"):
                    summary_parts.append(
                        f"Hostname mismatch: {error_info['hostname_mismatch']}"
                    )
                if error_info.get("revealed_hostnames"):
                    hostnames = ", ".join(error_info["revealed_hostnames"][:3])
                    summary_parts.append(f"Revealed hosts: {hostnames}")

            if summary_parts:
                result["scan_summary"] = (
                    f"HTTP SSL probe for {url}: {' | '.join(summary_parts)}"
                )

            return result

        except Exception as e:
            logger.error(f"Error parsing HTTP SSL probe output: {e}")
            result["status"] = "failure"
            result["error"] = f"Error parsing HTTP SSL probe output: {str(e)}"
            result["findings"] = {}
            # Include raw output for debugging
            result["raw_stdout"] = stdout[:1000] if stdout else None
            return result

    def _parse_ssl_handshake_info(self, output: str) -> dict:
        """
        Extract SSL handshake information from curl verbose output.
        """
        ssl_info = {}

        # Extract server certificate subject
        cert_subject_match = re.search(
            r"\*\s+server certificate.*?subject:\s*(.+?)(?:\n|$)",
            output,
            re.IGNORECASE | re.MULTILINE,
        )
        if cert_subject_match:
            ssl_info["certificate_subject"] = cert_subject_match.group(1).strip()

        # Extract server certificate issuer
        cert_issuer_match = re.search(
            r"\*\s+server certificate.*?issuer:\s*(.+?)(?:\n|$)",
            output,
            re.IGNORECASE | re.MULTILINE,
        )
        if cert_issuer_match:
            ssl_info["certificate_issuer"] = cert_issuer_match.group(1).strip()

        # Extract SSL version/cipher info
        ssl_established_match = re.search(
            r"\*\s+SSL connection using\s+(.+?)(?:\n|$)", output, re.IGNORECASE
        )
        if ssl_established_match:
            ssl_info["ssl_connection_details"] = ssl_established_match.group(1).strip()

        # Extract certificate dates
        cert_start_match = re.search(
            r"\*\s+start date:\s*(.+?)(?:\n|$)", output, re.IGNORECASE
        )
        if cert_start_match:
            ssl_info["certificate_start_date"] = cert_start_match.group(1).strip()

        cert_expire_match = re.search(
            r"\*\s+expire date:\s*(.+?)(?:\n|$)", output, re.IGNORECASE
        )
        if cert_expire_match:
            ssl_info["certificate_expire_date"] = cert_expire_match.group(1).strip()

        # Extract common name from subject if available
        if "certificate_subject" in ssl_info:
            cn_match = re.search(
                r"CN\s*=\s*([^,\n]+)", ssl_info["certificate_subject"], re.IGNORECASE
            )
            if cn_match:
                ssl_info["certificate_common_name"] = cn_match.group(1).strip()

        return ssl_info

    def _parse_http_response_info(self, output: str) -> dict:
        """
        Extract HTTP response information from curl output.
        """
        http_info = {}

        # Extract HTTP status code and message
        status_match = re.search(r"<\s*HTTP/[\d.]+\s+(\d+)\s*(.*)(?:\n|$)", output)
        if status_match:
            http_info["status_code"] = int(status_match.group(1))
            http_info["status_message"] = status_match.group(2).strip()

        # Extract interesting headers
        headers = {}
        header_lines = re.findall(r"<\s*([^:]+):\s*(.+?)(?:\n|$)", output)
        for header_name, header_value in header_lines:
            header_name = header_name.strip().lower()
            if header_name in ["server", "location", "www-authenticate", "set-cookie"]:
                headers[header_name] = header_value.strip()

        if headers:
            http_info["interesting_headers"] = headers

        return http_info

    def _extract_ssl_error_info(self, output: str) -> dict:
        """
        Extract SSL error information that might reveal correct hostnames.
        This is the key function for replicating gobuster dir's error-revealing behavior.
        """
        error_info = {}

        # Certificate verification errors
        cert_verify_patterns = [
            r"certificate verify failed:\s*(.+?)(?:\n|$)",
            r"SSL certificate problem:\s*(.+?)(?:\n|$)",
            r"server certificate verification failed:\s*(.+?)(?:\n|$)",
        ]

        for pattern in cert_verify_patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                error_info["certificate_verification_error"] = match.group(1).strip()
                break

        # Hostname mismatch errors (these often reveal the correct hostname)
        hostname_mismatch_patterns = [
            r"doesn't match requested host name\s*['\"]?([^'\"\\s,\n]+)",
            r"certificate subject name\s*['\"]?([^'\"\\s,\n]+)['\"]?\s*does not match target host name",
            r"hostname\s*['\"]?([^'\"\\s,\n]+)['\"]?\s*doesn't match certificate",
            r"certificate is not valid for\s*['\"]?([^'\"\\s,\n]+)",
        ]

        for pattern in hostname_mismatch_patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                error_info["hostname_mismatch"] = match.group(1).strip()
                break

        # Extract any hostnames/domains mentioned in certificate errors
        revealed_hostnames = set()

        # Look for DNS names in error messages
        dns_patterns = [
            r"DNS:([a-zA-Z0-9.-]+)",
            r"CN\s*=\s*([a-zA-Z0-9.-]+)",
            r'certificate.*?for\s*[\'"]?([a-zA-Z0-9.-]+)',
            r'subject.*?[\'"]?([a-zA-Z0-9.-]+)',
        ]

        for pattern in dns_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            for match in matches:
                if "." in match and not match.startswith(
                    "."
                ):  # Basic domain validation
                    revealed_hostnames.add(match.strip())

        if revealed_hostnames:
            error_info["revealed_hostnames"] = list(revealed_hostnames)

        # Look for certificate details in error context
        cert_details_patterns = [
            r"server certificate:\s*(.+?)(?:\n\*|$)",
            r"certificate:\s*subject:\s*(.+?)(?:\n|$)",
        ]

        for pattern in cert_details_patterns:
            match = re.search(pattern, output, re.IGNORECASE | re.MULTILINE)
            if match:
                error_info["certificate_details_in_error"] = match.group(1).strip()
                break

        # Connection errors that might be relevant
        connection_error_patterns = [
            r"Could not resolve host:\s*(.+?)(?:\n|$)",
            r"Connection refused",
            r"timeout",
            r"SSL_connect failed",
        ]

        for pattern in connection_error_patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                if match.groups():
                    error_info["connection_error"] = match.group(1).strip()
                else:
                    error_info["connection_error"] = match.group(0).strip()
                break

        return error_info
