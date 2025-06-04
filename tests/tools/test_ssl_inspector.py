"""
Tests for SSL Inspector Tool

This module tests the SSL certificate inspection functionality.
"""

from unittest.mock import MagicMock, patch

import pytest

from src.alienrecon.tools.ssl_inspector import SSLInspectorTool


class TestSSLInspectorTool:
    """Test cases for SSL Inspector Tool."""

    def test_tool_initialization(self):
        """Test that the SSL inspector tool can be initialized."""
        tool = SSLInspectorTool()
        assert tool.name == "ssl_inspector"
        assert tool.executable_name == "openssl"
        assert "SSL certificate" in tool.description

    def test_build_command_basic(self):
        """Test building basic SSL inspection command."""
        tool = SSLInspectorTool()
        command = tool.build_command(ip="10.10.10.10")

        assert "s_client" in command
        assert "-connect" in command
        assert "10.10.10.10:443" in command
        assert "-showcerts" in command

    def test_build_command_with_sni(self):
        """Test building SSL inspection command with SNI hostname."""
        tool = SSLInspectorTool()
        command = tool.build_command(ip="10.10.10.10", hostname_for_sni="example.com")

        assert "-servername" in command
        assert "example.com" in command

    def test_build_command_custom_port(self):
        """Test building SSL inspection command with custom port."""
        tool = SSLInspectorTool()
        command = tool.build_command(ip="10.10.10.10", port=8443)

        assert "10.10.10.10:8443" in command

    def test_build_command_missing_ip(self):
        """Test that missing IP raises ValueError."""
        tool = SSLInspectorTool()
        with pytest.raises(ValueError, match="IP address must be provided"):
            tool.build_command()

    def test_parse_certificate_info(self):
        """Test parsing certificate information from openssl output."""
        tool = SSLInspectorTool()

        # Sample openssl s_client output
        sample_output = """
subject=CN=example.com, O=Example Corp, C=US
issuer=CN=Example CA, O=Example CA Corp, C=US
notBefore=Jan  1 00:00:00 2023 GMT
notAfter=Dec 31 23:59:59 2024 GMT
serial=1234567890ABCDEF
        X509v3 Subject Alternative Name:
            DNS:www.example.com, DNS:api.example.com, IP Address:192.168.1.1
"""

        cert_info = tool._parse_certificate_info(sample_output)

        assert cert_info["common_name"] == "example.com"
        assert "www.example.com" in cert_info["subject_alt_names"]
        assert "api.example.com" in cert_info["subject_alt_names"]
        assert "IP:192.168.1.1" in cert_info["subject_alt_names"]
        assert "Example CA" in cert_info["issuer"]
        assert cert_info["serial_number"] == "1234567890ABCDEF"

    def test_extract_error_info(self):
        """Test extracting useful error information from failed SSL connections."""
        tool = SSLInspectorTool()

        # Sample error output with hostname mismatch
        error_output = """
verify error:num=62:hostname mismatch expected: correct-hostname.com
certificate subject: CN=wrong-hostname.com
Connection refused
"""

        error_info = tool._extract_error_info(error_output)

        assert "hostname mismatch" in error_info.get("verification_error", "")
        assert error_info.get("expected_hostname") == "correct-hostname.com"
        assert "Connection refused" in error_info.get("connection_error", "")

    @patch("subprocess.run")
    def test_execute_success(self, mock_run):
        """Test successful SSL certificate inspection execution."""
        # Mock successful openssl s_client execution
        mock_result = MagicMock()
        mock_result.stdout = """
subject=CN=test.example.com
issuer=CN=Test CA
        X509v3 Subject Alternative Name:
            DNS:www.test.example.com
"""
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        tool = SSLInspectorTool()
        tool.executable_path = "/usr/bin/openssl"  # Mock path

        result = tool.execute(ip="10.10.10.10")

        assert result["status"] == "success"
        assert result["tool_name"] == "ssl_inspector"
        assert "certificate" in result["findings"]
        assert result["findings"]["certificate"]["common_name"] == "test.example.com"

    @patch("subprocess.run")
    def test_execute_with_error_info(self, mock_run):
        """Test SSL inspection that fails but provides useful error information."""
        # Mock openssl s_client execution with connection error but useful info
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = (
            "verify error:num=62:hostname mismatch expected: real-hostname.com"
        )
        mock_run.return_value = mock_result

        tool = SSLInspectorTool()
        tool.executable_path = "/usr/bin/openssl"  # Mock path

        result = tool.execute(ip="10.10.10.10")

        assert result["status"] == "partial"
        assert "error_details" in result["findings"]
        assert "hostname mismatch" in result["findings"]["error_details"].get(
            "verification_error", ""
        )

    def test_execute_no_executable(self):
        """Test execution when openssl executable is not found."""
        tool = SSLInspectorTool()
        tool.executable_path = None  # Simulate missing executable

        result = tool.execute(ip="10.10.10.10")

        assert result["status"] == "failure"
        assert "not found" in result["error"]
