# src/alienrecon/core/input_validator.py
"""Input validation and sanitization for security."""

import ipaddress
import re
import shlex
from pathlib import Path
from typing import Union
from urllib.parse import urlparse

from .exceptions import SecurityError, ValidationError


class InputValidator:
    """Validates and sanitizes user inputs for security."""

    # Regex patterns for validation
    HOSTNAME_PATTERN = re.compile(
        r'^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})*$'
    )
    PORT_PATTERN = re.compile(r'^\d{1,5}$')

    # Dangerous command patterns
    DANGEROUS_PATTERNS = [
        r';\s*rm\s+-rf',  # rm -rf commands
        r';\s*dd\s+',     # dd commands
        r'>\s*/dev/',     # Writing to devices
        r'`[^`]+`',       # Command substitution
        r'\$\([^)]+\)',   # Command substitution
        r'&&\s*curl',     # Command chaining with curl
        r'&&\s*wget',     # Command chaining with wget
        r'\|\s*sh',       # Piping to shell
        r'\|\s*bash',     # Piping to bash
    ]

    @classmethod
    def validate_target(cls, target: str) -> str:
        """Validate and sanitize a target IP or hostname."""
        if not target:
            raise ValidationError("Target cannot be empty")

        target = target.strip()

        # Try to parse as IP address first
        try:
            ip = ipaddress.ip_address(target)
            # Check for private/reserved IPs if needed
            if ip.is_loopback and target != "127.0.0.1":
                raise ValidationError("Loopback addresses other than 127.0.0.1 are not allowed")
            return str(ip)
        except ValueError:
            # Not a valid IP, check if it looks like an invalid IP
            if re.match(r'^\d+(\.\d+){3}$', target):
                # It looks like an IP but isn't valid
                raise ValidationError(f"Invalid IP address: {target}")

        # Try to parse as hostname
        if cls.HOSTNAME_PATTERN.match(target):
            return target

        raise ValidationError(f"Invalid target format: {target}")

    @classmethod
    def validate_port(cls, port: Union[str, int]) -> int:
        """Validate a port number."""
        try:
            port_num = int(port)
            if 1 <= port_num <= 65535:
                return port_num
            raise ValidationError(f"Port must be between 1 and 65535, got {port_num}")
        except (ValueError, TypeError):
            raise ValidationError(f"Invalid port: {port}")

    @classmethod
    def validate_port_list(cls, ports: str) -> str:
        """Validate a comma-separated list of ports or port ranges."""
        if not ports:
            raise ValidationError("Port list cannot be empty")

        validated_parts = []
        for part in ports.split(','):
            part = part.strip()
            if '-' in part:
                # Port range
                start, end = part.split('-', 1)
                start_port = cls.validate_port(start)
                end_port = cls.validate_port(end)
                if start_port > end_port:
                    raise ValidationError(f"Invalid port range: {part}")
                validated_parts.append(f"{start_port}-{end_port}")
            else:
                # Single port
                validated_parts.append(str(cls.validate_port(part)))

        return ','.join(validated_parts)

    @classmethod
    def validate_file_path(cls, path: str, must_exist: bool = False) -> Path:
        """Validate a file path."""
        try:
            # Check for path traversal attempts before resolving
            if '..' in path:
                raise SecurityError("Path traversal detected")

            path_obj = Path(path).resolve()

            if must_exist and not path_obj.exists():
                raise ValidationError(f"Path does not exist: {path}")

            return path_obj
        except SecurityError:
            raise  # Re-raise security errors
        except Exception as e:
            raise ValidationError(f"Invalid path: {path} - {e}")

    @classmethod
    def sanitize_command_args(cls, args: str) -> list[str]:
        """Sanitize command arguments for subprocess execution."""
        if not args:
            return []

        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, args, re.IGNORECASE):
                raise SecurityError("Potentially dangerous command pattern detected")

        # Use shlex to safely split arguments
        try:
            return shlex.split(args)
        except ValueError as e:
            raise ValidationError(f"Invalid command arguments: {e}")

    @classmethod
    def validate_url(cls, url: str) -> str:
        """Validate and sanitize a URL."""
        if not url:
            raise ValidationError("URL cannot be empty")

        try:
            parsed = urlparse(url)

            # Check scheme
            if parsed.scheme not in ('http', 'https', 'ftp'):
                raise ValidationError(f"Unsupported URL scheme: {parsed.scheme}")

            # Check for basic validity
            if not parsed.netloc:
                raise ValidationError("URL must include a domain")

            # Reconstruct URL to ensure it's properly formatted
            return parsed.geturl()
        except Exception as e:
            raise ValidationError(f"Invalid URL: {url} - {e}")

    @classmethod
    def validate_username(cls, username: str) -> str:
        """Validate a username."""
        if not username:
            raise ValidationError("Username cannot be empty")

        # Basic validation - alphanumeric, underscore, dash, dot
        if not re.match(r'^[a-zA-Z0-9._-]+$', username):
            raise ValidationError("Username contains invalid characters")

        if len(username) > 64:
            raise ValidationError("Username too long (max 64 characters)")

        return username

    @classmethod
    def validate_wordlist_path(cls, path: str) -> Path:
        """Validate a wordlist file path."""
        path_obj = cls.validate_file_path(path, must_exist=True)

        # Check file extension
        if path_obj.suffix not in ('.txt', '.lst', '.list'):
            raise ValidationError("Wordlist must be a .txt, .lst, or .list file")

        # Check file size (prevent loading huge files)
        max_size = 100 * 1024 * 1024  # 100MB
        if path_obj.stat().st_size > max_size:
            raise ValidationError("Wordlist file too large (max 100MB)")

        return path_obj
