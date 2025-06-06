# src/alienrecon/core/exceptions.py
"""Custom exception hierarchy for Alien Recon."""


class AlienReconError(Exception):
    """Base exception for all Alien Recon errors."""
    pass


class ToolExecutionError(AlienReconError):
    """Raised when a tool fails to execute properly."""
    pass


class ConfigurationError(AlienReconError):
    """Raised when there's a configuration issue."""
    pass


class SessionError(AlienReconError):
    """Raised when there's an issue with session management."""
    pass


class ValidationError(AlienReconError):
    """Raised when input validation fails."""
    pass


class PlanExecutionError(AlienReconError):
    """Raised when plan execution encounters an error."""
    pass


class SecurityError(AlienReconError):
    """Raised when a security constraint is violated."""
    pass
