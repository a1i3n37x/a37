import logging  # Logging module
import os
import subprocess
from abc import ABC, abstractmethod

# Correct import from core.config
from ..core.config import TOOL_PATHS, console
from ..core.exceptions import SecurityError, ValidationError
from ..core.input_validator import InputValidator
from ..core.types import ToolResult

# DEFINE THE MODULE-LEVEL LOGGER
logger = logging.getLogger(__name__)


def _validate_command_security(command_list: list[str]) -> None:
    """Validate command for security concerns."""
    if not command_list:
        raise ValidationError("Empty command list")

    # Check executable
    executable = command_list[0]

    # Allowed executable names for security tools
    ALLOWED_EXECUTABLES = {
        'nmap', 'nikto', 'ffuf', 'hydra', 'enum4linux-ng',
        'smbclient', 'openssl', 'curl', 'wget', 'searchsploit'
    }

    executable_name = os.path.basename(executable)
    if executable_name not in ALLOWED_EXECUTABLES:
        raise SecurityError(f"Executable '{executable_name}' not in allowed list")

    # Check for dangerous argument patterns
    full_command = ' '.join(command_list)

    # Dangerous patterns that should never appear
    DANGEROUS_PATTERNS = [
        r';\s*rm\s+-rf',
        r';\s*dd\s+',
        r'>\s*/dev/',
        r'`[^`]+`',
        r'\$\([^)]+\)',
        r'&&\s*curl.*\|\s*sh',
        r'&&\s*wget.*\|\s*sh',
        r'\|\s*sh\s*$',
        r'\|\s*bash\s*$',
        r'exec\s*\(',
    ]

    import re
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, full_command, re.IGNORECASE):
            raise SecurityError(f"Dangerous command pattern detected: {pattern}")

    # Validate individual arguments
    for arg in command_list[1:]:
        if len(arg) > 1000:  # Prevent extremely long arguments
            raise ValidationError(f"Argument too long: {len(arg)} characters")

        # Check for null bytes
        if '\x00' in arg:
            raise SecurityError("Null byte detected in argument")

        # Check for control characters (except common ones)
        import string
        allowed_chars = string.printable.replace('\x0b\x0c', '')
        if not all(c in allowed_chars for c in arg):
            raise SecurityError("Invalid characters detected in argument")


def run_command(
    command_list: list[str], timeout: int = 3600
) -> tuple[str | None, str | None]:
    if not command_list:
        # Use the logger we just defined
        logger.error("Empty command list provided to run_command.")
        return None, "Empty command list provided."

    # Validate the command for security
    try:
        _validate_command_security(command_list)
    except (SecurityError, ValidationError) as e:
        logger.error(f"Command security validation failed: {e}")
        return None, f"Security validation failed: {e}"

    executable_name = os.path.basename(command_list[0])
    # Use the logger
    logger.debug(f"Executing command: {' '.join(command_list)}")
    try:
        result = subprocess.run(
            command_list,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
        if result.returncode != 0:
            stderr_output = (
                result.stderr.strip()
                if result.stderr
                else f"{executable_name} exited with status {result.returncode}"
            )
            # Use the logger
            logger.warning(
                f"Command '{executable_name}' failed. Return Code: "
                f"{result.returncode}. Stderr: {stderr_output}"
            )
            return result.stdout.strip() if result.stdout else None, stderr_output
        return result.stdout.strip() if result.stdout else "", None
    except FileNotFoundError:
        err_msg = (
            f"Command not found: '{command_list[0]}'. Ensure "
            f"'{executable_name}' is installed and in PATH, or check tool configuration."
        )
        # Use the logger
        logger.error(err_msg)
        console.print(f"[bold red]Error: {err_msg}[/bold red]")
        return None, err_msg
    except subprocess.TimeoutExpired:
        err_msg = f"Command timed out after {timeout}s: {' '.join(command_list)}"
        # Use the logger
        logger.error(err_msg)
        console.print(f"[bold red]Error: {err_msg}[/bold red]")
        return None, err_msg
    except Exception as e:
        err_msg = f"Error running command {' '.join(command_list)}: {e}"
        # Use the logger
        logger.error(err_msg, exc_info=True)
        console.print(f"[bold red]Error: {err_msg}[/bold red]")
        return None, err_msg


class CommandTool(ABC):
    name: str = "UnnamedTool"
    description: str = "No description provided."
    executable_name: str = ""  # MUST BE SET BY SUBCLASS (e.g., "nmap", "ffuf")

    def __init__(self):
        if not self.executable_name:
            # Use the logger
            logger.critical(
                f"Tool class {self.__class__.__name__} has not set 'executable_name'. "
                "Cannot determine executable path. Tool will be unusable."
            )
            self.executable_path = None
            return

        resolved_path_from_config = TOOL_PATHS.get(self.executable_name)

        if resolved_path_from_config:
            if os.path.isfile(resolved_path_from_config) and os.access(
                resolved_path_from_config, os.X_OK
            ):
                self.executable_path = resolved_path_from_config
                # Use the logger
                logger.debug(
                    f"Tool '{self.name}' (for '{self.executable_name}') initialized. "
                    f"Executable path set to: {self.executable_path}"
                )
            else:
                # Use the logger
                logger.error(
                    f"Path for '{self.executable_name}' resolved from TOOL_PATHS to '{resolved_path_from_config}', "
                    f"but this file either does not exist or is not executable. "
                    f"Tool '{self.name}' will be unavailable."
                )
                self.executable_path = None
        else:
            # Use the logger
            logger.warning(
                f"Executable '{self.executable_name}' for tool '{self.name}' "
                f"could not be found (checked PATH via shutil.which and known fallbacks in config). "
                f"Tool '{self.name}' will be unavailable."
            )
            self.executable_path = None

    @abstractmethod
    def build_command(self, **kwargs) -> list[str]:
        pass

    def validate_input(self, **kwargs) -> dict:
        """Validate and sanitize input parameters. Override in subclasses for specific validation."""
        validated = {}

        # Common validations
        if 'target' in kwargs:
            validated['target'] = InputValidator.validate_target(kwargs['target'])

        if 'port' in kwargs:
            validated['port'] = InputValidator.validate_port(kwargs['port'])

        if 'ports' in kwargs:
            validated['ports'] = InputValidator.validate_port_list(kwargs['ports'])

        if 'url' in kwargs:
            validated['url'] = InputValidator.validate_url(kwargs['url'])

        if 'username' in kwargs:
            validated['username'] = InputValidator.validate_username(kwargs['username'])

        if 'wordlist' in kwargs:
            validated['wordlist'] = str(InputValidator.validate_wordlist_path(kwargs['wordlist']))

        # Copy other arguments that don't need validation
        for key, value in kwargs.items():
            if key not in validated:
                validated[key] = value

        return validated

    @abstractmethod
    def parse_output(
        self, stdout: str | None, stderr: str | None, **kwargs
    ) -> ToolResult:
        pass

    def execute(self, **kwargs) -> ToolResult:
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
            # Validate input parameters first
            validated_kwargs = self.validate_input(**kwargs)
            command_args = self.build_command(**validated_kwargs)
            if not isinstance(self.executable_path, str):
                err_msg = f"Tool '{self.name}' has an invalid executable_path type: {type(self.executable_path)}. Expected string."
                logger.error(err_msg)
                return {
                    "tool_name": self.name,
                    "status": "failure",
                    "scan_summary": f"{self.name.capitalize()} setup error.",
                    "error": err_msg,
                    "findings": {},
                }
            command = [self.executable_path] + command_args
        except (ValueError, FileNotFoundError) as e:
            err_msg = f"Error building command for {self.name}: {e}"
            logger.error(err_msg)
            return {
                "tool_name": self.name,
                "status": "failure",
                "scan_summary": f"{self.name.capitalize()} command build failed.",
                "error": err_msg,
                "findings": {},
            }
        except Exception as e:
            err_msg = f"Unexpected error building command for {self.name}: {e}"
            logger.error(err_msg, exc_info=True)
            return {
                "tool_name": self.name,
                "status": "failure",
                "scan_summary": f"{self.name.capitalize()} command build failed (unexpected).",
                "error": err_msg,
                "findings": {},
            }
        stdout, stderr = run_command(command)
        try:
            parsed_results = self.parse_output(stdout, stderr, **kwargs)
            parsed_results.setdefault("tool_name", self.name)
            if "status" not in parsed_results:
                parsed_results["status"] = (
                    "success" if not parsed_results.get("error") else "failure"
                )
            if "scan_summary" not in parsed_results:
                parsed_results["scan_summary"] = parsed_results.get(
                    "error", f"{self.name.capitalize()} scan processing completed."
                )
            if "findings" not in parsed_results:
                parsed_results["findings"] = (
                    {} if isinstance(parsed_results.get("findings"), dict) else []
                )
            if stdout is not None:
                parsed_results["raw_stdout"] = stdout[:5000]
            if stderr is not None:
                parsed_results["raw_stderr"] = stderr[:5000]
            return parsed_results
        except Exception as e:
            err_msg = f"Error parsing output for {self.name}: {e}"
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
