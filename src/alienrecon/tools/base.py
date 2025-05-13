# src/alienrecon/tools/base.py
import logging
import os
import subprocess
from abc import ABC, abstractmethod
from typing import Any

# Correct import from core.config
from ..core.config import TOOL_PATHS, console


# --- Helper Function (Moved from main.py) ---
# This function is generic for running any command-line tool.
def run_command(
    command_list: list[str], timeout: int = 3600
) -> tuple[str | None, str | None]:
    """
    Executes an external command and captures its stdout and stderr.

    Args:
        command_list: The command and its arguments as a list of strings.
        timeout: Timeout in seconds for the command execution.

    Returns:
        A tuple containing (stdout, stderr). stderr is None if the command
        executed successfully (return code 0), otherwise it contains the
        stderr output or an error message. stdout might be None if the
        command failed catastrophically (e.g., not found).
    """
    if not command_list:
        return None, "Empty command list provided."

    executable_name = os.path.basename(command_list[0])  # Get tool name for logging
    # Use DEBUG level for command execution details
    logging.debug(f"Executing command: {' '.join(command_list)}")
    try:
        result = subprocess.run(
            command_list,
            capture_output=True,
            text=True,
            check=False,  # Don't raise exception on non-zero exit code
            timeout=timeout,
        )
        if result.returncode != 0:
            stderr_output = (
                result.stderr.strip()
                if result.stderr
                else f"{executable_name} exited with status {result.returncode}"
            )
            logging.warning(
                f"Command '{executable_name}' failed. Return Code: "
                f"{result.returncode}. Stderr: {stderr_output}"
            )
            # Return stdout even on failure, it might contain partial info
            # or error details
            return result.stdout.strip() if result.stdout else None, stderr_output
        # Success case: return stdout and None for error
        return result.stdout.strip() if result.stdout else "", None
    except FileNotFoundError:
        err_msg = (
            f"Command not found: '{command_list[0]}'. Ensure "
            f"'{executable_name}' is installed and in PATH."
        )
        logging.error(err_msg)
        console.print(f"[bold red]Error: {err_msg}[/bold red]")
        return None, err_msg
    except subprocess.TimeoutExpired:
        err_msg = f"Command timed out after {timeout}s: {' '.join(command_list)}"
        logging.error(err_msg)
        console.print(f"[bold red]Error: {err_msg}[/bold red]")
        return None, err_msg
    except Exception as e:
        err_msg = f"Error running command {' '.join(command_list)}: {e}"
        logging.error(
            err_msg, exc_info=True
        )  # Log full traceback for unexpected errors
        console.print(f"[bold red]Error: {err_msg}[/bold red]")
        return None, err_msg


# --- Abstract Base Class for Tools ---
class CommandTool(ABC):
    """
    Abstract base class for command-line tools integrated with Alien Recon.
    Each specific tool (Nmap, Gobuster, etc.) should inherit from this class.
    """

    # Class attributes to be overridden by subclasses
    name: str = "UnnamedTool"  # Short name, e.g., "nmap", "gobuster"
    description: str = "No description provided."  # Brief description for help/logging
    executable_name: str = ""  # The actual command name (e.g., "nmap", "gobuster")

    def __init__(self):
        """
        Initializes the tool, checking if the executable exists.
        """
        self.executable_path = TOOL_PATHS.get(self.executable_name)
        if not self.executable_path:
            logging.warning(
                f"Executable '{self.executable_name}' for tool '{self.name}' "
                f"not found in PATH."
            )

    @abstractmethod
    def build_command(self, **kwargs) -> list[str]:
        """
        Constructs the command-line arguments for the tool based on input parameters.

        Args:
            **kwargs: Arguments specific to the tool (e.g., target, port, wordlist).

        Returns:
            A list of strings representing the command and its arguments
            (excluding the executable path itself).
            Example: ['-sV', '-T4', '192.168.1.1']

        Raises:
            ValueError: If required arguments are missing or invalid.
            FileNotFoundError: If a required file (like a wordlist) is not found.
        """
        pass

    @abstractmethod
    def parse_output(
        self, stdout: str | None, stderr: str | None, **kwargs
    ) -> dict[str, Any]:
        """
        Parses the raw stdout and stderr from the tool's execution into a
        structured JSON-serializable dictionary suitable for the LLM.

        Args:
            stdout: The standard output from the command execution, or None.
            stderr: The standard error from the command execution (contains error
                    message if run_command indicated failure), or None.
            **kwargs: The original arguments passed to the execute method,
                      useful for context during parsing (e.g., target URL).


        Returns:
            A dictionary containing the parsed results and a summary.
            Example: {"scan_summary": "Nmap scan completed...", "findings": [...]}
                     or {"scan_summary": "Nmap scan failed.", "error": "...",
                         "findings": []}
        """
        pass

    def execute(self, **kwargs) -> dict[str, Any]:
        """
        Executes the tool's command and returns the parsed results.
        This method orchestrates the build->run->parse workflow.

        Args:
            **kwargs: Arguments passed to build_command.

        Returns:
            A dictionary containing the parsed results from parse_output.
        """
        if not self.executable_path:
            err_msg = (
                f"Tool '{self.name}' ({self.executable_name}) cannot be "
                f"executed because it was not found in PATH."
            )
            logging.error(err_msg)
            return {
                "scan_summary": f"{self.name.capitalize()} execution failed.",
                "error": err_msg,
                "findings": [],  # Ensure findings list/dict exists
            }

        try:
            command_args = self.build_command(**kwargs)
            command = [self.executable_path] + command_args  # Prepend executable path
        except (
            ValueError,
            FileNotFoundError,
        ) as e:  # Catch specific errors from build_command
            err_msg = f"Error building command for {self.name}: {e}"
            logging.error(err_msg)
            return {
                "scan_summary": f"{self.name.capitalize()} command build failed.",
                "error": err_msg,
                "findings": [],
            }
        except Exception as e:  # Catch unexpected errors
            err_msg = f"Unexpected error building command for {self.name}: {e}"
            logging.error(err_msg, exc_info=True)
            return {
                "scan_summary": f"{self.name.capitalize()} command build failed.",
                "error": err_msg,
                "findings": [],
            }

        # Run the command using the helper function
        stdout, stderr = run_command(
            command
        )  # stderr contains error details if run failed

        # Parse the output using subclass logic, passing original kwargs for context
        try:
            parsed_results = self.parse_output(stdout, stderr, **kwargs)
            # Ensure standard fields are present for robustness
            if "scan_summary" not in parsed_results:
                parsed_results["scan_summary"] = parsed_results.get(
                    "error", f"{self.name.capitalize()} scan completed."
                )
            if "findings" not in parsed_results:
                parsed_results["findings"] = []  # Default to empty list if missing
            return parsed_results
        except Exception as e:
            err_msg = f"Error parsing output for {self.name}: {e}"
            logging.error(err_msg, exc_info=True)
            return {
                "scan_summary": f"{self.name.capitalize()} output parsing failed.",
                "error": err_msg,
                "raw_stdout": stdout[:500] if stdout else None,
                "raw_stderr": stderr[:500] if stderr else None,
                "findings": [],
            }
