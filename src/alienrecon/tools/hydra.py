import logging
import os
import re

from ..core.config import DEFAULT_PASSWORD_LIST  # Import default password list
from ..core.types import ToolResult
from .base import CommandTool

logger = logging.getLogger(__name__)


class HydraTool(CommandTool):
    """
    Tool wrapper for executing Hydra brute-force attacks.
    """

    name: str = "hydra"
    description: str = "Performs brute-force attacks on login services using Hydra."
    executable_name: str = "hydra"

    DEFAULT_THREADS = 4  # A conservative default for threads

    def build_command(
        self,
        target: str,
        port: int,
        service_protocol: str,  # e.g., "http-get", "ftp", "ssh"
        username: str,
        password_list: str | None = None,
        path: str | None = None,  # Optional, for services like http-get
        threads: int | None = None,
        **kwargs,  # For any other hydra specific args the LLM might want to pass
    ) -> list[str]:
        """
        Constructs the Hydra command arguments.

        Args:
            target: The target IP address or hostname.
            port: The target port number.
            service_protocol: The Hydra service module (e.g., 'http-get', 'ftp').
            username: The username to target.
            password_list: Optional path to a specific password list. Uses default if None.
            path: Optional path for the service (e.g., /protected for http-get).
            threads: Optional number of parallel threads for Hydra.
            **kwargs: Additional hydra arguments as a string under 'hydra_options' key.

        Returns:
            A list of strings for the Hydra command.

        Raises:
            ValueError: If required arguments are missing.
            FileNotFoundError: If the specified or default password list cannot be found.
        """
        if not all([target, port, service_protocol, username]):
            raise ValueError(
                "Target, port, service_protocol, and username must be provided for Hydra."
            )

        password_list_to_use = password_list or DEFAULT_PASSWORD_LIST
        if not password_list_to_use:
            raise FileNotFoundError(
                "No specific password list provided and no default password list configured."
            )
        if not os.path.exists(password_list_to_use):
            # Try to resolve relative paths, though full paths are preferred
            if not os.path.isabs(password_list_to_use):
                expanded_path = os.path.expanduser(password_list_to_use)
                if os.path.exists(expanded_path):
                    password_list_to_use = expanded_path
                else:  # If still not found after expansion
                    raise FileNotFoundError(
                        f"Password list not found at '{password_list_to_use}' (or '{expanded_path}')."
                    )
            else:  # If it was an absolute path and not found
                raise FileNotFoundError(
                    f"Password list not found at '{password_list_to_use}'."
                )

        threads_to_use = threads or self.DEFAULT_THREADS

        command_args = [
            "-l",
            username,
            "-P",
            password_list_to_use,
            "-s",
            str(port),
            "-t",
            str(threads_to_use),
            # "-V", # Verbose output - good for debugging, but maybe too noisy for LLM
            # "-q", # Quiet mode - check if Hydra has one that's useful
        ]

        # Handle additional hydra options if provided by LLM
        # These should be carefully curated by the LLM or have strict validation
        # to prevent command injection if user input influences this.
        # For now, assuming LLM provides safe, well-formed options.
        additional_hydra_options = kwargs.get("hydra_options")
        if additional_hydra_options and isinstance(additional_hydra_options, str):
            # Naive split, consider shlex if complex options are expected
            command_args.extend(additional_hydra_options.split())

        # Construct the target string for Hydra
        # For http-get, it's often <target_ip> <service_protocol> <path>
        # For others, it's usually just <target_ip> <service_protocol>
        if service_protocol.startswith("http") and path:
            if not path.startswith("/"):
                path = "/" + path
            # Hydra command structure for http-get with path: <target> <service> <opts>
            # Example: 10.10.10.10 http-get /login.php
            # So target and service_protocol come after the options usually.
            # Let's re-evaluate command construction order with this in mind.
            # Hydra format: hydra [[[-l LOGIN|-L FILE] [-p PASS|-P FILE]] | [-C FILE]] [-e nsr] [-o FILE] [-t TASKS] [-M FILE [-T TASKS]] [-w TIME] [-W TIME] [-f] [-s PORT] [-x MIN:MAX:CHARSET] [-c TIME] [-ISOuvVd46] [-m MODULE_OPT] [service://server[:PORT][/OPT]]
            # The service specification comes last.

            # command_args.extend([target, service_protocol, path]) # This is not quite right for hydra syntax
            # Corrected approach: The target and service are the final arguments.
            # The path is usually part of the service string for HTTP modules or an option

            # For many modules like http-get, the path is an option for the module, not appended to service string.
            # e.g. hydra -l user -P list target http-get /path
            # However, some Hydra modules might take it as service://server/path
            # For http-get, it's typically service://server/path OR target http-get /path
            # Let's assume the path is an option that the service module itself handles if specified in the protocol string
            # e.g. if service_protocol is 'http-get /protected'
            # No, the path is typically an argument for the module after the basic target/service.
            # This part is tricky as Hydra's syntax varies.
            # Let's assume 'path' for http-get is appended to the service URI for simplicity or passed as a module option.
            # Safest: `target service_protocol` then module specific options like the path.
            # Example: `hydra -l bob -P pass.txt 10.10.199.90 http-get /protected`
            # The path is part of the "OPT" in `service://server[:PORT][/OPT]` for http-get

            # service_uri = f"{service_protocol}://{target}:{port}{path if path else ''}"
            # Actually, for http-get, hydra expects: <target_ip> http-get <path_after_domain>
            # command_args.extend([target, service_protocol])
            # if path:
            #    command_args.append(path) # This is how it's often shown
            # Let's use the service URI format for clarity, Hydra should parse it.
            # No, that's not how hydra CLI typically works for http-get for the path.
            # It's usually `target service path_option`
            # e.g. `hydra <options> <target> <protocol> <path_for_protocol>`

            # Final arguments are target and protocol
            # Path needs to be handled carefully based on protocol.
            # For 'http-get', 'http-post-form', etc., path is often separate.
            command_args.extend([target, service_protocol])
            if path:  # Path is typically an extra argument for http-get module
                command_args.append(path)
        else:
            command_args.extend([target, service_protocol])

        logger.debug(f"Built Hydra command args: {command_args}")
        return command_args

    def parse_output(
        self, stdout: str | None, stderr: str | None, **kwargs
    ) -> ToolResult:
        target_context = kwargs.get("target", "Unknown Target")
        username_context = kwargs.get("username", "N/A")
        service_context = kwargs.get("service_protocol", "N/A")
        path_context = kwargs.get("path", "")
        result: ToolResult = {
            "tool_name": self.name,
            "status": "success",
            "scan_summary": f"Hydra scan results for {target_context} ({service_context}{path_context} user {username_context})",
            "findings": {},
        }
        if stderr:
            result["status"] = "failure"
            result["scan_summary"] = (
                f"Hydra scan for {target_context} failed or produced no output."
            )
            result["error"] = stderr.strip()
            if stdout:
                result["raw_stdout"] = stdout[:5000]
            if stderr:
                result["raw_stderr"] = stderr[:5000]
            return result
        if not stdout:
            result["status"] = "failure"
            result["scan_summary"] = (
                f"Hydra scan for {target_context} produced no output."
            )
            result["error"] = "No standard output received from Hydra."
            return result
        findings = {}
        # More robust regex for host, username, password
        line_re = re.compile(
            r"host:\s*(?P<host>\S+)\s+login:\s*(?P<username>\S+)\s+password:\s*(?P<password>\S+)"
        )
        for line in stdout.splitlines():
            match = line_re.search(line.strip())
            if match:
                findings = {
                    "host": match.group("host"),
                    "username": match.group("username"),
                    "password": match.group("password"),
                }
                break
        if findings:
            result["findings"] = findings
            result["status"] = "success"
        else:
            result["status"] = "failure"
            result["scan_summary"] = (
                f"Hydra scan for {target_context} produced no output."
            )
            result["error"] = "No valid credentials parsed from Hydra output."
        return result
