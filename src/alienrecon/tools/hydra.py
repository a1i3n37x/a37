import logging
import os
import re
from typing import Any

from ..core.config import DEFAULT_PASSWORD_LIST  # Import default password list
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
    ) -> dict[str, Any]:
        """
        Parses Hydra output to find successful logins.

        Args:
            stdout: Raw text output from Hydra execution.
            stderr: Error output from Hydra or run_command.
            **kwargs: Original arguments for context.

        Returns:
            A dictionary containing the parsed scan results or error information.
        """
        target_context = kwargs.get("target", "Unknown Target")
        username_context = kwargs.get("username", "N/A")
        service_context = kwargs.get("service_protocol", "N/A")
        path_context = kwargs.get("path", "")

        if stderr:
            # Hydra often prints "0 valid passwords found" to stderr on failure,
            # which isn't a critical error for parsing, but good to note.
            # Critical errors (e.g., can't connect) also go to stderr.
            logger.warning(
                f"Hydra for {target_context} ({service_context}{path_context} user {username_context}) reported to stderr: {stderr[:200]}"
            )

        findings = {}
        if stdout:
            # Example success line:
            # [80][http-get] host: 10.10.199.90 login: bob password: password123
            # Regex to capture this:
            # For service with port: \[(\d+)\]\[([^\]]+)\] host: ([^\s]+) login: ([^\s]+) password: (.+)
            # For service without port (e.g. ssh): host: ([^\s]+) service: (\d+|ssh|ftp) login: ([^\s]+) password: (.+) -- needs adjustment

            # Simpler regex focusing on the core part if Hydra output is consistent:
            # "host: <host> login: <login> password: <password>"
            # Let's try a more specific one for the common output format

            # Regex to find the successful login line
            # It might start with a port and service, or directly with host
            # Example: 10.10.11.110  ssh   login: msfadmin password: msfadmin
            # Example: [80][http-get] host: 10.10.149.215 login: bob password: test

            # This regex tries to capture the essential parts of a success line
            # It allows for an optional prefix like "[80][http-get]"
            success_pattern = re.compile(
                r"(?:\[\d+\]\[[^\]]+\]\s+)?host:\s*([^\s]+)\s+(?:service:\s*\S+\s+)?login:\s*([^\s]+)\s+password:\s*(.+)",
                re.IGNORECASE,
            )

            match = success_pattern.search(stdout)

            if match:
                # Matched groups depend on the exact pattern used
                # Assuming the simpler pattern for now, or adjusting based on common Hydra output
                # For: host: ([^\s]+) login: ([^\s]+) password: (.+)
                # host_found = match.group(1)
                # login_found = match.group(2)
                # password_found = match.group(3).strip() # Strip potential trailing spaces

                # For more complex pattern:
                # (?:\[\d+\]\[[^\]]+\]\s+)?  -> Optional non-capturing group for [port][service]
                # host:\s*([^\s]+)           -> Group 1: host
                # (?:service:\s*\S+\s+)?    -> Optional non-capturing group for "service: xyz"
                # login:\s*([^\s]+)          -> Group 2: login
                # password:\s*(.+)           -> Group 3: password

                # Re-check group indices if pattern changes.
                # With the current complex pattern, they should be 1, 2, 3 for host, login, password respectively if all parts match.
                # If the optional prefix isn't there, the groups shift. This pattern is tricky.

                # Let's use a simpler, more direct approach by looking for lines containing "password: "
                lines = stdout.splitlines()
                for line in lines:
                    if (
                        "login:" in line and "password:" in line and "host:" in line
                    ):  # A good indicator of a success line
                        # Try to parse this specific line format
                        # Example: [80][http-get] host: 10.10.149.215 login: bob password: test
                        parts_match = re.search(
                            r"host:\s*([^\s]+)\s*login:\s*([^\s]+)\s*password:\s*(.+)",
                            line,
                            re.IGNORECASE,
                        )
                        if parts_match:
                            found_host = parts_match.group(1)
                            found_login = parts_match.group(2)
                            found_password = parts_match.group(3).strip()

                            findings = {
                                "host": found_host,
                                "username": found_login,
                                "password": found_password,
                                "service_protocol": service_context,
                                "target_path": path_context,
                            }
                            scan_summary = (
                                f"Hydra successfully found credentials for {username_context} "
                                f"on {target_context}:{kwargs.get('port', 'N/A')}{path_context} ({service_context})."
                            )
                            # Break after first find, assuming one user target
                            if (
                                username_context == found_login
                            ):  # Prioritize if it matches the input username
                                break
                if not findings:  # If loop finished with no specific match
                    scan_summary = (
                        f"Hydra scan completed for {username_context} on "
                        f"{target_context}:{kwargs.get('port', 'N/A')}{path_context} ({service_context}). No password found with the "
                        f"provided list, or output format unexpected."
                    )
                    if (
                        stdout
                    ):  # Include some stdout if parsing failed but output exists
                        findings["raw_stdout_sample"] = stdout[:200]

            else:  # No regex match in the entire stdout
                scan_summary = (
                    f"Hydra scan completed for {username_context} on "
                    f"{target_context}:{kwargs.get('port', 'N/A')}{path_context} ({service_context}). No password found with the "
                    f"provided list."
                )
                if stdout:  # Include some stdout if parsing failed but output exists
                    findings["raw_stdout_sample"] = stdout[:200]
        else:  # No stdout at all
            scan_summary = (
                f"Hydra scan for {username_context} on {target_context}:{kwargs.get('port', 'N/A')}{path_context} ({service_context}) "
                f"produced no output."
            )
            if stderr:
                findings["error_details"] = stderr[:200]

        result_dict = {"scan_summary": scan_summary, "findings": findings}
        if (
            stderr and "error_details" not in findings and "password" not in findings
        ):  # Add stderr if it seems like an error and not just "0 found"
            if (
                "0 valid passwords found" not in stderr.lower()
                and "failed to connect" in stderr.lower()
            ):
                result_dict["error"] = stderr.strip()
            elif (
                "0 valid passwords found" in stderr.lower()
                and "password" not in findings
            ):  # Explicitly note no creds found
                result_dict["findings"]["status"] = "No credentials found"

        return result_dict
