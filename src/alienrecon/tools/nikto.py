# src/alienrecon/tools/nikto.py
import json
import logging
import os
import shlex
import tempfile
from typing import Any

from ..core.types import ToolResult
from .base import CommandTool, run_command

logger = logging.getLogger(__name__)


class NiktoTool(CommandTool):
    name: str = "nikto"
    description: str = "Performs web server vulnerability scanning using Nikto."
    executable_name: str = "nikto"
    DEFAULT_TUNING = "x"

    def build_command(
        self,
        target: str,
        port: int,
        nikto_arguments: str | None = None,
        temp_json_output_path: str | None = None,
        **kwargs,
    ) -> list[str]:
        if not target:
            raise ValueError("Target must be provided for Nikto.")
        if not port:
            raise ValueError("Port must be provided for Nikto.")
        if not temp_json_output_path:
            raise ValueError("Temporary JSON output path must be provided.")

        command_args = [
            "-h",
            target,
            "-p",
            str(port),
            "-Format",
            "json",
            "-o",
            temp_json_output_path,
            "-Tuning",
            self.DEFAULT_TUNING,
            "-nointeractive",
            "-ask",
            "no",
        ]

        if nikto_arguments:
            try:
                extra_args = shlex.split(nikto_arguments)
                safe_extra_args = [
                    arg
                    for arg in extra_args
                    if not arg.startswith(
                        ("-h", "-p", "-Format", "-o", "-Save", "-ask", "-nointeractive")
                    )
                ]
                if len(safe_extra_args) != len(extra_args):
                    # Use module-level logging for static/class methods if self.logger isn't available
                    logging.warning(
                        "Filtered potentially conflicting arguments from Nikto "
                        f"args: '{nikto_arguments}'"
                    )
                command_args.extend(safe_extra_args)
            except ValueError as e:
                logging.error(
                    f"Error splitting nikto arguments '{nikto_arguments}': {e}. "
                    f"Ignoring extra args."
                )

        logger.debug(f"Built Nikto command args: {command_args}")
        return command_args

    def parse_output(
        self,
        stdout: str | None,
        stderr: str | None,
        parsed_json_data: dict[str, Any] | None = None,
        **kwargs,
    ) -> ToolResult:
        target_context = (
            f"{kwargs.get('target', 'Unknown')}:{kwargs.get('port', 'N/A')}"
        )
        scan_summary = f"Nikto scan results for {target_context}:"
        result: ToolResult = {
            "tool_name": self.name,
            "status": "success",
            "scan_summary": scan_summary,
            "findings": {},
        }
        if stderr and not parsed_json_data:
            result["status"] = "failure"
            result["scan_summary"] = (
                f"Nikto scan for {target_context} failed or produced no output."
            )
            result["error"] = stderr.strip()
            if stdout:
                result["raw_stdout"] = stdout[:5000]
            if stderr:
                result["raw_stderr"] = stderr[:5000]
            return result
        if not parsed_json_data:
            result["status"] = "failure"
            result["scan_summary"] = (
                f"Nikto ran but produced no output for {target_context}."
            )
            result["error"] = "No JSON data returned. Produced no output."
            return result
        try:
            data = parsed_json_data
            result["findings"]["host_info"] = {
                "target_ip": data.get("ip"),
            }
            # Copy vulnerabilities if present
            if "vulnerabilities" in data:
                result["findings"]["vulnerabilities"] = data["vulnerabilities"]
            # ... (rest of your parsing logic) ...
            if result["findings"].get("vulnerabilities"):
                result["scan_summary"] += (
                    f" Found {len(result['findings']['vulnerabilities'])} potential findings."
                )
            elif not result.get("error"):
                result["scan_summary"] += (
                    " No specific vulnerabilities identified by active checks."
                )
            if result["findings"].get("error"):
                result["scan_summary"] += f" (Error: {result['findings']['error']})"
            if result["findings"].get("warning"):
                result["scan_summary"] += f" (Warning: {result['findings']['warning']})"
            if result["findings"].get("informational"):
                result["scan_summary"] += (
                    f" (Informational: {len(result['findings']['informational'])})"
                )
            if result["findings"].get("error"):
                result["error"] = result["findings"]["error"]
            result["findings"]["raw_json_sample"] = str(parsed_json_data)[:500]
            return result
        except Exception as e:
            return {
                "tool_name": self.name,
                "status": "failure",
                "scan_summary": f"Nikto output parsing failed for {target_context}. Produced no output.",
                "error": str(e),
                "findings": {},
            }

    def execute(self, **kwargs) -> dict[str, Any]:
        if not self.executable_path:
            err_msg = (
                f"Tool '{self.name}' ({self.executable_name}) cannot be executed "
                f"because it was not found in PATH."
            )
            logger.error(err_msg)
            return {
                "scan_summary": f"{self.name.capitalize()} execution failed.",
                "error": err_msg,
                "findings": {},  # Ensure findings key
            }

        temp_json_path = None
        command_args_list = []  # Renamed from command_args to avoid confusion if needed
        command = None
        parsed_json_data = None
        stdout = None
        stderr = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w", delete=False, suffix=".json", encoding="utf-8"
            ) as tmpfile:
                temp_json_path = tmpfile.name

            command_args_list = self.build_command(
                temp_json_output_path=temp_json_path, **kwargs
            )
            command = [self.executable_path] + command_args_list

            # Removed unused target_display variable
            stdout, stderr = run_command(command)

            if temp_json_path and os.path.exists(temp_json_path):
                if os.path.getsize(temp_json_path) > 0:
                    try:
                        with open(temp_json_path, encoding="utf-8") as f:
                            parsed_json_data = json.load(f)
                        logger.debug(
                            f"Successfully read Nikto JSON output from {temp_json_path}"
                        )
                    except json.JSONDecodeError as json_err:
                        err_msg = f"Failed to decode Nikto JSON from {temp_json_path}: {json_err}"
                        logger.error(err_msg)
                        stderr = f"{stderr or ''}; {err_msg}".strip("; ")
                    except Exception as read_err:
                        err_msg = f"Failed to read Nikto JSON file {temp_json_path}: {read_err}"
                        logger.error(err_msg)
                        stderr = f"{stderr or ''}; {err_msg}".strip("; ")
                else:
                    warn_msg = f"Nikto created an empty JSON file: {temp_json_path}"
                    logger.warning(warn_msg)
                    if not stderr:
                        stderr = warn_msg
            elif not stderr:
                error_msg = f"Nikto completed but expected JSON file was not found: {temp_json_path}"
                logger.error(error_msg)
                stderr = error_msg

            parsed_results = self.parse_output(
                stdout, stderr, parsed_json_data=parsed_json_data, **kwargs
            )
            return parsed_results

        except (ValueError, FileNotFoundError, OSError) as e:
            err_msg = f"Error preparing/executing command for {self.name}: {e}"
            logger.error(err_msg)
            return {
                "scan_summary": f"{self.name.capitalize()} command prep/exec failed.",
                "error": err_msg,
                "findings": {},
            }
        except Exception as e:
            err_msg = f"Unexpected error during execution/parsing for {self.name}: {e}"
            logger.error(err_msg, exc_info=True)
            return {
                "scan_summary": f"{self.name.capitalize()} execution/parsing failed.",
                "error": err_msg,
                "raw_stdout": stdout[:500] if stdout else None,
                "raw_stderr": stderr[:500] if stderr else None,
                "findings": {},
            }
        finally:
            if temp_json_path and os.path.exists(temp_json_path):
                try:
                    os.remove(temp_json_path)
                    logger.debug(f"Removed temporary Nikto JSON file: {temp_json_path}")
                except OSError as e:
                    logger.warning(
                        f"Could not remove temporary Nikto JSON file {temp_json_path}: {e}"
                    )
