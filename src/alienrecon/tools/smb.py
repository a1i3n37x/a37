# alienrecon/tools/smb.py
import json
import logging
import os
import shlex
import tempfile
from typing import Any, Union  # Added Union for type hint

# Ensure this path is correct if config.py is in alienrecon/core/
from ..core.config import console
from ..core.types import ToolResult

# Import base class and utilities
from .base import CommandTool, run_command


class SmbTool(CommandTool):
    """
    Tool wrapper for executing SMB enumeration using enum4linux-ng.
    Uses enum4linux-ng's JSON output feature.
    """

    name: str = "smb_enum"
    description: str = (
        "Performs SMB enumeration (shares, users, policies, etc.) using enum4linux-ng."
    )
    executable_name: str = "enum4linux-ng"

    DEFAULT_ARGS = "-A"

    def build_command(
        self,
        target: str,
        enum_arguments: str | None = None,
        temp_file_base: str = None,
    ) -> list[str]:
        if not target:
            raise ValueError("Target must be provided for enum4linux-ng.")
        if not temp_file_base:
            raise ValueError(
                "Temporary file base path must be provided for JSON output."
            )

        args_to_use = enum_arguments or self.DEFAULT_ARGS
        if not args_to_use.strip():
            args_to_use = self.DEFAULT_ARGS
            logging.warning(
                "Empty enum4linux-ng arguments provided, using default '-A'."
            )
        try:
            base_args = shlex.split(args_to_use)
        except ValueError as e:
            logging.error(
                f"Error splitting enum4linux-ng arguments '{args_to_use}': {e}. "
                f"Using default '-A'."
            )
            base_args = shlex.split(self.DEFAULT_ARGS)

        filtered_args = [arg for arg in base_args if not arg.startswith(("-oJ", "-oA"))]
        command_args = filtered_args + ["-oJ", temp_file_base, target]
        logging.debug(f"Built enum4linux-ng command args: {command_args}")
        return command_args

    def _parse_data_item(
        self, data_item: Union[list, dict, None], max_items: int
    ) -> tuple[list[dict[str, Any]], bool, int]:
        """
        Helper to parse an item that could be a list or a dict (or other types)
        from enum4linux-ng JSON output, limiting the number of returned elements.
        """
        result_list = []
        original_count = 0
        truncated = False

        if isinstance(data_item, list):
            original_count = len(data_item)
            for item in data_item[:max_items]:
                if isinstance(item, dict):
                    result_list.append(item)
                elif isinstance(item, str):  # e.g. simple list of usernames
                    result_list.append(
                        {"name": item}
                    )  # Convert to dict for consistency
                else:  # Other non-dict items in a list
                    result_list.append({"raw_data": item})
            if original_count > max_items:
                truncated = True
        elif isinstance(data_item, dict):
            # If it's a dictionary, we might want to convert its items to a list of dicts
            # The structure of this dict can vary (e.g., users by RID, shares by name)
            # For simplicity, we'll try to make each entry a dict.
            # This part may need further refinement based on actual JSON structures.
            original_count = len(data_item)
            items_processed = 0
            for key, value in data_item.items():
                if items_processed >= max_items:
                    truncated = True
                    break
                if isinstance(value, dict):
                    # If value is a dict, try to add 'name' or 'id' field from key
                    entry = value.copy()
                    if "name" not in entry and "id" not in entry:  # Avoid overwriting
                        entry["id_or_key"] = key
                    result_list.append(entry)
                elif isinstance(value, str):
                    result_list.append({"id_or_key": key, "value": value})
                else:
                    result_list.append({"id_or_key": key, "raw_value": value})
                items_processed += 1
        elif data_item is not None:  # Some other unexpected type
            logging.warning(
                f"Data item expected to be list or dict, got {type(data_item)}. "
                "Storing as raw."
            )
            result_list.append({"raw_data_item": data_item})
            original_count = 1

        return result_list, truncated, original_count

    def parse_output(
        self,
        stdout: str | None,
        stderr: str | None,
        parsed_json_data: dict[str, Any] | None = None,
        **kwargs,
    ) -> ToolResult:
        target_context = kwargs.get("target", "Unknown Target")
        scan_summary = f"SMB Enumeration (enum4linux-ng) results for {target_context}:"
        result: ToolResult = {
            "tool_name": self.name,
            "status": "success",
            "scan_summary": scan_summary,
            "findings": {},
        }
        if stderr and not parsed_json_data:
            result["status"] = "failure"
            result["scan_summary"] = (
                f"Enum4linux-ng scan for {target_context} failed or produced no output."
            )
            result["error"] = (
                stderr.strip()
                if stderr
                else "Unknown execution error. Produced no output."
            )
            if stdout:
                result["raw_stdout"] = stdout[:5000]
            if stderr:
                result["raw_stderr"] = stderr[:5000]
            return result
        if not parsed_json_data:
            result["status"] = "failure"
            result["scan_summary"] = (
                f"Enum4linux-ng ran but produced no output for {target_context}."
            )
            result["error"] = "No JSON data returned. Produced no output."
            return result
        try:
            data = parsed_json_data

            findings = {
                "summary": {},
                "os_info": {},
                "users": [],
                "groups": [],
                "shares": [],
                "password_policy": {},
                "sessions": [],
                "printers": [],
                "domains": [],
                "misc": {},  # Added domains and misc for flexibility
            }
            max_list_items = 20

            findings["summary"]["rid_cycling_used"] = data.get(
                "rid_cycling_used", False
            )
            findings["summary"]["rpcclient_used"] = data.get("rpcclient_used", False)
            findings["summary"]["lookupsid_used"] = data.get("lookupsid_used", False)

            os_info_raw = data.get("osinfo", {})
            if isinstance(os_info_raw, dict):
                findings["os_info"]["os_version"] = os_info_raw.get("os_version_guess")
                findings["os_info"]["server_name"] = os_info_raw.get("server_name")
                findings["os_info"]["workgroup"] = os_info_raw.get("workgroup")
                findings["os_info"]["domain"] = os_info_raw.get(
                    "domain_name"
                )  # Common field
                findings["os_info"]["fqdn"] = os_info_raw.get("fqdn")
                findings["os_info"]["smb_negotiation"] = os_info_raw.get(
                    "smb_negotiation"
                )
            elif os_info_raw:
                findings["os_info"]["raw_os_info"] = str(os_info_raw)

            # Map keys from enum4linux-ng JSON to our findings structure
            # and parse them using the helper
            key_map = {
                "users": "users",
                "groups": "groups",  # Often local groups
                "domaingroups": "groups",  # Append domain groups to 'groups'
                "shares": "shares",
                "sessions": "sessions",
                "printers": "printers",
                "domains": "domains",  # if separate domain info is provided
            }

            for json_key, findings_key in key_map.items():
                data_item = data.get(json_key)
                parsed_items, truncated, count = self._parse_data_item(
                    data_item, max_list_items
                )

                if findings_key == "groups" and json_key == "domaingroups":  # Append
                    findings[findings_key].extend(parsed_items)
                else:
                    findings[findings_key] = parsed_items  # Overwrite/set

                if truncated:
                    findings["summary"][f"{findings_key}_truncated"] = (
                        f"True (showing up to {len(parsed_items)}/{count})"
                    )

            # Special handling for shares to filter out IPC$/ADMIN$ by default
            raw_shares = findings.get("shares", [])
            filtered_shares = []
            ignored_shares = [
                "IPC$",
                "ADMIN$",
            ]  # Common admin shares to ignore by default
            for share_info in raw_shares:
                share_name = share_info.get(
                    "name", share_info.get("id_or_key", "")
                ).upper()  # Check both possible keys
                if share_name not in ignored_shares:
                    filtered_shares.append(share_info)
            findings["shares"] = filtered_shares
            if len(raw_shares) > len(filtered_shares):
                findings["summary"]["shares_filtered"] = (
                    "True (filtered out common admin shares like IPC$, ADMIN$)"
                )

            # Password Policy
            pwpolicy_data = data.get("passwordpolicy", {})
            if isinstance(pwpolicy_data, dict) and pwpolicy_data:
                findings["password_policy"] = pwpolicy_data
            elif (
                pwpolicy_data
            ):  # if it's non-empty but not a dict (e.g., a string error message)
                findings["password_policy"] = {"raw_policy_data": str(pwpolicy_data)}

            # Other misc info if present
            if "netinfo" in data:
                findings["misc"]["netinfo"] = data["netinfo"]
            if "sidinfo" in data:
                findings["misc"]["sidinfo"] = data["sidinfo"]

            scan_summary += " Key findings extracted."
            if not any(
                findings[k]
                for k in ["users", "groups", "shares", "password_policy", "os_info"]
                if findings[k]
            ):
                scan_summary += " No detailed SMB information found or parsed."

            result["findings"] = findings
            result["scan_summary"] = scan_summary
            return result

        except Exception as e:
            return {
                "tool_name": self.name,
                "status": "failure",
                "scan_summary": f"Enum4linux-ng output parsing failed for {target_context}. Produced no output.",
                "error": str(e),
                "findings": {},
            }

    def execute(self, **kwargs) -> dict[str, Any]:
        if not self.executable_path:
            err_msg = (
                f"Tool '{self.name}' ({self.executable_name}) cannot be executed "
                f"because it was not found in PATH."
            )
            logging.error(err_msg)
            return {
                "scan_summary": f"{self.name.capitalize()} execution failed.",
                "error": err_msg,
                "findings": {},
            }

        temp_file_base = None
        expected_json_path = None
        command_args = []

        try:
            with tempfile.NamedTemporaryFile(
                mode="w", delete=False, suffix=".json"
            ) as tmpfile:
                full_temp_name = tmpfile.name
                temp_file_base = full_temp_name.replace(".json", "")
                expected_json_path = full_temp_name

            command_args = self.build_command(temp_file_base=temp_file_base, **kwargs)
            command = [self.executable_path] + command_args

        except (ValueError, FileNotFoundError) as e:
            err_msg = f"Error preparing command for {self.name}: {e}"
            logging.error(err_msg)
            return {
                "scan_summary": f"{self.name.capitalize()} command preparation failed.",
                "error": err_msg,
                "findings": {},
            }
        except Exception as e:
            err_msg = f"Unexpected error preparing command for {self.name}: {e}"
            logging.error(err_msg, exc_info=True)
            if expected_json_path and os.path.exists(expected_json_path):
                try:
                    os.remove(expected_json_path)
                except OSError as cleanup_err:
                    logging.warning(
                        f"Could not remove temp file {expected_json_path} "
                        f"after setup error: {cleanup_err}"
                    )
            return {
                "scan_summary": f"{self.name.capitalize()} command preparation failed.",
                "error": err_msg,
                "findings": {},
            }

        parsed_json_data = None
        stdout = None
        stderr = None

        try:
            target_display = kwargs.get("target", "unknown target")
            console.print(
                f"[yellow]Initiating {self.name} probe on {target_display} "
                f"(Args: {' '.join(command_args)})...[/yellow]"
            )
            stdout, stderr = run_command(command)

            if expected_json_path and os.path.exists(expected_json_path):
                if os.path.getsize(expected_json_path) > 0:
                    try:
                        with open(expected_json_path) as f:
                            parsed_json_data = json.load(f)
                        logging.info(
                            f"Successfully read JSON output from {expected_json_path}"
                        )
                    except json.JSONDecodeError as json_err:
                        err_msg = (
                            f"Failed to decode JSON from {expected_json_path}: "
                            f"{json_err}"
                        )
                        logging.error(err_msg)
                        stderr = f"{stderr or ''}; {err_msg}".strip("; ")
                    except Exception as read_err:
                        err_msg = (
                            f"Failed to read JSON file {expected_json_path}: {read_err}"
                        )
                        logging.error(err_msg)
                        stderr = f"{stderr or ''}; {err_msg}".strip("; ")
                else:  # Empty JSON file
                    warn_msg = (
                        f"Enum4linux-ng created an empty JSON file: "
                        f"{expected_json_path}"
                    )
                    logging.warning(warn_msg)
                    if not stderr:
                        stderr = warn_msg
            elif not stderr:  # File not found and no other error
                error_msg = (
                    f"Enum4linux-ng completed but expected JSON file was "
                    f"not found: {expected_json_path}"
                )
                logging.error(error_msg)
                stderr = error_msg

            parsed_results = self.parse_output(
                stdout, stderr, parsed_json_data=parsed_json_data, **kwargs
            )
            return parsed_results

        except Exception as e:
            err_msg = f"Unexpected error during {self.name} execution/parsing: {e}"
            logging.error(err_msg, exc_info=True)
            return {
                "scan_summary": f"{self.name.capitalize()} process failed.",
                "error": err_msg,
                "raw_stdout": stdout[:500] if stdout else None,
                "raw_stderr": stderr[:500] if stderr else None,
                "findings": {},
            }
        finally:
            if expected_json_path and os.path.exists(expected_json_path):
                try:
                    os.remove(expected_json_path)
                except OSError as e:
                    logging.warning(
                        f"Could not remove temp JSON {expected_json_path}: {e}"
                    )
            if temp_file_base and os.path.exists(
                temp_file_base
            ):  # Might be a dir if -oA used
                try:
                    if os.path.isfile(temp_file_base):
                        os.remove(temp_file_base)
                    # elif os.path.isdir(temp_file_base): shutil.rmtree(temp_file_base) # If -oA used
                except OSError as e:
                    if not os.path.isdir(
                        temp_file_base
                    ):  # Don't warn if it was a dir for -oA
                        logging.warning(
                            f"Could not remove temp base {temp_file_base}: {e}"
                        )
