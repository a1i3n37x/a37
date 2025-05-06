# alienrecon/tools/smb.py
import os
import logging
import json
import tempfile
import shlex
from typing import Any, Dict, List, Tuple, Optional

# Import base class and utilities
from .base import CommandTool, run_command
from ..config import console, TOOL_PATHS # Import console and TOOL_PATHS

class SmbTool(CommandTool):
    """
    Tool wrapper for executing SMB enumeration using enum4linux-ng.
    Uses enum4linux-ng's JSON output feature.
    """
    name: str = "smb_enum"
    description: str = "Performs SMB enumeration (shares, users, policies, etc.) using enum4linux-ng."
    executable_name: str = "enum4linux-ng" # Command-line executable

    # Default arguments for enum4linux-ng
    DEFAULT_ARGS = "-A" # "-A" means run all simple enumeration modules

    def build_command(self, target: str, enum_arguments: Optional[str] = None, temp_file_base: str = None) -> List[str]:
        """
        Constructs the enum4linux-ng command arguments, ensuring JSON output.

        Args:
            target: The target IP address or hostname.
            enum_arguments: User-provided enum4linux-ng arguments string (e.g., "-U -S").
                            Defaults to "-A" if None or empty.
            temp_file_base: The base path for the temporary JSON output file (without extension).

        Returns:
            A list of strings for the enum4linux-ng command (excluding the executable itself).

        Raises:
            ValueError: If target or temp_file_base is missing.
        """
        if not target:
            raise ValueError("Target must be provided for enum4linux-ng.")
        if not temp_file_base:
            raise ValueError("Temporary file base path must be provided for JSON output.")

        args_to_use = enum_arguments or self.DEFAULT_ARGS
        if not args_to_use.strip(): # Ensure arguments are not empty space
             args_to_use = self.DEFAULT_ARGS
             logging.warning("Empty enum4linux-ng arguments provided, using default '-A'.")

        # Safely split the arguments string
        try:
            base_args = shlex.split(args_to_use)
        except ValueError as e:
            logging.error(f"Error splitting enum4linux-ng arguments '{args_to_use}': {e}. Using default '-A'.")
            base_args = shlex.split(self.DEFAULT_ARGS) # Fallback to default on split error

        # Ensure JSON output ('-oJ') is included and target is last
        # Remove existing -oJ or -oA if present to avoid conflicts
        filtered_args = [arg for arg in base_args if not arg.startswith(('-oJ', '-oA'))] # -oA writes all formats, -oJ just JSON

        # Add '-oJ <temp_base>' and the target
        command_args = filtered_args + ['-oJ', temp_file_base, target]
        logging.debug(f"Built enum4linux-ng command args: {command_args}")
        return command_args

    def parse_output(self, stdout: Optional[str], stderr: Optional[str], parsed_json_data: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
        """
        Parses the JSON data obtained from enum4linux-ng's output file.

        Args:
            stdout: Raw standard output from enum4linux-ng (might be minimal with -oJ).
            stderr: Standard error output (contains execution errors or warnings).
            parsed_json_data: The dictionary loaded from the enum4linux-ng JSON output file.
            **kwargs: Original arguments passed to execute (target, enum_arguments).

        Returns:
            A dictionary containing the parsed scan results or error information.
        """
        target_context = kwargs.get('target', 'Unknown Target')
        scan_summary = f"SMB Enumeration (enum4linux-ng) results for {target_context}:"
        # Mimic structure of old format_smb_enum_results
        findings = {
            "summary": {}, "os_info": {}, "users": [], "groups": [], "shares": [],
            "password_policy": {}, "sessions": [], "printers": []
        }
        max_list_items = 20 # Limit list items in results

        # Case 1: Execution failed significantly (indicated by stderr and no JSON data)
        if stderr and not parsed_json_data:
            scan_summary = f"SMB Enumeration for {target_context} failed or produced no usable output."
            findings["error"] = stderr
            return {"scan_summary": scan_summary, "findings": findings}

        # Case 2: Execution completed, but there might be warnings in stderr
        if stderr:
            scan_summary += " Scan completed with potential warnings."
            # Include stderr as a warning in the findings summary
            findings["summary"]["warnings"] = stderr.strip()

        # Case 3: No JSON data returned even if stderr is empty (unexpected)
        if not parsed_json_data:
            if not stderr: # If stderr was also empty, something odd happened
                 error_msg = "Enum4linux-ng ran but produced no JSON data and no errors."
                 logging.warning(f"{error_msg} Target: {target_context}")
                 findings["error"] = error_msg
            # If stderr *was* present, it's already handled above.
            scan_summary += " No data returned from scan."
            return {"scan_summary": scan_summary, "findings": findings}

        # Case 4: We have JSON data, proceed with parsing
        try:
            data = parsed_json_data # Use the pre-parsed JSON

            # Extract summary flags
            findings["summary"]["rid_cycling_used"] = data.get("rid_cycling_used", False)
            findings["summary"]["rpcclient_used"] = data.get("rpcclient_used", False)

            # Extract OS Info
            os_info_raw = data.get("osinfo", {})
            if isinstance(os_info_raw, dict):
                findings["os_info"]["os_version"] = os_info_raw.get("os_version_guess")
                findings["os_info"]["server_name"] = os_info_raw.get("server_name")
                findings["os_info"]["workgroup"] = os_info_raw.get("workgroup")
                findings["os_info"]["smb_negotiation"] = os_info_raw.get("smb_negotiation")
            elif os_info_raw: # If present but not a dict
                 findings["os_info"]["raw_os_info"] = os_info_raw

            # Helper to extract and limit lists from the JSON data
            def extract_limited_list(key, max_items):
                raw_list = data.get(key)
                truncated = False
                result_list = []
                original_count = 0
                if isinstance(raw_list, list):
                    original_count = len(raw_list)
                    result_list = raw_list[:max_items]
                    if original_count > max_items:
                        truncated = True
                elif raw_list is not None: # Handle unexpected type
                    logging.warning(f"Expected '{key}' to be a list in enum4linux-ng JSON, got {type(raw_list)}. Storing raw.")
                    result_list = [{"raw_data": raw_list}] # Wrap in list/dict for consistency
                    original_count = 1 # Treat as one item
                return result_list, truncated, original_count

            # Extract Users, Groups, Sessions, Printers
            findings["users"], truncated, count = extract_limited_list("users", max_list_items)
            if truncated: findings["summary"]["users_truncated"] = f"True (showing {max_list_items}/{count})"
            findings["groups"], truncated, count = extract_limited_list("groups", max_list_items)
            if truncated: findings["summary"]["groups_truncated"] = f"True (showing {max_list_items}/{count})"
            findings["sessions"], truncated, count = extract_limited_list("sessions", max_list_items)
            if truncated: findings["summary"]["sessions_truncated"] = f"True (showing {max_list_items}/{count})"
            findings["printers"], truncated, count = extract_limited_list("printers", max_list_items)
            if truncated: findings["summary"]["printers_truncated"] = f"True (showing {max_list_items}/{count})"

            # Extract Shares (with filtering)
            all_shares, _, original_share_count = extract_limited_list("shares", max_list_items * 2) # Get more initially for filtering
            filtered_shares = []
            ignored_shares = ["IPC$", "ADMIN$"] # Common admin shares to ignore
            share_count = 0
            truncated_shares = False
            for share in all_shares:
                # Check if it's a dict and has a name not in the ignore list
                if isinstance(share, dict) and share.get("name") not in ignored_shares:
                    if share_count < max_list_items:
                        filtered_shares.append(share)
                        share_count += 1
                    else:
                        truncated_shares = True; break
                # Handle non-dict items if they occur, or include ignored shares if needed later
                elif not isinstance(share, dict) and share:
                     if share_count < max_list_items:
                          filtered_shares.append({"raw_share_data": share})
                          share_count += 1
                     else:
                          truncated_shares = True; break

            findings["shares"] = filtered_shares
            if truncated_shares or (original_share_count > len(filtered_shares) and not truncated_shares):
                findings["summary"]["shares_truncated_or_filtered"] = f"True (showing {len(filtered_shares)}/{original_share_count} total, filtered & limited)"

            # Extract Password Policy
            findings["password_policy"] = data.get("passwordpolicy", {})

            scan_summary += " Key findings extracted."

        except Exception as e:
            logging.error(f"Error processing enum4linux-ng JSON data for {target_context}: {e}", exc_info=True)
            scan_summary += " (Error occurred during results processing)."
            findings["processing_error"] = str(e)
            # Include a sample of the raw JSON if parsing failed
            findings["raw_data_sample"] = str(parsed_json_data)[:500] if parsed_json_data else "N/A"

        # Final structure
        result_dict = {"scan_summary": scan_summary, "findings": findings}
        return result_dict

    def execute(self, **kwargs) -> Dict[str, Any]:
        """
        Executes enum4linux-ng, handles temporary file creation/cleanup,
        and parses the JSON output. Overrides the base execute method.

        Args:
            **kwargs: Arguments expected by build_command (target, enum_arguments).

        Returns:
            A dictionary containing the parsed results from parse_output.
        """
        if not self.executable_path:
            err_msg = f"Tool '{self.name}' ({self.executable_name}) cannot be executed because it was not found in PATH."
            logging.error(err_msg)
            # Ensure findings key exists even on early failure
            return {"scan_summary": f"{self.name.capitalize()} execution failed.", "error": err_msg, "findings": {}}

        temp_file_base = None
        expected_json_path = None
        command_args = [] # Initialize in outer scope

        try:
            # 1. Create a temporary file base name safely
            # Use delete=False so we control deletion in the finally block
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".json") as tmpfile:
                full_temp_name = tmpfile.name
                # enum4linux-ng needs the base name (without .json) for -oJ
                temp_file_base = full_temp_name.replace(".json", "")
                expected_json_path = full_temp_name # Store the full path

            # 2. Build the command using the temporary base name
            command_args = self.build_command(temp_file_base=temp_file_base, **kwargs)
            command = [self.executable_path] + command_args

        except (ValueError, FileNotFoundError) as e: # Catch specific errors from build_command or tempfile issues
            err_msg = f"Error preparing command for {self.name}: {e}"
            logging.error(err_msg)
            return {"scan_summary": f"{self.name.capitalize()} command preparation failed.", "error": err_msg, "findings": {}}
        except Exception as e: # Catch unexpected errors during setup
            err_msg = f"Unexpected error preparing command for {self.name}: {e}"
            logging.error(err_msg, exc_info=True)
            # Clean up temp file if it was created before the error
            if expected_json_path and os.path.exists(expected_json_path):
                try: os.remove(expected_json_path)
                except OSError as cleanup_err: logging.warning(f"Could not remove temp file {expected_json_path} after setup error: {cleanup_err}")
            return {"scan_summary": f"{self.name.capitalize()} command preparation failed.", "error": err_msg, "findings": {}}

        parsed_json_data = None
        stdout = None
        stderr = None

        try:
            # 3. Run the command
            target_display = kwargs.get('target', 'unknown target')
            console.print(f"[yellow]Initiating {self.name} probe on {target_display} (Args: {' '.join(command_args)})...[/yellow]")
            # No spinner here to keep base execute simple, main loop handles status
            stdout, stderr = run_command(command) # stderr contains error details if run failed

            # 4. Attempt to read the JSON output file
            if expected_json_path and os.path.exists(expected_json_path):
                if os.path.getsize(expected_json_path) > 0:
                    try:
                        with open(expected_json_path, 'r') as f:
                            parsed_json_data = json.load(f)
                        logging.info(f"Successfully read JSON output from {expected_json_path}")
                    except json.JSONDecodeError as json_err:
                        err_msg = f"Failed to decode JSON from {expected_json_path}: {json_err}"
                        logging.error(err_msg)
                        # If run_command didn't report error, make this the primary error
                        if not stderr: stderr = err_msg
                        else: stderr += f"; {err_msg}" # Append error
                    except Exception as read_err:
                        err_msg = f"Failed to read JSON file {expected_json_path}: {read_err}"
                        logging.error(err_msg)
                        if not stderr: stderr = err_msg
                        else: stderr += f"; {err_msg}"
                else:
                    warn_msg = f"Enum4linux-ng created an empty JSON file: {expected_json_path}"
                    logging.warning(warn_msg)
                    # Treat as warning unless stderr is also empty
                    if not stderr: stderr = warn_msg # Promote to error if no other error occurred
            else:
                # If the command didn't fail catastrophically but the file is missing
                if not stderr:
                    error_msg = f"Enum4linux-ng completed but expected JSON file was not found: {expected_json_path}"
                    logging.error(error_msg)
                    stderr = error_msg # Make this the error

            # 5. Parse the results (pass the loaded JSON data)
            # Pass original kwargs for context like target
            parsed_results = self.parse_output(stdout, stderr, parsed_json_data=parsed_json_data, **kwargs)
            return parsed_results

        except Exception as e:
            # Catch unexpected errors during execution or parsing call
            err_msg = f"Unexpected error during execution/parsing for {self.name}: {e}"
            logging.error(err_msg, exc_info=True)
            return {
                "scan_summary": f"{self.name.capitalize()} execution/parsing failed.",
                "error": err_msg,
                "raw_stdout": stdout[:500] if stdout else None,
                "raw_stderr": stderr[:500] if stderr else None,
                "findings": {} # Ensure findings key exists
            }
        finally:
            # 6. Clean up temporary files
            if expected_json_path and os.path.exists(expected_json_path):
                try:
                    os.remove(expected_json_path)
                    logging.debug(f"Removed temporary JSON file: {expected_json_path}")
                except OSError as e:
                    logging.warning(f"Could not remove temporary JSON file {expected_json_path}: {e}")
            # enum4linux-ng might create other files based on the base name, attempt removal if base exists
            if temp_file_base and os.path.exists(temp_file_base):
                 try:
                     os.remove(temp_file_base)
                     logging.debug(f"Removed temporary base file: {temp_file_base}")
                 except OSError as e:
                     # This might fail if it's a directory, which is fine
                     if not os.path.isdir(temp_file_base):
                          logging.warning(f"Could not remove temporary base file {temp_file_base}: {e}")
