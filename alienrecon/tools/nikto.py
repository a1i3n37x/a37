# alienrecon/tools/nikto.py
import os
import logging
import json
import tempfile
import shlex
from typing import Any, Dict, List, Optional

# Import base class and utilities
from .base import CommandTool, run_command
from ..config import console # Import console for potential direct printing

class NiktoTool(CommandTool):
    """
    Tool wrapper for executing Nikto web server vulnerability scans.
    Uses Nikto's JSON output format saved to a temporary file.
    """
    name: str = "nikto"
    description: str = "Performs web server vulnerability scanning using Nikto."
    executable_name: str = "nikto" # Command-line executable

    # Default Nikto settings
    DEFAULT_TUNING = "x" # Example: Tune for interesting files/configs

    def build_command(self, target: str, port: int, nikto_arguments: Optional[str] = None, temp_json_output_path: Optional[str] = None, **kwargs) -> List[str]:
        """
        Constructs the Nikto command arguments for JSON output to a file.

        Args:
            target: The target IP address or hostname.
            port: The target port number.
            nikto_arguments: Optional string of additional arguments provided by user/LLM.
            temp_json_output_path: Path to the temporary file for JSON output.
            **kwargs: Catches any other potential arguments (currently unused).

        Returns:
            A list of strings for the Nikto command (excluding the executable).

        Raises:
            ValueError: If target, port, or temp_json_output_path is missing.
        """
        if not target: raise ValueError("Target must be provided for Nikto.")
        if not port: raise ValueError("Port must be provided for Nikto.")
        if not temp_json_output_path: raise ValueError("Temporary JSON output path must be provided.")

        # Base command arguments for JSON output
        command_args = [
            "-h", target,
            "-p", str(port),
            "-Format", "json", # <<< Request JSON format
            "-o", temp_json_output_path, # <<< Output to temp file
            "-Tuning", self.DEFAULT_TUNING, # Apply default tuning
            "-nointeractive", # Ensure no interactive prompts
            "-ask", "no" # Disable auto-yes to prompts
        ]

        # Add extra arguments if provided, splitting safely
        if nikto_arguments:
            try:
                extra_args = shlex.split(nikto_arguments)
                # Prevent overriding core/output args
                safe_extra_args = [arg for arg in extra_args if not arg.startswith(('-h', '-p', '-Format', '-o', '-Save', '-ask', '-nointeractive'))]
                if len(safe_extra_args) != len(extra_args):
                     logging.warning(f"Filtered potentially conflicting arguments from Nikto args: '{nikto_arguments}'")
                command_args.extend(safe_extra_args)
            except ValueError as e:
                logging.error(f"Error splitting nikto arguments '{nikto_arguments}': {e}. Ignoring extra args.")

        logging.debug(f"Built Nikto command args: {command_args}")
        return command_args

    def parse_output(self, stdout: Optional[str], stderr: Optional[str], parsed_json_data: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
        """
        Parses the JSON data obtained from Nikto's output file.

        Args:
            stdout: Raw standard output from Nikto execution (may contain progress/errors).
            stderr: Standard error output from Nikto or run_command.
            parsed_json_data: The dictionary loaded from the Nikto JSON output file.
            **kwargs: Original arguments (target, port) for context.

        Returns:
            A dictionary containing the parsed scan results or error information.
        """
        target_context = f"{kwargs.get('target', 'Unknown')}:{kwargs.get('port', 'N/A')}"
        scan_summary = f"Nikto scan results for {target_context}:"
        # Structure for findings based on typical Nikto JSON fields
        findings = {
            "host_info": {},
            "vulnerabilities": [],
            "informational": [], # Use this for non-critical findings if needed
            "error": None,
            "warning": None,
        }
        limit_per_type = 50 # Max items per category for LLM context
        vuln_count = 0
        truncated = False

        # Case 1: Significant execution error (stderr present, no JSON data)
        if stderr and not parsed_json_data:
            scan_summary = f"Nikto scan for {target_context} failed or produced no usable output."
            findings["error"] = stderr.strip()
            # Add stdout sample if it contains potentially useful error info
            if stdout and "error" in stdout.lower():
                findings["error"] += f"\nStdout sample: {stdout[:200]}"
            return {"scan_summary": scan_summary, "findings": findings}

        # Case 2: Execution completed, but potentially with warnings or errors in stderr
        if stderr:
            scan_summary += " Scan completed with potential warnings/errors."
            findings["warning"] = f"Scan stderr reported: {stderr.strip()}"

        # Case 3: No JSON data even if stderr is empty
        if not parsed_json_data:
            error_msg = "Nikto ran but produced no JSON data."
            if not stderr: # If no stderr, this is the primary error
                findings["error"] = error_msg
                logging.warning(f"{error_msg} Target: {target_context}")
            # If stderr exists, it's already captured as a warning
            scan_summary += " No vulnerability data returned."
            return {"scan_summary": scan_summary, "findings": findings}

        # Case 4: Process the parsed JSON data
        try:
            # Nikto JSON structure usually has 'host', 'port', 'banner', 'vulnerabilities'
            data = parsed_json_data
            findings["host_info"]["target_ip"] = data.get("ip")
            findings["host_info"]["target_host"] = data.get("host")
            findings["host_info"]["target_port"] = data.get("port")
            findings["host_info"]["banner"] = data.get("banner")

            # Process vulnerabilities list
            vulnerabilities_list = data.get("vulnerabilities", [])
            if isinstance(vulnerabilities_list, list):
                for item in vulnerabilities_list:
                    if vuln_count >= limit_per_type:
                        truncated = True
                        break
                    # Extract key info - structure can vary slightly based on Nikto version/plugins
                    finding_detail = {
                        "id": item.get("id"), # OSVDB, BID etc.
                        "method": item.get("method"), # GET, POST etc.
                        "url": item.get("url"),
                        "description": item.get("msg"),
                        "references": item.get("references"), # Optional list/string
                        # Add other potentially useful fields if present
                        "test_id": item.get("testID"),
                        "namelink": item.get("namelink"),
                    }
                    findings["vulnerabilities"].append(finding_detail)
                    vuln_count += 1
            else:
                 logging.warning(f"Expected 'vulnerabilities' to be a list in Nikto JSON, got {type(vulnerabilities_list)}")
                 findings["warning"] = (findings.get("warning") or "") + "; Unexpected format for 'vulnerabilities' field."


            if findings["vulnerabilities"]:
                 scan_summary += f" Found {len(findings['vulnerabilities'])} potential findings."
            elif not findings["error"]: # No vulns found and no errors reported yet
                 scan_summary += " No specific vulnerabilities identified by active checks."

            if truncated:
                 scan_summary += f" (Vulnerability list limited to first {limit_per_type})."

        except Exception as e:
            logging.error(f"Error processing Nikto JSON data for {target_context}: {e}", exc_info=True)
            scan_summary += " (Error occurred during results processing)."
            findings["error"] = (findings.get("error") or "") + f"; JSON Processing Error: {str(e)}"
            findings["raw_json_sample"] = str(parsed_json_data)[:500] # Include sample on error

        # Final structure
        result_dict = {"scan_summary": scan_summary, "findings": findings}
        return result_dict


    def execute(self, **kwargs) -> Dict[str, Any]:
        """
        Executes Nikto, handles temporary JSON file creation/cleanup,
        and parses the JSON output. Overrides the base execute method.

        Args:
            **kwargs: Arguments expected by build_command (target, port, nikto_arguments).

        Returns:
            A dictionary containing the parsed results from parse_output.
        """
        if not self.executable_path:
            err_msg = f"Tool '{self.name}' ({self.executable_name}) cannot be executed because it was not found in PATH."
            logging.error(err_msg)
            return {"scan_summary": f"{self.name.capitalize()} execution failed.", "error": err_msg, "findings": {}} # Ensure findings key

        temp_json_path = None
        command_args = []

        try:
            # 1. Create a temporary file path safely
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".json", encoding='utf-8') as tmpfile:
                temp_json_path = tmpfile.name # Get the full path

            # 2. Build the command using the temporary path
            command_args = self.build_command(temp_json_output_path=temp_json_path, **kwargs)
            command = [self.executable_path] + command_args

        except (ValueError, FileNotFoundError, OSError) as e: # Catch specific errors during setup
            err_msg = f"Error preparing command for {self.name}: {e}"
            logging.error(err_msg)
            # Clean up temp file if it was created before the error
            if temp_json_path and os.path.exists(temp_json_path):
                 try: os.remove(temp_json_path)
                 except OSError as cleanup_err: logging.warning(f"Could not remove temp file {temp_json_path} after setup error: {cleanup_err}")
            return {"scan_summary": f"{self.name.capitalize()} command preparation failed.", "error": err_msg, "findings": {}}
        except Exception as e: # Catch unexpected errors
            err_msg = f"Unexpected error preparing command for {self.name}: {e}"
            logging.error(err_msg, exc_info=True)
            if temp_json_path and os.path.exists(temp_json_path):
                 try: os.remove(temp_json_path)
                 except OSError as cleanup_err: logging.warning(f"Could not remove temp file {temp_json_path} after setup error: {cleanup_err}")
            return {"scan_summary": f"{self.name.capitalize()} command preparation failed.", "error": err_msg, "findings": {}}

        parsed_json_data = None
        stdout = None
        stderr = None

        try:
            # 3. Run the command
            target_display = f"{kwargs.get('target', 'unknown')}:{kwargs.get('port', 'N/A')}"
            console.print(f"[yellow]Initiating {self.name} scan on {target_display} (Args: {' '.join(command_args)})...[/yellow]")
            stdout, stderr = run_command(command) # stderr contains error details if run failed

            # 4. Attempt to read the JSON output file
            if temp_json_path and os.path.exists(temp_json_path):
                if os.path.getsize(temp_json_path) > 0:
                    try:
                        with open(temp_json_path, 'r', encoding='utf-8') as f:
                            parsed_json_data = json.load(f)
                        logging.info(f"Successfully read Nikto JSON output from {temp_json_path}")
                    except json.JSONDecodeError as json_err:
                        err_msg = f"Failed to decode Nikto JSON from {temp_json_path}: {json_err}"
                        logging.error(err_msg)
                        # Append to stderr or make it the primary error
                        if not stderr: stderr = err_msg
                        else: stderr += f"; {err_msg}"
                    except Exception as read_err:
                        err_msg = f"Failed to read Nikto JSON file {temp_json_path}: {read_err}"
                        logging.error(err_msg)
                        if not stderr: stderr = err_msg
                        else: stderr += f"; {err_msg}"
                else:
                    warn_msg = f"Nikto created an empty JSON file: {temp_json_path}"
                    logging.warning(warn_msg)
                    # Treat as warning unless no other error reported
                    if not stderr: stderr = warn_msg # Promote to error
            elif not stderr: # File doesn't exist AND command didn't report error
                error_msg = f"Nikto completed but expected JSON file was not found: {temp_json_path}"
                logging.error(error_msg)
                stderr = error_msg # Make this the error

            # 5. Parse the results (pass the loaded JSON data)
            # Pass original kwargs for context
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
            # 6. Clean up temporary file
            if temp_json_path and os.path.exists(temp_json_path):
                try:
                    os.remove(temp_json_path)
                    logging.debug(f"Removed temporary Nikto JSON file: {temp_json_path}")
                except OSError as e:
                    logging.warning(f"Could not remove temporary Nikto JSON file {temp_json_path}: {e}")
