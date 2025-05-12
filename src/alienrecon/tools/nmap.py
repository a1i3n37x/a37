# alienrecon/tools/nmap.py
import logging
import shlex  # For safely splitting arguments string
import xml.etree.ElementTree as ET  # For parsing Nmap XML output
from typing import Any

# Import base class
from .base import CommandTool

# Try importing the python-nmap library specifically for parsing XML
try:
    import nmap
except ImportError:
    logging.warning(
        "python-nmap library not found. Nmap XML parsing will rely on "
        "basic XML parsing."
    )
    nmap = None  # Set to None if not available


class NmapTool(CommandTool):
    """
    Tool wrapper for executing Nmap scans and parsing results.
    Uses Nmap's XML output format (-oX -) for parsing.
    """

    name: str = "nmap"
    description: str = (
        "Performs network scans using Nmap to discover hosts and services."
    )
    executable_name: str = "nmap"  # Command-line executable

    def build_command(self, target: str, arguments: str = "-sV -T4") -> list[str]:
        """
        Constructs the Nmap command arguments, ensuring XML output to stdout.

        Args:
            target: The target IP address or hostname.
            arguments: User-provided Nmap arguments string
                       (e.g., "-sV -T4 -p 80,443").

        Returns:
            A list of strings for the Nmap command (excluding the executable itself).
        """
        if not target:
            raise ValueError("Target must be provided for Nmap scan.")

        # Safely split the arguments string provided by the user/LLM
        try:
            base_args = shlex.split(arguments)
        except ValueError as e:
            logging.error(f"Error splitting nmap arguments '{arguments}': {e}")
            # Fallback to basic split if shlex fails, or raise error
            base_args = arguments.split()  # Less safe fallback

        # Ensure XML output to stdout ('-oX -') is included
        # Remove existing -oX or -oA if present to avoid conflicts
        filtered_args = [arg for arg in base_args if not arg.startswith(("-oX", "-oA"))]

        # Add '-oX -' and the target
        command_args = filtered_args + ["-oX", "-", target]
        logging.debug(f"Built Nmap command args: {command_args}")
        return command_args

    def parse_output(
        self, stdout: str | None, stderr: str | None, **kwargs
    ) -> dict[str, Any]:
        """
        Parses Nmap XML output from stdout into a structured dictionary.

        Args:
            stdout: XML output from Nmap (-oX -), or None if execution failed badly.
            stderr: Error output from Nmap or run_command, or None if successful.
            **kwargs: Original arguments passed to execute (e.g., target, arguments).
                      Used here mainly for logging context if needed.

        Returns:
            A dictionary containing the parsed scan results or error information.
        """
        target_context = kwargs.get("target", "Unknown Target")
        args_context = kwargs.get("arguments", "Default Args")

        scan_summary = f"Nmap scan results for {target_context}:"
        results = {
            "hosts": [],
            "scan_arguments_used": args_context,
        }  # Initialize structure

        if stderr:
            scan_summary = (
                f"Nmap scan for {target_context} failed or completed with errors."
            )
            if nmap and stdout:
                logging.warning(
                    f"Nmap scan had errors, attempting to parse potential XML "
                    f"output. Target: {target_context}. Stderr: {stderr}"
                )
                # Pass stderr to helper for potential inclusion in results
                parsed_data = self._parse_with_python_nmap(
                    stdout, stderr, target_context=target_context
                )
                if parsed_data:
                    return parsed_data  # Return if parsing succeeded despite error

            # Fallback: return error directly
            return {"scan_summary": scan_summary, "error": stderr, "hosts": []}

        if not stdout:
            # No stdout, no stderr means unexpected or nmap produced no output
            return {
                "scan_summary": f"Nmap scan for {target_context} produced no output.",
                "error": "No standard output received from Nmap.",
                "hosts": [],
            }

        # --- Attempt to parse valid XML output ---
        if nmap:
            # Preferred method: Use python-nmap library
            parsed_data = self._parse_with_python_nmap(
                stdout, None, target_context=target_context
            )
            if parsed_data:
                return parsed_data
            # If _parse_with_python_nmap returns None, fall through to basic XML

        # Fallback method: Basic XML parsing
        logging.info(
            f"Parsing Nmap XML output for {target_context} using basic ElementTree."
        )
        try:
            root = ET.fromstring(stdout)
            results["scan_arguments_used"] = root.get("args", args_context)

            for host_node in root.findall("host"):
                ip_address_node = host_node.find("./address[@addrtype='ipv4']")
                if ip_address_node is None:
                    ip_address_node = host_node.find("./address[@addrtype='ipv6']")

                hostname_node = host_node.find("./hostnames/hostname")
                host_data = {
                    "host": ip_address_node.get("addr")
                    if ip_address_node is not None
                    else target_context,
                    "hostname": hostname_node.get("name")
                    if hostname_node is not None
                    else "N/A",
                    "status": host_node.find("status").get("state", "unknown"),
                    "open_ports": [],
                }

                ports_node = host_node.find("ports")
                if ports_node is not None:
                    for port_node in ports_node.findall("port"):
                        state_node = port_node.find("state")
                        if state_node is not None and state_node.get("state") == "open":
                            service_node = port_node.find("service")
                            port_info = {
                                "port": int(port_node.get("portid")),
                                "protocol": port_node.get("protocol"),
                                "service": service_node.get("name", "N/A")
                                if service_node is not None
                                else "N/A",
                                "version": service_node.get("version", "")
                                if service_node is not None
                                else "",
                                "product": service_node.get("product", "")
                                if service_node is not None
                                else "",
                                "extrainfo": service_node.get("extrainfo", "")
                                if service_node is not None
                                else "",
                            }
                            full_version = (
                                (
                                    f"{port_info['product']} {port_info['version']} "
                                    f"({port_info['extrainfo']})"
                                )
                                .strip()
                                .replace("()", "")
                            )
                            host_data["open_ports"].append(
                                {
                                    "port": port_info["port"],
                                    "protocol": port_info["protocol"],
                                    "service": port_info["service"],
                                    "version": full_version if full_version else "N/A",
                                }
                            )
                results["hosts"].append(host_data)

            if not results["hosts"]:
                scan_summary += " Scan completed, but no hosts found or host was down."
            else:
                scan_summary += f" Found {len(results['hosts'])} host(s)."

            return {"scan_summary": scan_summary, **results}

        except ET.ParseError as e:
            logging.error(
                f"Failed to parse Nmap XML output for {target_context}: {e}",
                exc_info=True,
            )
            return {
                "scan_summary": (
                    f"Nmap scan for {target_context} completed, but failed to "
                    f"parse XML output."
                ),
                "error": f"XML Parse Error: {e}",
                "raw_output_sample": stdout[:500],  # Include sample of bad XML
            }
        except Exception as e:  # Catch other unexpected parsing errors
            logging.error(
                f"Unexpected error parsing Nmap XML for {target_context}: {e}",
                exc_info=True,
            )
            return {
                "scan_summary": (
                    f"Nmap scan for {target_context} completed, but an unexpected "
                    f"error occurred during parsing."
                ),
                "error": str(e),
                "raw_output_sample": stdout[:500],
            }

    def _parse_with_python_nmap(
        self, xml_string: str, stderr: str | None, target_context: str
    ) -> dict[str, Any] | None:
        """Helper to parse Nmap XML using the python-nmap library."""
        if not nmap:
            return None

        logging.info(
            f"Attempting to parse Nmap XML for {target_context} using "
            f"python-nmap library."
        )
        try:
            nm_parser = nmap.PortScanner()
            scan_data = nm_parser.analyse_nmap_xml_scan(nmap_xml_output=xml_string)

            # Reuse old formatting logic, adapted for current nm object
            results = {
                "scan_summary": (
                    f"Nmap scan results for {target_context} (parsed via python-nmap):"
                ),
                "hosts": [],
            }
            # scan_info = scan_data.get("nmap", {}).get("scaninfo", {}) # F841 - unused
            scan_args = scan_data.get("nmap", {}).get("command_line", "N/A")
            results["scan_arguments_used"] = scan_args

            scan_results = scan_data.get("scan", {})
            if not scan_results:
                summary = (
                    f"Nmap scan for {target_context} completed but yielded no "
                    f"host results (parsed via python-nmap)."
                )
                scan_stats = scan_data.get("nmap", {}).get("scanstats", {})
                if scan_stats.get("uphosts", "0") == "0":
                    summary += " Host may be down."
                results["scan_summary"] = summary
                if stderr:
                    results["warning"] = f"Scan stderr reported: {stderr}"
                return results

            for host, host_data_dict in scan_results.items():
                if not isinstance(host_data_dict, dict):
                    logging.warning(
                        f"Unexpected data type for host '{host}' in python-nmap "
                        f"parsed results: {type(host_data_dict)}. Skipping host."
                    )
                    continue

                host_info = {
                    "host": host,
                    "hostname": host_data_dict.get("hostnames", [{}])[0].get(
                        "name", "N/A"
                    ),
                    "status": host_data_dict.get("status", {}).get("state", "unknown"),
                    "open_ports": [],
                }
                if host_info["status"] == "up":
                    for proto in ["tcp", "udp", "sctp", "ip"]:
                        proto_data = host_data_dict.get(proto)
                        if isinstance(proto_data, dict):
                            for port_str, port_info_dict in proto_data.items():
                                try:
                                    port_num = int(port_str)
                                    state = port_info_dict.get("state", "unknown")
                                    if state == "open":
                                        service = port_info_dict.get("name", "")
                                        version = port_info_dict.get("version", "")
                                        product = port_info_dict.get("product", "")
                                        extrainfo = port_info_dict.get("extrainfo", "")
                                        full_version = (
                                            (f"{product} {version} ({extrainfo})")
                                            .strip()
                                            .replace("()", "")
                                        )
                                        host_info["open_ports"].append(
                                            {
                                                "port": port_num,
                                                "protocol": proto,
                                                "service": service,
                                                "version": full_version
                                                if full_version
                                                else "N/A",
                                            }
                                        )
                                except (ValueError, TypeError) as e:
                                    logging.warning(
                                        f"Error processing port '{port_str}' for "
                                        f"host {host} protocol {proto}: {e}"
                                    )
                results["hosts"].append(host_info)

            if stderr:
                results["scan_summary"] += " Scan completed with warnings."
                results["warning"] = f"Scan stderr reported: {stderr}"

            return results

        except Exception as e:
            logging.error(
                f"python-nmap failed to parse XML for {target_context}: {e}",
                exc_info=True,
            )
            return None
