# src/alienrecon/tools/searchsploit.py
"""Searchsploit tool wrapper for exploit database searches."""

import json
import logging
import re
from typing import Any

from ..core.types import ToolResult
from .base import CommandTool

logger = logging.getLogger(__name__)


class SearchsploitTool(CommandTool):
    """Tool for searching exploit database with searchsploit."""

    name = "Searchsploit"
    description = "Search for exploits in the Exploit Database"
    executable_name = "searchsploit"

    def build_command(self, query: str, **kwargs) -> list[str]:
        """Build searchsploit command."""
        if not query and not kwargs.get("cve") and not kwargs.get("edb_id"):
            raise ValueError("Query parameter is required for searchsploit")

        # Build base command
        command = []

        # Add JSON output flag first if needed
        if kwargs.get("json", True):  # Default to JSON output
            command.append("--json")

        # Add search modifiers
        if kwargs.get("exact", False):
            command.append("--exact")

        # Handle different search types
        if kwargs.get("cve"):
            command.extend(["--cve", str(kwargs["cve"])])
        elif kwargs.get("edb_id"):
            # For examining specific exploit by ID, use -p
            command.extend(["-p", str(kwargs["edb_id"])])
        else:
            # Split the query into individual terms
            command.extend(query.split())

        # Note: searchsploit doesn't have a --max option
        # Results will need to be limited in post-processing

        return command

    def parse_output(self, stdout: str, stderr: str, **kwargs) -> ToolResult:
        """Parse searchsploit output."""
        if stderr and "not found" in stderr.lower():
            return {
                "tool_name": self.name,
                "status": "failure",
                "scan_summary": "Searchsploit not found. Please install exploitdb package.",
                "error": stderr,
                "findings": [],
            }

        if not stdout:
            return {
                "tool_name": self.name,
                "status": "success",
                "scan_summary": "No exploits found for the given query.",
                "findings": [],
            }

        try:
            # Try to parse JSON output
            if stdout.strip().startswith('[') or stdout.strip().startswith('{'):
                exploits = self._parse_json_output(stdout)
            else:
                # Fallback to text parsing
                exploits = self._parse_text_output(stdout)

            if not exploits:
                return {
                    "tool_name": self.name,
                    "status": "success",
                    "scan_summary": "No exploits found for the given query.",
                    "findings": [],
                }

            # Limit results if max_results is specified
            max_results = kwargs.get("max_results", 20)
            if max_results and len(exploits) > max_results:
                exploits = exploits[:max_results]

            # Build summary
            summary = f"Found {len(exploits)} potential exploit(s)"
            if exploits:
                platforms = set(exploit.get("platform", "Unknown") for exploit in exploits)
                summary += f" for platforms: {', '.join(platforms)}"

            return {
                "tool_name": self.name,
                "status": "success",
                "scan_summary": summary,
                "findings": exploits,
                "query": kwargs.get("query", ""),
            }

        except Exception as e:
            logger.error(f"Error parsing searchsploit output: {e}")
            return {
                "tool_name": self.name,
                "status": "failure",
                "scan_summary": "Failed to parse searchsploit output",
                "error": str(e),
                "findings": [],
                "raw_stdout": stdout[:1000] if stdout else None,
            }

    def _parse_json_output(self, stdout: str) -> list[dict[str, Any]]:
        """Parse JSON output from searchsploit."""
        try:
            data = json.loads(stdout)

            # Handle different JSON structures
            if isinstance(data, dict) and "RESULTS_EXPLOIT" in data:
                # Standard searchsploit JSON format
                exploits = data["RESULTS_EXPLOIT"]
            elif isinstance(data, list):
                # Direct list format
                exploits = data
            else:
                logger.warning(f"Unexpected JSON structure: {type(data)}")
                return []

            parsed_exploits = []
            for exploit in exploits:
                parsed_exploit = {
                    "title": exploit.get("Title", "Unknown"),
                    "date": exploit.get("Date", "Unknown"),
                    "platform": exploit.get("Platform", "Unknown"),
                    "type": exploit.get("Type", "Unknown"),
                    "path": exploit.get("Path", ""),
                    "edb_id": exploit.get("EDB-ID", ""),
                }

                # Extract CVE if present in title
                cve_match = re.search(r'CVE-\d{4}-\d{4,}', parsed_exploit["title"])
                if cve_match:
                    parsed_exploit["cve"] = cve_match.group(0)

                parsed_exploits.append(parsed_exploit)

            return parsed_exploits

        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            return []

    def _parse_text_output(self, stdout: str) -> list[dict[str, Any]]:
        """Parse text output from searchsploit (fallback)."""
        exploits = []
        lines = stdout.strip().split('\n')

        # Skip header lines
        for line in lines:
            if '---' in line or 'Exploit Title' in line or 'Path' in line:
                continue

            line = line.strip()
            if not line:
                continue

            # Try to parse the line format: Title | Date | Platform | Type | Path
            parts = [part.strip() for part in line.split('|')]
            if len(parts) >= 4:
                exploit = {
                    "title": parts[0],
                    "date": parts[1] if len(parts) > 1 else "Unknown",
                    "platform": parts[2] if len(parts) > 2 else "Unknown",
                    "type": parts[3] if len(parts) > 3 else "Unknown",
                    "path": parts[4] if len(parts) > 4 else "",
                }

                # Extract CVE if present
                cve_match = re.search(r'CVE-\d{4}-\d{4,}', exploit["title"])
                if cve_match:
                    exploit["cve"] = cve_match.group(0)

                exploits.append(exploit)

        return exploits


