# src/alienrecon/core/session_manager.py
"""Session state management for Alien Recon."""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .exceptions import SessionError
from .input_validator import InputValidator

logger = logging.getLogger(__name__)


class SessionManager:
    """Manages session state persistence and retrieval."""

    SESSION_FILE = ".alienrecon_session.json"

    def __init__(self, session_file: Optional[str] = None):
        self.session_file = session_file or self.SESSION_FILE
        self.state: dict[str, Any] = self._get_default_state()
        self.chat_history: list[dict[str, Any]] = []
        self.task_queue: list[dict] = []
        self.current_plan: Optional[dict] = None
        self.plan_history: list[dict] = []

    def _get_default_state(self) -> dict[str, Any]:
        """Get default session state."""
        return {
            "target_ip": None,
            "target_hostname": None,
            "open_ports": [],  # List of {"port": int, "service": str, "version": str}
            "discovered_subdomains": [],
            "web_findings": {},  # E.g. {"http://target:port/path": {"tech": [], "interesting_files": []}}
            "active_ctf_context": None,  # CTF box metadata and context
            "session_created": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat(),
        }

    def save_session(self) -> None:
        """Save current session state to file."""
        try:
            session_data = {
                "state": self.state,
                "chat_history": self.chat_history,
                "task_queue": self.task_queue,
                "current_plan": self.current_plan,
                "plan_history": self.plan_history,
                "last_updated": datetime.now().isoformat(),
            }

            # Update last_updated in state
            self.state["last_updated"] = session_data["last_updated"]

            # Write to temporary file first
            temp_file = f"{self.session_file}.tmp"
            with open(temp_file, "w") as f:
                json.dump(session_data, f, indent=2)

            # Atomic rename
            os.replace(temp_file, self.session_file)

            logger.info(f"Session saved to {self.session_file}")
        except Exception as e:
            logger.error(f"Failed to save session: {e}")
            raise SessionError(f"Failed to save session: {e}")

    def load_session(self) -> bool:
        """Load session state from file. Returns True if loaded successfully."""
        try:
            session_path = Path(self.session_file)
            if not session_path.exists():
                logger.info("No existing session found")
                return False

            with open(session_path) as f:
                session_data = json.load(f)

            # Validate and load session data
            self.state = session_data.get("state", self._get_default_state())
            self.chat_history = session_data.get("chat_history", [])
            self.task_queue = session_data.get("task_queue", [])
            self.current_plan = session_data.get("current_plan", None)
            self.plan_history = session_data.get("plan_history", [])

            logger.info(f"Session loaded from {self.session_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to load session: {e}")
            return False

    def clear_session(self) -> None:
        """Clear current session and reset to defaults."""
        self.state = self._get_default_state()
        self.chat_history = []
        self.task_queue = []
        self.current_plan = None
        self.plan_history = []

        # Remove session file if it exists
        try:
            if os.path.exists(self.session_file):
                os.remove(self.session_file)
                logger.info(f"Session file {self.session_file} removed")
        except Exception as e:
            logger.error(f"Failed to remove session file: {e}")

    def set_target(self, target_address: str) -> None:
        """Set the target for the session."""
        # Validate target
        validated_target = InputValidator.validate_target(target_address)

        # Update state
        self.state["target_ip"] = validated_target
        self.state["target_hostname"] = target_address if target_address != validated_target else None
        self.state["last_updated"] = datetime.now().isoformat()

        logger.info(f"Target set to: {validated_target}")

    def get_target(self) -> Optional[str]:
        """Get the current target."""
        return self.state.get("target_ip") or self.state.get("target_hostname")

    def add_open_port(self, port: int, service: str = "", version: str = "") -> None:
        """Add an open port to the session state."""
        port_info = {"port": port, "service": service, "version": version}

        # Check if port already exists
        existing_ports = [p["port"] for p in self.state["open_ports"]]
        if port not in existing_ports:
            self.state["open_ports"].append(port_info)
            self.state["last_updated"] = datetime.now().isoformat()
            logger.info(f"Added open port: {port}")
        else:
            # Update existing port info
            for p in self.state["open_ports"]:
                if p["port"] == port:
                    p.update(port_info)
                    break
            self.state["last_updated"] = datetime.now().isoformat()
            logger.info(f"Updated port info: {port}")

    def add_subdomain(self, subdomain: str) -> None:
        """Add a discovered subdomain."""
        if subdomain not in self.state["discovered_subdomains"]:
            self.state["discovered_subdomains"].append(subdomain)
            self.state["last_updated"] = datetime.now().isoformat()
            logger.info(f"Added subdomain: {subdomain}")

    def add_web_finding(self, url: str, finding_type: str, data: Any) -> None:
        """Add a web finding."""
        if url not in self.state["web_findings"]:
            self.state["web_findings"][url] = {}

        if finding_type not in self.state["web_findings"][url]:
            self.state["web_findings"][url][finding_type] = []

        if isinstance(data, list):
            self.state["web_findings"][url][finding_type].extend(data)
        else:
            self.state["web_findings"][url][finding_type].append(data)

        self.state["last_updated"] = datetime.now().isoformat()
        logger.info(f"Added web finding for {url}: {finding_type}")

    def set_ctf_context(self, metadata: dict[str, Any], box_identifier: str) -> None:
        """Set CTF context for the session."""
        self.state["active_ctf_context"] = {
            "box_identifier": box_identifier,
            "metadata": metadata,
            "start_time": datetime.now().isoformat(),
        }
        self.state["last_updated"] = datetime.now().isoformat()
        logger.info(f"CTF context set for box: {box_identifier}")

    def get_context_summary(self) -> dict[str, Any]:
        """Get a summary of the current session context."""
        return {
            "target": self.get_target(),
            "open_ports": len(self.state["open_ports"]),
            "discovered_subdomains": len(self.state["discovered_subdomains"]),
            "web_findings": len(self.state["web_findings"]),
            "has_ctf_context": self.state["active_ctf_context"] is not None,
            "task_queue_size": len(self.task_queue),
            "has_active_plan": self.current_plan is not None,
        }

    def export_session(self, output_path: str) -> None:
        """Export session data to a file."""
        try:
            export_data = {
                "session": {
                    "state": self.state,
                    "task_queue": self.task_queue,
                    "plan_history": self.plan_history,
                },
                "exported_at": datetime.now().isoformat(),
            }

            with open(output_path, "w") as f:
                json.dump(export_data, f, indent=2)

            logger.info(f"Session exported to {output_path}")
        except Exception as e:
            raise SessionError(f"Failed to export session: {e}")
