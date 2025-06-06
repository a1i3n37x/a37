# src/alienrecon/core/refactored_session_controller.py
"""Refactored SessionController using modular architecture."""

import logging
from typing import Any, Optional

from openai.types.chat.chat_completion_message import ChatCompletionMessage
from openai.types.chat.chat_completion_message_tool_call import (
    ChatCompletionMessageToolCall,
)

from ..tools.llm_functions import LLM_TOOL_FUNCTIONS, _set_session_controller
from .agent import get_llm_response
from .cache import ResultCache
from .config import initialize_openai_client
from .exceptions import ConfigurationError
from .interaction_handler import InteractionHandler
from .plan_executor import PlanExecutor
from .session_manager import SessionManager
from .tool_orchestrator import ToolOrchestrator

logger = logging.getLogger(__name__)


class RefactoredSessionController:
    """Refactored session controller with modular architecture."""

    def __init__(self, session_file: Optional[str] = None):
        """Initialize the session controller with dependency injection."""
        self.interaction = InteractionHandler()

        try:
            self.openai_client = initialize_openai_client()
        except Exception as e:
            self.interaction.display_error(f"Failed to initialize OpenAI client: {e}")
            logger.critical(f"OpenAI initialization failed: {e}", exc_info=True)
            raise ConfigurationError(f"OpenAI initialization failed: {e}")

        # Initialize core modules
        self.cache = ResultCache()
        self.session_manager = SessionManager(session_file)
        self.tool_orchestrator = ToolOrchestrator(self.cache)
        self.plan_executor = PlanExecutor(self.tool_orchestrator)

        # AI state
        self.pending_tool_call: Optional[ChatCompletionMessageToolCall] = None
        self.is_novice_mode: bool = True

        # Load existing session
        self.session_manager.load_session()

        # Set session controller reference for LLM functions
        _set_session_controller(self)

        logger.info("RefactoredSessionController initialized successfully")

    # Target Management
    def set_target(self, target_address: str) -> None:
        """Set the target for reconnaissance."""
        self.session_manager.set_target(target_address)
        self.session_manager.save_session()
        self.interaction.display_success(f"Target set to: {target_address}")

    def get_target(self) -> Optional[str]:
        """Get the current target."""
        return self.session_manager.get_target()

    # Session Management
    def save_session(self) -> None:
        """Save the current session."""
        self.session_manager.save_session()

    def display_session_status(self) -> None:
        """Display current session status."""
        context = self.session_manager.get_context_summary()
        self.interaction.display_session_status(context)

    def clear_session(self) -> None:
        """Clear the current session."""
        self.session_manager.clear_session()
        self.cache.clear()
        self.plan_executor.current_plan = None
        self.interaction.display_success("Session cleared")

    # Tool Execution
    def execute_tool(
        self, tool_name: str, args: dict[str, Any], show_result: bool = True
    ) -> dict[str, Any]:
        """Execute a single tool."""
        result = self.tool_orchestrator.execute_tool(tool_name, args)

        if show_result:
            self.interaction.display_tool_result(tool_name, result)

        # Update session state with results
        self._update_session_from_result(tool_name, result)
        self.session_manager.save_session()

        return result

    async def execute_tools_parallel(
        self, tool_requests: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Execute multiple tools in parallel."""
        results = await self.tool_orchestrator.execute_tools_parallel(tool_requests)

        # Display results and update session
        for i, result in enumerate(results):
            tool_name = tool_requests[i].get("tool", "unknown")
            self.interaction.display_tool_result(tool_name, result)
            self._update_session_from_result(tool_name, result)

        self.session_manager.save_session()
        return results

    def _update_session_from_result(self, tool_name: str, result: dict[str, Any]) -> None:
        """Update session state based on tool results."""
        if not result.get("success"):
            return

        data = result.get("data", {})

        # Handle different tool types
        if tool_name == "nmap" and "hosts" in data:
            for host in data["hosts"]:
                for port in host.get("ports", []):
                    self.session_manager.add_open_port(
                        port["port"],
                        port.get("service", ""),
                        port.get("version", "")
                    )

        elif tool_name == "ffuf" and "findings" in data:
            base_url = data.get("target_url", "")
            for finding in data["findings"]:
                url = f"{base_url}/{finding.get('path', '')}"
                self.session_manager.add_web_finding(url, "directory", finding)

        elif tool_name == "nikto" and "vulnerabilities" in data:
            url = data.get("target_url", "")
            self.session_manager.add_web_finding(url, "vulnerabilities", data["vulnerabilities"])

    # Plan Management
    def create_plan(
        self, name: str, description: str, steps: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Create a new reconnaissance plan."""
        plan = self.plan_executor.create_plan(name, description, steps)
        self.interaction.display_plan_summary(plan)

        # Save plan to session
        self.session_manager.current_plan = plan
        self.session_manager.save_session()

        return plan

    def execute_next_plan_step(self) -> bool:
        """Execute the next step in the current plan."""
        try:
            result = self.plan_executor.execute_next_step()
            if result:
                self.session_manager.save_session()
                return True
            return False
        except Exception as e:
            self.interaction.display_error(f"Plan execution failed: {e}")
            return False

    def get_plan_status(self) -> Optional[dict[str, Any]]:
        """Get current plan status."""
        return self.plan_executor.get_plan_status()

    # Interactive Sessions
    def start_interactive_session(self) -> None:
        """Start an interactive AI-guided reconnaissance session."""
        self.interaction.display_welcome(self.get_target())

        # Add initial system message to chat history
        self.session_manager.chat_history = [
            {"role": "system", "content": "You are an AI reconnaissance assistant."}
        ]

        while True:
            try:
                user_input = self.interaction.prompt_input("\n[cyan]You:[/cyan]")

                if user_input.lower() in ["exit", "quit", "q"]:
                    break

                self.handle_user_input(user_input)

            except KeyboardInterrupt:
                self.interaction.display_info("Session interrupted by user")
                break
            except Exception as e:
                self.interaction.display_error(f"Unexpected error: {e}")
                logger.error(f"Interactive session error: {e}", exc_info=True)

    def handle_user_input(self, user_input: str) -> None:
        """Handle user input and get AI response."""
        # Add user message to history
        self.session_manager.chat_history.append({
            "role": "user",
            "content": user_input
        })

        # Get AI response
        try:
            ai_message = self._get_ai_response()
            if ai_message:
                self._process_ai_message(ai_message)
        except Exception as e:
            self.interaction.display_error(f"AI response failed: {e}")
            logger.error(f"AI response error: {e}")

    def _get_ai_response(self) -> Optional[ChatCompletionMessage]:
        """Get response from AI agent."""
        try:
            context = self._build_context_for_ai()

            response = get_llm_response(
                self.openai_client,
                self.session_manager.chat_history,
                available_functions=LLM_TOOL_FUNCTIONS,
                context=context
            )

            return response
        except Exception as e:
            logger.error(f"Failed to get AI response: {e}")
            return None

    def _build_context_for_ai(self) -> str:
        """Build context string for AI."""
        target = self.get_target()
        context_parts = []

        if target:
            context_parts.append(f"Target: {target}")

        state = self.session_manager.state
        if state["open_ports"]:
            ports = [f"{p['port']}/{p['service']}" for p in state["open_ports"]]
            context_parts.append(f"Open ports: {', '.join(ports)}")

        if state["discovered_subdomains"]:
            context_parts.append(f"Subdomains: {len(state['discovered_subdomains'])}")

        if state["web_findings"]:
            context_parts.append(f"Web findings: {len(state['web_findings'])}")

        return " | ".join(context_parts) if context_parts else "No context available"

    def _process_ai_message(self, ai_message: ChatCompletionMessage) -> None:
        """Process AI message and handle tool calls."""
        # Add AI message to history
        self.session_manager.chat_history.append(ai_message.model_dump())

        # Display AI message if it has content
        if ai_message.content:
            self.interaction.display_ai_message(ai_message.content)

        # Handle tool calls
        if ai_message.tool_calls:
            for tool_call in ai_message.tool_calls:
                self.pending_tool_call = tool_call

                # Confirm and execute tool
                if self._confirm_and_execute_tool_call():
                    self.interaction.display_success("Tool executed successfully")
                else:
                    self.interaction.display_warning("Tool execution cancelled or failed")

    def _confirm_and_execute_tool_call(self) -> bool:
        """Confirm and execute a tool call."""
        if not self.pending_tool_call:
            return False

        tool_call = self.pending_tool_call
        function_name = tool_call.function.name

        # Show tool proposal
        self.interaction.display_info(f"Proposed tool: {function_name}")

        # Get confirmation
        if not self.interaction.prompt_confirmation("Execute this tool?", default=True):
            self.pending_tool_call = None
            return False

        try:
            # Execute the tool via LLM functions
            import json
            args = json.loads(tool_call.function.arguments)

            if function_name in LLM_TOOL_FUNCTIONS:
                result = LLM_TOOL_FUNCTIONS[function_name](**args)

                # Add result to chat history
                self.session_manager.chat_history.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(result)
                })

                self.pending_tool_call = None
                self.session_manager.save_session()
                return True
            else:
                self.interaction.display_error(f"Unknown function: {function_name}")
                return False

        except Exception as e:
            self.interaction.display_error(f"Tool execution failed: {e}")
            logger.error(f"Tool execution error: {e}")
            return False

    # Quick Recon
    def execute_quick_recon(self) -> None:
        """Execute a quick reconnaissance sequence."""
        target = self.get_target()
        if not target:
            self.interaction.display_error("No target set. Use set_target() first.")
            return

        # Create a quick recon plan
        steps = [
            {
                "tool": "nmap",
                "args": {"target": target, "scan_type": "quick"},
                "description": "Quick port scan"
            },
            {
                "tool": "nmap",
                "args": {"target": target, "scan_type": "service"},
                "description": "Service detection on open ports",
                "conditions": {"if_previous_success": True}
            }
        ]

        self.create_plan("Quick Recon", "Automated quick reconnaissance", steps)

        # Execute all steps
        while self.plan_executor.current_plan and \
              self.plan_executor.current_plan["status"] == "pending":
            if not self.execute_next_plan_step():
                break

    # CTF Context
    def set_ctf_context(self, metadata: dict[str, Any], box_identifier: str) -> None:
        """Set CTF context for the session."""
        self.session_manager.set_ctf_context(metadata, box_identifier)
        self.session_manager.save_session()
        self.interaction.display_success(f"CTF context set for: {box_identifier}")

    # Utility Methods
    def get_available_tools(self) -> list[str]:
        """Get list of available tools."""
        return self.tool_orchestrator.get_available_tools()

    def set_novice_mode(self, novice: bool) -> None:
        """Set novice mode for detailed explanations."""
        self.is_novice_mode = novice
        logger.info(f"Novice mode set to: {novice}")
