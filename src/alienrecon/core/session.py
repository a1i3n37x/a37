# src/alienrecon/core/session.py
import asyncio
import json
import logging
import os
import random
import re
import socket
from datetime import datetime
from typing import Any, Optional

from openai.types.chat.chat_completion_message import ChatCompletionMessage
from openai.types.chat.chat_completion_message_tool_call import (
    ChatCompletionMessageToolCall,
)
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.spinner import Spinner

# Tool imports
from ..tools.http_fetcher import HttpPageFetcherTool  # ADDED
from ..tools.hydra import HydraTool

# Import the LLM_TOOL_FUNCTIONS registry
from ..tools.llm_functions import LLM_TOOL_FUNCTIONS
from ..tools.nikto import NiktoTool
from ..tools.nmap import NmapTool
from ..tools.smb import SmbTool
from ..tools.ssl_inspector import SSLInspectorTool
from .agent import (
    AGENT_SYSTEM_PROMPT,
    AGENT_WELCOME_MESSAGE,
    AGENT_WELCOME_MESSAGE_WITH_TARGET,
    get_llm_response,
)
from .config import (
    DEFAULT_PASSWORD_LIST,
    initialize_openai_client,
)

logger = logging.getLogger(__name__)


class SessionController:
    SESSION_FILE = ".alienrecon_session.json"  # Default session file in CWD

    def __init__(self):
        self.console = Console()
        logger.debug("Initializing SessionController...")
        try:
            self.openai_client = initialize_openai_client()
        except Exception as e:
            self.console.print(
                f"[bold red]CRITICAL: Failed to initialize SessionController: {e}[/bold red]"
            )
            logger.critical(f"SessionController __init__ failed: {e}", exc_info=True)
            raise

        self.current_target: Optional[str] = None
        self.chat_history: list[dict[str, Any]] = []
        self.pending_tool_call: Optional[ChatCompletionMessageToolCall] = None
        self.is_novice_mode: bool = True

        # Session state specifically for target context
        self.state = {
            "target_ip": None,
            "target_hostname": None,
            "open_ports": [],  # List of {"port": int, "service": str, "version": str}
            "discovered_subdomains": [],
            "web_findings": {},  # E.g. {"http://target:port/path": {"tech": [], "interesting_files": []}}
        }

        self.nmap_tool: Optional[NmapTool] = None
        self.nikto_tool: Optional[NiktoTool] = None
        self.smb_tool: Optional[SmbTool] = None
        self.hydra_tool: Optional[HydraTool] = None
        self.http_fetcher_tool: Optional[HttpPageFetcherTool] = None  # ADDED
        self.ssl_inspector_tool: Optional[SSLInspectorTool] = None
        self._initialize_tools()

        # Try to load session state if it exists
        self.load_session()

        logger.info("SessionController initialized successfully.")

    def _initialize_tools(self):
        logger.debug("Initializing reconnaissance tools...")
        # For tools that are classes derived from CommandTool
        command_tool_classes = {
            "nmap_tool": NmapTool,
            "nikto_tool": NiktoTool,
            "smb_tool": SmbTool,
            "hydra_tool": HydraTool,
            "ssl_inspector_tool": SSLInspectorTool,
        }
        for attr_name, tool_class in command_tool_classes.items():
            try:
                tool_exe_name = getattr(
                    tool_class, "executable_name", "UnknownExecutable"
                )
                logger.debug(
                    f"Attempting to initialize CommandTool: {tool_class.__name__} (for '{tool_exe_name}')."
                )
                instance = tool_class()
                if not instance.executable_path:
                    logger.warning(
                        f"{tool_class.__name__} (for '{tool_exe_name}') initialized, but its executable_path is NOT set. Tool unavailable."
                    )
                    setattr(self, attr_name, None)
                else:
                    setattr(self, attr_name, instance)
                    logger.debug(
                        f"{tool_class.__name__} initialized. Executable path: {instance.executable_path}"
                    )
            except Exception as e:
                logger.error(
                    f"Error initializing CommandTool {tool_class.__name__}: {e}",
                    exc_info=True,
                )
                setattr(self, attr_name, None)

        # For internal tools like HttpPageFetcherTool (not a CommandTool)
        try:
            logger.debug(f"Attempting to initialize {HttpPageFetcherTool.__name__}.")
            self.http_fetcher_tool = HttpPageFetcherTool()
            logger.debug(f"{HttpPageFetcherTool.__name__} initialized.")
        except Exception as e:
            logger.error(
                f"Error initializing {HttpPageFetcherTool.__name__}: {e}", exc_info=True
            )
            self.http_fetcher_tool = None

        logger.debug("Tools initialization attempt finished.")

    def display_session_status(self, panel: bool = False):
        # Mission time
        mission_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status_lines = [
            f"[bold]🟢 Mission Time:[/bold] [bold yellow]{mission_time}[/bold yellow]",
            f"[bold]🎯 Target:[/bold] [bold cyan]{self.current_target or '[NOT SET]'}[/bold cyan]",
            f"[bold]🤖 Mode:[/bold] {'[bold green]🟡 Novice[/bold green]' if self.is_novice_mode else '[bold magenta]🟣 Expert[/bold magenta]'}",
        ]
        # Tools online
        tool_status = []
        if self.nmap_tool:
            tool_status.append("[bold blue]Nmap[/bold blue] 🛰️")
        if self.nikto_tool:
            tool_status.append("[bold red]Nikto[/bold red] 🦠")
        if self.smb_tool:
            tool_status.append("[bold white]SMB Enum[/bold white] 📁")
        if self.hydra_tool:
            tool_status.append("[bold green]Hydra[/bold green] 🐍")
        if self.http_fetcher_tool:
            tool_status.append("[bold cyan]HTTP Fetcher[/bold cyan] 🌐")
        if self.ssl_inspector_tool:
            tool_status.append("[bold yellow]SSL Inspector[/bold yellow] 🔒")
        status_lines.append(
            "[bold]🛠️ Tools Online:[/bold] "
            + (", ".join(tool_status) if tool_status else "[red]None[/red]")
        )
        if DEFAULT_PASSWORD_LIST:
            status_lines.append(
                f"[bold]🔑 Hydra Password List:[/bold] [bold white]{os.path.basename(DEFAULT_PASSWORD_LIST)}[/bold white]"
            )
        else:
            status_lines.append(
                "[bold]🔑 Hydra Password List:[/bold] [red]Not Set/Found - User/AI must specify[/red]"
            )
        status_text = "\n".join(status_lines)
        if panel:
            self.console.print(
                Panel.fit(
                    status_text,
                    title="[bold magenta]👽 Alien Recon Session Status[/bold magenta]",
                    border_style="bright_magenta",
                )
            )
        else:
            self.console.print(
                Markdown("### [bold magenta]Alien Recon Session Status[/bold magenta]")
            )
            for line in status_lines:
                self.console.print(line)
            self.console.print("-" * 50)

    def save_session(self):
        """Save current session state to SESSION_FILE."""
        session_data = {
            "current_target": self.current_target,
            "chat_history": self.chat_history,
            "is_novice_mode": self.is_novice_mode,
            "state": self.state,  # Save session state
        }
        try:
            with open(self.SESSION_FILE, "w", encoding="utf-8") as f:
                json.dump(session_data, f, indent=2)
            logger.info(f"Session saved to {self.SESSION_FILE}")
        except Exception as e:
            logger.error(f"Failed to save session: {e}", exc_info=True)

    def load_session(self):
        """Load session state from SESSION_FILE if it exists."""
        if os.path.exists(self.SESSION_FILE):
            try:
                with open(self.SESSION_FILE, encoding="utf-8") as f:
                    session_data = json.load(f)
                self.current_target = session_data.get("current_target")
                self.chat_history = session_data.get("chat_history", [])
                self.is_novice_mode = session_data.get("is_novice_mode", True)
                self.state = session_data.get("state", self.state)  # Load session state
                logger.info(f"Session loaded from {self.SESSION_FILE}")
            except Exception as e:
                logger.error(f"Failed to load session: {e}", exc_info=True)
        else:
            logger.info("No previous session file found; starting fresh.")

    def set_target(self, target_address: str):
        is_valid_target = False
        ip_address: Optional[str] = None
        hostname: Optional[str] = None

        if target_address:
            stripped_target = target_address.strip()
            # Check if it's an IP
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", stripped_target):
                is_valid_target = True
                ip_address = stripped_target
                try:
                    # Attempt reverse DNS lookup for hostname
                    hostname, _, _ = socket.gethostbyaddr(ip_address)
                except socket.herror:
                    hostname = None  # No resolvable hostname
            # Check if it's a CIDR (treat as IP for now, could refine later)
            elif re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", stripped_target):
                is_valid_target = True
                ip_address = stripped_target  # Store CIDR as IP for now
                hostname = stripped_target  # And as hostname
            # Else, assume it's a hostname
            elif "." in stripped_target:  # Basic check for hostname
                is_valid_target = True
                hostname = stripped_target
                try:
                    ip_address = socket.gethostbyname(hostname)
                except socket.gaierror:
                    self.console.print(
                        f"[bold red]Error: Could not resolve hostname '{hostname}' to an IP address.[/bold red]"
                    )
                    logger.warning(f"Could not resolve hostname: {hostname}")
                    is_valid_target = False
            else:
                self.console.print(
                    f"[bold red]Invalid target format: '{target_address}'. Use IP or domain.[/bold red]"
                )
                logger.warning(f"Invalid target format: {target_address}")
                return

        if is_valid_target:
            # Use the IP address as the primary current_target if available
            primary_target_display = ip_address or hostname
            if self.current_target != primary_target_display:
                self.current_target = primary_target_display
                self.state["target_ip"] = ip_address
                self.state["target_hostname"] = hostname
                # Reset other state parts as target has changed
                self.state["open_ports"] = []
                self.state["discovered_subdomains"] = []
                self.state["web_findings"] = {}

                self.console.print(
                    f"[bold blue]Session Target Locked:[/bold blue] {self.current_target} "
                    f"(IP: {ip_address or 'N/A'}, Hostname: {hostname or 'N/A'})"
                )
                logger.info(
                    f"Target set to: {self.current_target} (IP: {ip_address}, Hostname: {hostname})"
                )
                self.chat_history = []
                self.pending_tool_call = None
                logger.debug("Chat history cleared due to new target.")
                self.save_session()
            else:
                self.console.print(
                    f"[blue]Session Target re-confirmed:[/blue] {self.current_target}"
                )
        else:
            self.console.print(
                f"[bold red]Invalid target format: '{target_address}'. Use IP or domain.[/bold red]"
            )
            logger.warning(f"Invalid target format: {target_address}")

    def get_current_target(self) -> Optional[str]:
        return self.current_target

    def get_target_ip(self) -> Optional[str]:
        """Returns the resolved IP address of the current target."""
        return self.state.get("target_ip")

    def get_target_hostname(self) -> Optional[str]:
        """Returns the hostname of the current target, if available."""
        return self.state.get("target_hostname")

    def set_novice_mode(self, novice: bool):
        if self.is_novice_mode != novice:
            self.is_novice_mode = novice
            mode_text = "Novice (more guidance)" if novice else "Expert (less guidance)"
            self.console.print(
                f"[cyan]Guidance mode set to: [bold]{mode_text}[/bold][/cyan]"
            )
            logger.info(f"Novice mode set to: {self.is_novice_mode}")
            self.save_session()
        else:
            mode_text = "Novice" if novice else "Expert"
            self.console.print(
                f"[cyan]Guidance mode is already [bold]{mode_text}[/bold].[/cyan]"
            )

    def start_interactive_recon_session(self):
        # ASCII Art Banner (Alien/Space/CTF theme)
        ascii_banner = r'''[bold green]
      .-"""-.
     / .===. \
     \/ 6 6 \/
     ( \___/ )
 ___ooo__V__ooo___
[magenta]  ALIEN RECON: CTF OPS CENTER  [/magenta]
[/bold green]'''
        self.console.print(ascii_banner, highlight=True)

        # Pro Tips / Alien Intel
        pro_tips = [
            "[bold cyan]Alien Intel:[/bold cyan] Use [bold]Nmap[/bold] with -sV to detect service versions for more targeted attacks!",
            "[bold cyan]Alien Intel:[/bold cyan] Check robots.txt and .git/ directories for hidden clues on web servers.",
            "[bold cyan]Alien Intel:[/bold cyan] Use [bold]ffuf[/bold] with different wordlists for deeper directory brute-forcing.",
            "[bold cyan]Alien Intel:[/bold cyan] Look for usernames in HTML comments and error messages!",
            "[bold cyan]Alien Intel:[/bold cyan] Hydra is powerful, but always check for account lockout policies first.",
            "[bold cyan]Alien Intel:[/bold cyan] [bold]SMB shares[/bold] can leak sensitive files—enumerate thoroughly!",
            "[bold cyan]Alien Intel:[/bold cyan] If you get stuck, ask: 'What else can we do?' or try a different tool!",
            "[bold cyan]Alien Intel:[/bold cyan] [bold]Nikto[/bold] can reveal web server misconfigurations and vulnerabilities quickly.",
            "[bold cyan]Alien Intel:[/bold cyan] Use [bold]Expert Mode[/bold] for less hand-holding and faster ops!",
        ]
        pro_tip = random.choice(pro_tips)

        if not self.current_target:
            self.console.print("[bold magenta]👽 Welcome, Earthling![/bold magenta]")
            self.console.print(Markdown(AGENT_WELCOME_MESSAGE))
            self.display_session_status()
            self.console.print(
                "Type '[bold yellow]exit[/bold yellow]' or '[bold yellow]quit[/bold yellow]' to end recon and return to CLI."
            )
            self.console.print("-" * 50)
            self.console.print(pro_tip)
            logger.info("Interactive session started with no target set.")
            return

        # If target is set, use the concise welcome message
        welcome_msg = AGENT_WELCOME_MESSAGE_WITH_TARGET.replace(
            "[TARGET]", f"[bold cyan]{self.current_target}[/bold cyan]"
        )
        self.console.print("[bold magenta]👽 Welcome, Operative![/bold magenta]")
        self.console.print(welcome_msg, highlight=True)
        self.console.print("\n" + "[bold green]" + "⎯" * 60 + "[/bold green]\n")
        self.display_session_status(panel=True)
        self.console.print(
            "Type '[bold yellow]exit[/bold yellow]' or '[bold yellow]quit[/bold yellow]' to end recon and return to CLI."
        )
        self.console.print("[bold green]" + "⎯" * 60 + "[/bold green]")
        self.console.print(pro_tip)

        logger.info(f"Starting interactive reconnaissance for {self.current_target}")

        if not self.chat_history:
            # Construct initial message that includes target information for the AI's first turn.
            # Guide the AI to use the new nmap_scan function for its first proposal.
            initial_user_msg = (
                f"Initiate reconnaissance for primary target coordinates: {self.current_target}. "
                "For the first step, please propose an initial Nmap scan using the `nmap_scan` tool. "
                "A good initial scan for CTFs would be a SYN scan on the top 1000 TCP ports, "
                "explicitly using -Pn as ping is often blocked. So, consider parameters like: "
                '`ip` should be the target IP, `scan_type="SYN"`, `top_ports=1000`, and `custom_arguments="-Pn"`. '
                "Only suggest service/version detection or other scans after these initial open ports are found. "
                "Remember to propose this as a tool call."
            )
            self.chat_history.append({"role": "user", "content": initial_user_msg})
            ai_response = self._get_llm_response_from_agent()
            self._process_llm_message(ai_response)

        # NEW: On session start, if last message is assistant with tool_calls, resolve them
        if self.chat_history:
            last_msg = self.chat_history[-1]
            if last_msg.get("role") == "assistant" and last_msg.get("tool_calls"):
                # Check if there are any tool calls that haven't been resolved yet
                unresolved_tool_calls = []
                if last_msg.get("tool_calls"):
                    for tool_call in last_msg["tool_calls"]:
                        tool_call_id = tool_call["id"]
                        # Check if this tool call has already been resolved
                        has_response = any(
                            msg.get("role") == "tool"
                            and msg.get("tool_call_id") == tool_call_id
                            for msg in self.chat_history
                        )
                        if not has_response:
                            unresolved_tool_calls.append(tool_call)

                # Only process if there are unresolved tool calls
                if unresolved_tool_calls:
                    # Reconstruct a ChatCompletionMessage-like object for processing
                    from openai.types.chat.chat_completion_message import (
                        ChatCompletionMessage,
                        ChatCompletionMessageToolCall,
                    )

                    tool_calls = [
                        ChatCompletionMessageToolCall(**tc)
                        for tc in unresolved_tool_calls
                    ]
                    ai_message = ChatCompletionMessage(
                        role="assistant",
                        content=last_msg.get("content"),
                        tool_calls=tool_calls,
                        function_call=None,
                        tool_call_id=None,
                        name=None,
                    )
                    self._process_llm_message(ai_message)
            else:
                # If the last message isn't an assistant with unresolved tool calls,
                # and we have a conversation history, prompt the AI to continue
                if self.chat_history and self.chat_history[-1].get("role") in [
                    "assistant",
                    "tool",
                ]:
                    # Ask the AI what to do next
                    continuation_msg = (
                        "What should we investigate next based on our current findings? "
                        "Please suggest the next reconnaissance step or tool to use."
                    )
                    self.chat_history.append(
                        {"role": "user", "content": continuation_msg}
                    )
                    ai_response = self._get_llm_response_from_agent()
                    self._process_llm_message(ai_response)

        while True:
            try:
                # NEW: Block user input if there are unresolved tool calls
                while self.pending_tool_call:
                    if self._confirm_tool_proposal():
                        self._execute_single_tool_call_and_update_history()
                    else:
                        if self.pending_tool_call is not None:
                            tool_call_id = self.pending_tool_call.id
                            function_name = self.pending_tool_call.function.name
                            self._send_tool_cancellation_to_llm(
                                tool_call_id, function_name
                            )
                            self.pending_tool_call = None
                            ai_response = self._get_llm_response_from_agent()
                            self._process_llm_message(ai_response)
                        else:
                            break

                user_input = self.console.input(
                    "[bold cyan]You (to Alien Recon):[/bold cyan] "
                ).strip()
                if user_input.lower() in ["exit", "quit"]:
                    self.console.print(
                        "[bold magenta]Ending reconnaissance with Alien Recon.[/bold magenta]"
                    )
                    break
                if not user_input:
                    continue

                self.chat_history.append({"role": "user", "content": user_input})
                ai_response = self._get_llm_response_from_agent()
                self._process_llm_message(ai_response)

            except KeyboardInterrupt:
                self.console.print(
                    "\n[bold magenta]Recon interrupted. Returning to CLI.[/bold magenta]"
                )
                break
            except Exception as e:
                logger.critical(f"Critical error in recon loop: {e}", exc_info=True)
                self.console.print(
                    f"[bold red]Critical error: {e}. Session ending.[/bold red]"
                )
                break
        logger.info(f"Interactive session ended for target {self.current_target}")

    def _get_llm_response_from_agent(self) -> Optional[ChatCompletionMessage]:
        if not self.chat_history or (
            self.chat_history[-1]["role"] not in ["user", "tool"]
        ):
            if not self.chat_history or self.chat_history[-1]["role"] == "assistant":
                logger.debug(
                    "Last message was from assistant without tool call, appending clarifying user message."
                )
                self.chat_history.append(
                    {
                        "role": "user",
                        "content": "What are my options now? Or what should I investigate based on your last statement?",
                    }
                )
            else:
                logger.warning(
                    "Attempted to get LLM response in an unexpected state. Please provide input."
                )
                return None

        logger.debug(
            f"Sending {len(self.chat_history)} messages to LLM. Last: '{self.chat_history[-1]['content'][:70] if self.chat_history and self.chat_history[-1].get('content') else 'Tool Call/No Content'}'"
        )
        ai_message_obj = get_llm_response(
            client=self.openai_client,
            history=self.chat_history,
            system_prompt=AGENT_SYSTEM_PROMPT,
        )
        if ai_message_obj:
            log_content = (
                str(ai_message_obj.content)[:70] if ai_message_obj.content else "None"
            )
            log_tools = (
                len(ai_message_obj.tool_calls) if ai_message_obj.tool_calls else 0
            )
            logger.debug(
                f"LLM response. Content: '{log_content[:70]}...' Tools: {log_tools}"
            )
        else:
            logger.warning("get_llm_response returned None. AI did not respond.")
        return ai_message_obj

    def _process_llm_message(self, ai_message: Optional[ChatCompletionMessage]):
        if not ai_message:
            self.console.print(
                "[red](Alien Recon encountered an issue and could not respond. Please try again or check logs.)[/red]"
            )
            return

        # Ensure the AI's textual response is displayed if present
        if ai_message.content:
            self.console.print(Markdown(f"**Alien Recon:** {ai_message.content}"))
        elif not ai_message.tool_calls:
            # Only log/print warning if there are no tool calls AND no content
            logger.warning("LLM message had no text content and no tool_calls.")
            self.console.print(
                "[grey50](Alien Recon offered no textual guidance and proposed no actions this turn.)[/grey50]"
            )

        # The primary addition of the AI's message to history happens here:
        # Check if we're adding a duplicate - avoid adding the same message twice
        message_dump = ai_message.model_dump()

        # Check if the last message in history is identical to what we're about to add
        if (
            self.chat_history
            and self.chat_history[-1].get("role") == "assistant"
            and self.chat_history[-1].get("tool_calls")
            == message_dump.get("tool_calls")
        ):
            # This appears to be a duplicate message, don't add it again
            logger.debug("Skipping duplicate assistant message addition to history")
        else:
            self.chat_history.append(message_dump)
            self.save_session()

        if ai_message.tool_calls:
            tool_calls_to_process = list(ai_message.tool_calls)
            confirmed_tool_calls = []

            # First, confirm all tool calls
            for tool_call in tool_calls_to_process:
                self.pending_tool_call = (
                    tool_call  # Set current tool_call for _confirm_tool_proposal
                )

                if self._confirm_tool_proposal():  # This shows [E]dit [C]onfirm prompt
                    confirmed_tool_calls.append(tool_call)
                else:
                    # User cancelled the tool proposal
                    self._send_tool_cancellation_to_llm(
                        tool_call.id, tool_call.function.name
                    )

            # If multiple tools confirmed, offer parallel execution
            if len(confirmed_tool_calls) > 1:
                from .parallel_executor import ParallelExecutor

                executor = ParallelExecutor(self.console)

                # Prepare tool calls data
                tool_calls_data = []
                for tool_call in confirmed_tool_calls:
                    tool_info = LLM_TOOL_FUNCTIONS.get(tool_call.function.name, {})
                    display_name = tool_info.get(
                        "description", tool_call.function.name
                    ).split(".")[0]
                    tool_calls_data.append(
                        (
                            tool_call.id,
                            tool_call.function.name,
                            display_name,
                            json.loads(tool_call.function.arguments or "{}"),
                        )
                    )

                if executor.should_run_parallel(tool_calls_data):
                    self.console.print(
                        f"\n[cyan]Multiple tools confirmed ({len(confirmed_tool_calls)} tools).[/cyan]"
                    )
                    self.console.print(
                        "Would you like to run them in parallel for faster results?"
                    )
                    choice = (
                        self.console.input("[bold][P]arallel  [S]equential:[/bold] ")
                        .strip()
                        .lower()
                    )

                    if choice in ["p", "parallel"]:
                        # Execute in parallel
                        self.console.print(
                            "[green]Running tools in parallel...[/green]\n"
                        )

                        # Run tools in parallel
                        results = asyncio.run(
                            executor.execute_tools_parallel(tool_calls_data)
                        )

                        # Display results
                        executor.display_parallel_results(results)

                        # Add results to chat history
                        for result_info in results:
                            self.chat_history.append(
                                {
                                    "tool_call_id": result_info["tool_call_id"],
                                    "role": "tool",
                                    "name": result_info["function_name"],
                                    "content": json.dumps(result_info["result"]),
                                }
                            )

                        self.save_session()
                        executor.cleanup()
                    else:
                        # Sequential execution
                        for tool_call in confirmed_tool_calls:
                            self.pending_tool_call = tool_call
                            if not self._execute_single_tool_call_and_update_history():
                                continue
                else:
                    # Not suitable for parallel, run sequentially
                    for tool_call in confirmed_tool_calls:
                        self.pending_tool_call = tool_call
                        if not self._execute_single_tool_call_and_update_history():
                            continue
            else:
                # Single tool or no confirmed tools
                for tool_call in confirmed_tool_calls:
                    self.pending_tool_call = tool_call
                    if not self._execute_single_tool_call_and_update_history():
                        continue

            self.pending_tool_call = None  # Clear pending call after the loop

            # Only after all tool messages are appended, get next LLM response
            next_ai_response_message = self._get_llm_response_from_agent()
            self._process_llm_message(
                next_ai_response_message
            )  # Recursive call for next turn
            return  # Important: return after handling tool calls and dispatching next LLM turn

        # If we reach here, the AI message had no tool calls but had content - this is normal
        # The text content has already been displayed above, so we just return
        return

    def _confirm_tool_proposal(self) -> bool:
        if not self.pending_tool_call:
            logger.error("Confirmation requested but no tool_call is pending.")
            return False
        tool_name_llm = self.pending_tool_call.function.name
        try:
            tool_args = json.loads(self.pending_tool_call.function.arguments)
        except json.JSONDecodeError as e:
            logger.error(
                f"JSONDecodeError for LLM tool args: {self.pending_tool_call.function.arguments}. Tool: {tool_name_llm}. Error: {e}"
            )
            self.console.print(
                f"[bold red]Error: AI proposed action '{tool_name_llm}' with invalid arguments. Aborting this action.[/bold red]"
            )
            if self.pending_tool_call is not None:
                tool_call_id = self.pending_tool_call.id
                # function_name = self.pending_tool_call.function.name # Already have tool_name_llm
                self._send_tool_cancellation_to_llm(tool_call_id, tool_name_llm)
                self.pending_tool_call = None
            return False

        # Get function details from the registry
        function_definition = LLM_TOOL_FUNCTIONS.get(tool_name_llm)
        if not function_definition:
            logger.error(
                f"Tool function '{tool_name_llm}' not found in LLM_TOOL_FUNCTIONS registry."
            )
            self.console.print(
                f"[bold red]Error: Unknown tool function '{tool_name_llm}' proposed by AI. Aborting.[/bold red]"
            )
            if self.pending_tool_call is not None:
                tool_call_id = self.pending_tool_call.id
                self._send_tool_cancellation_to_llm(tool_call_id, tool_name_llm)
                self.pending_tool_call = None
            return False

        display_name = function_definition.get("description", tool_name_llm)

        def show_args(current_tool_args, function_params_definition):
            self.console.rule(
                f"[bold yellow]Decision Point: {display_name} Proposal[/bold yellow]"
            )
            # Display a brief description of the function
            # self.console.print(f"[dim]{function_definition.get('description', '')}[/dim]")

            for param_name, param_info in function_params_definition.items():
                description = param_info.get("description", "")
                current_value = current_tool_args.get(param_name)
                default_value = param_info.get("default")

                display_value = current_value
                value_source = "(current)"
                if current_value is None and default_value is not None:
                    display_value = default_value
                    value_source = "(default)"
                elif current_value is None:
                    display_value = "[NOT SET]"
                    value_source = ""

                self.console.print(
                    f"  [bold]{param_name}[/bold] ({description}): [cyan]{display_value}[/cyan] {value_source}",
                    markup=True,
                )

            # If this is an FFUF directory enumeration, show derived port
            if tool_name_llm == "ffuf_dir_enum":
                try:
                    from urllib.parse import urlparse

                    parsed = urlparse(current_tool_args.get("url", ""))
                    derived_port = parsed.port or (
                        443 if parsed.scheme == "https" else 80
                    )
                    self.console.print(
                        f"  [bold]port[/bold] (derived from URL): [cyan]{derived_port}[/cyan] (derived)",
                        markup=True,
                    )
                except Exception:
                    pass
            self.console.rule()

        # Prepare current arguments by merging defaults with LLM-provided args
        llm_provided_args = tool_args  # tool_args is already a dict from json.loads()

        function_params_definition = function_definition.get("parameters", {})
        current_display_args = {}
        for param_name, param_info in function_params_definition.items():
            current_display_args[param_name] = llm_provided_args.get(
                param_name, param_info.get("default")
            )

        while True:
            show_args(current_display_args, function_params_definition)
            self.console.print(
                "[bold][E][/bold]dit  [bold][C][/bold]onfirm  [bold][S][/bold]kip  [bold][Q][/bold]uit session"
            )
            choice = self.console.input("  Your choice: ").strip().lower()
            if choice in ["c", "confirm"]:
                # Update pending_tool_call with potentially edited args before returning True
                self.pending_tool_call.function.arguments = json.dumps(
                    current_display_args
                )
                return True
            elif choice in ["s", "skip"]:
                logger.info(
                    f"User skipped tool: {display_name} (Args: {current_display_args})"
                )
                if self.pending_tool_call is not None:
                    tool_call_id = self.pending_tool_call.id
                    # function_name = self.pending_tool_call.function.name # Already have tool_name_llm
                    self._send_tool_cancellation_to_llm(tool_call_id, tool_name_llm)
                    self.pending_tool_call = None
                return False
            elif choice in ["q", "quit"]:
                self.console.print(
                    "[bold magenta]Ending reconnaissance with Alien Recon.[/bold magenta]",
                    markup=False,
                )
                exit(0)  # Consider a cleaner exit strategy if needed
            elif choice in ["e", "edit"]:
                for (
                    param_name_to_edit,
                    param_info_to_edit,
                ) in function_params_definition.items():
                    prompt_val = current_display_args.get(param_name_to_edit)
                    if (
                        prompt_val is None
                        and param_info_to_edit.get("default") is not None
                    ):
                        prompt_val = param_info_to_edit.get("default")
                    elif prompt_val is None:
                        prompt_val = ""

                    prompt = f"  Edit '{param_name_to_edit}' (current: [yellow]{prompt_val}[/yellow]): "
                    new_val_str = self.console.input(prompt, markup=True)

                    if new_val_str.strip() != "":
                        param_type = param_info_to_edit.get("type", "string")
                        # Attempt type conversion for boolean, integer, number
                        if param_type == "integer":
                            try:
                                current_display_args[param_name_to_edit] = int(
                                    new_val_str
                                )
                            except ValueError:
                                self.console.print(
                                    f"[red]Invalid integer value for {param_name_to_edit}. Keeping previous.[/red]"
                                )
                        elif param_type == "number":  # float
                            try:
                                current_display_args[param_name_to_edit] = float(
                                    new_val_str
                                )
                            except ValueError:
                                self.console.print(
                                    f"[red]Invalid number value for {param_name_to_edit}. Keeping previous.[/red]"
                                )
                        elif param_type == "boolean":
                            if new_val_str.lower() in ["true", "t", "yes", "y", "1"]:
                                current_display_args[param_name_to_edit] = True
                            elif new_val_str.lower() in ["false", "f", "no", "n", "0"]:
                                current_display_args[param_name_to_edit] = False
                            else:
                                self.console.print(
                                    f"[red]Invalid boolean value for {param_name_to_edit} (true/false). Keeping previous.[/red]"
                                )
                        elif (
                            param_type == "array"
                        ):  # For array, expect comma-separated string
                            try:
                                # Simple split, assuming elements don't contain commas.
                                # For more complex array inputs, more robust parsing might be needed.
                                current_display_args[param_name_to_edit] = [
                                    s.strip()
                                    for s in new_val_str.split(",")
                                    if s.strip()
                                ]
                            except Exception:
                                self.console.print(
                                    f"[red]Could not parse array for {param_name_to_edit}. Keeping previous.[/red]"
                                )
                        else:  # string or other types
                            current_display_args[param_name_to_edit] = new_val_str
                    # If user enters empty string, it means keep the current/default value, so no change to current_display_args[param_name_to_edit]

                self.console.print("[green]Arguments updated.[/green]", markup=False)
                # No need to update pending_tool_call here, as the loop will show_args again
                # and confirmation will dump current_display_args.
                continue
            else:
                self.console.print(
                    "[yellow]Invalid choice. Please enter E, C, S, or Q.[/yellow]",
                    markup=False,
                )
                continue

    def _send_tool_cancellation_to_llm(self, tool_call_id: str, function_name: str):
        """Handles user cancellation of a tool, adds a 'tool' role message to history."""
        self.console.print(
            f"[yellow]Tool call '{function_name}' cancelled by user.[/yellow]"
        )

        cancellation_content = json.dumps(
            {
                "status": "cancelled_by_user",
                "message": f"User explicitly cancelled the tool: {function_name}",
            }
        )

        self.chat_history.append(
            {
                "tool_call_id": tool_call_id,
                "role": "tool",  # Crucially, this must be 'tool'
                "name": function_name,
                "content": cancellation_content,
            }
        )
        self.save_session()
        # No longer calls LLM here; caller (_process_llm_message) will do it.

    def _execute_single_tool_call_and_update_history(self) -> bool:
        """
        Executes the self.pending_tool_call, displays results,
        and adds the 'tool' message (success or error) to history.
        Returns True if tool executed (even if tool reported an operational error),
        False if a critical error occurred during argument parsing or dispatch.
        """
        if not self.pending_tool_call:
            logger.error(
                "CRITICAL: _execute_single_tool_call_and_update_history called with no pending_tool_call."
            )
            self.console.print(
                "[bold red]Error: No tool call pending for execution.[/bold red]"
            )
            return False

        tool_call_id = self.pending_tool_call.id
        function_name = self.pending_tool_call.function.name
        arguments_str = self.pending_tool_call.function.arguments or "{}"

        self.console.print(f"[cyan]Engaging tool {function_name}...[/cyan]")
        spinner = Spinner("dots", text=f" Alien Recon is running {function_name}...")

        tool_output_json_str: Optional[str] = None
        tool_function_succeeded = False  # Tracks if the Python function for the tool ran without Python exceptions

        try:
            arguments = json.loads(arguments_str)

            # Find and call the actual tool function
            tool_info = LLM_TOOL_FUNCTIONS.get(function_name)
            if not tool_info or not callable(tool_info.get("function")):
                logger.error(
                    f"Tool function '{function_name}' not found or not callable in LLM_TOOL_FUNCTIONS."
                )
                tool_output_dict = {
                    "status": "failure",
                    "error": f"Internal error: Tool '{function_name}' is not implemented correctly.",
                }
            else:
                actual_tool_function = tool_info["function"]
                logger.info(f"Executing tool: {function_name} with args: {arguments}")

                with self.console.status(spinner, speed=1.5):
                    tool_output_dict = actual_tool_function(
                        **arguments
                    )  # Execute the function

                # tool_output_dict should already be a dict from the llm_functions
                if not isinstance(tool_output_dict, dict):
                    logger.error(
                        f"Tool {function_name} did not return a dict. Got: {type(tool_output_dict)}"
                    )
                    tool_output_dict = {
                        "status": "failure",
                        "error": f"Tool {function_name} returned an unexpected data type.",
                    }
            tool_function_succeeded = True  # Python function call itself was successful

        except json.JSONDecodeError as e:
            logger.error(
                f"JSONDecodeError parsing arguments for {function_name}: {e}. Args: {arguments_str}"
            )
            tool_output_dict = {
                "status": "failure",
                "error": f"Invalid arguments provided for {function_name}: {e}",
            }
        except (
            TypeError
        ) as e:  # Catch errors from calling the tool function with wrong args
            logger.error(
                f"TypeError calling tool {function_name} with args {arguments_str}: {e}",
                exc_info=True,
            )
            tool_output_dict = {
                "status": "failure",
                "error": f"Error calling tool {function_name} (check arguments): {e}",
            }
        except (
            Exception
        ) as e:  # Catch-all for other unexpected errors during tool setup/dispatch
            logger.error(
                f"Unexpected error preparing or calling tool {function_name}: {e}",
                exc_info=True,
            )
            tool_output_dict = {
                "status": "failure",
                "error": f"An unexpected error occurred with tool {function_name}: {e}",
            }

        # Convert the tool's output dictionary to a JSON string for the history
        try:
            tool_output_json_str = json.dumps(tool_output_dict)
        except TypeError as e:
            logger.error(
                f"TypeError serializing tool output for {function_name} to JSON: {e}. Output: {tool_output_dict}",
                exc_info=True,
            )
            tool_output_json_str = json.dumps(
                {
                    "status": "failure",
                    "error": f"Failed to serialize tool output for {function_name}: {e}",
                }
            )
            # This indicates a problem with the tool's returned structure, but we still add it to history.

        # Check if result was from cache
        from_cache = isinstance(tool_output_dict, dict) and tool_output_dict.get(
            "_from_cache", False
        )

        # Display cache indicator if result was cached
        if from_cache:
            self.console.print(
                "[dim italic]🔄 Using cached result. Run 'alienrecon cache clear' to force fresh scans.[/dim italic]"
            )

        # Remove cache metadata from display
        display_dict = (
            tool_output_dict.copy()
            if isinstance(tool_output_dict, dict)
            else tool_output_dict
        )
        if isinstance(display_dict, dict) and "_from_cache" in display_dict:
            display_dict.pop("_from_cache")

        # Display tool output/summary to user
        cache_indicator = " [green](CACHED)[/green]" if from_cache else ""

        if display_dict.get("status") == "failure":
            self.console.print(
                Panel(
                    f"[bold red]Error from {function_name}:[/bold red]\\n{display_dict.get('error', 'Unknown error')}",
                    title=f"Tool Execution Failed{cache_indicator}",
                    border_style="red",
                )
            )
        elif (
            "scan_summary" in display_dict and display_dict["scan_summary"]
        ):  # For tools that provide a summary
            self.console.print(
                Panel(
                    Markdown(
                        display_dict["scan_summary"]
                    ),  # Render summary as Markdown
                    title=f"Tool Results: {function_name}{cache_indicator}",
                    border_style="green",
                )
            )
        elif "findings" in display_dict:  # Generic display for other tools
            self.console.print(
                Panel(
                    json.dumps(display_dict.get("findings"), indent=2),
                    title=f"Tool Results: {function_name}{cache_indicator}",
                    border_style="green",
                )
            )
        else:  # Fallback if no clear summary or findings
            # Re-serialize without cache metadata
            clean_json_str = (
                json.dumps(display_dict)
                if isinstance(display_dict, dict)
                else tool_output_json_str
            )
            self.console.print(
                Panel(
                    clean_json_str,
                    title=f"Raw Tool Output: {function_name}{cache_indicator}",
                    border_style="yellow",
                )
            )

        # Add the tool's result to chat history
        self.chat_history.append(
            {
                "tool_call_id": tool_call_id,
                "role": "tool",
                "name": function_name,
                "content": tool_output_json_str,  # This MUST be a string
            }
        )
        self.save_session()

        # Return True if the Python function for the tool was called successfully,
        # even if the tool itself reported an operational error (e.g., "target not found").
        # Return False for critical errors like argument parsing, function not found, etc.
        return tool_function_succeeded

    def run_task(self, task):
        # Dispatch to the correct tool and run it
        tool_map = {
            "nmap": self.nmap_tool,
            "nikto": self.nikto_tool,
            "smb_enum": self.smb_tool,
            "hydra": self.hydra_tool,
            "http_page_fetcher": self.http_fetcher_tool,
        }
        tool = tool_map.get(task.tool_name)
        if not tool:
            self.console.print(f"[red]Tool {task.tool_name} not found![/red]")
            return
        self.console.print(f"[cyan]Running {task.tool_name} on {task.target}...[/cyan]")
        kwargs = {"target": task.target}
        if task.arguments:
            kwargs["arguments"] = task.arguments
        if task.port:
            kwargs["port"] = task.port
        if task.wordlist:
            kwargs["wordlist"] = task.wordlist
        result = tool.execute(**kwargs)
        self.console.print(
            f"[green]{task.tool_name} result:[/green] {result['scan_summary']}"
        )
        # Print findings for all tools, not just Nmap
        findings = result.get("findings")
        if findings:
            from pprint import pformat

            self.console.print("[bold yellow]Findings:[/bold yellow]")
            self.console.print(pformat(findings))
        # Print raw_stdout/raw_stderr if error is present
        if result.get("status") == "failure" or result.get("error"):
            if result.get("raw_stdout"):
                self.console.print("[dim]Raw stdout:[/dim]")
                self.console.print(result["raw_stdout"])
            if result.get("raw_stderr"):
                self.console.print("[dim]Raw stderr:[/dim]")
                self.console.print(result["raw_stderr"])
        if task.post_hook:
            task.post_hook(result)

    def run_assistant_session(self):
        """
        Launch the conversational AI assistant session. This is the recommended workflow for Alien Recon.
        """
        print(
            "\n[Alien Recon] Starting assistant-driven recon session. Type your commands or questions. Type 'exit' to quit.\n"
        )
        while True:
            user_input = input("[assistant]> ").strip()
            if user_input.lower() in ("exit", "quit"):
                print("[Alien Recon] Session ended. Goodbye!")
                break
            # Route all tool orchestration, result parsing, and explanations through the assistant
            self.handle_assistant_input(user_input)

    def handle_assistant_input(self, user_input: str):
        """
        Process user input in the context of the assistant-driven session.
        """
        self.chat_history.append({"role": "user", "content": user_input})
        try:
            ai_response = self._get_llm_response_from_agent()
            self._process_llm_message(ai_response)
            while self.pending_tool_call:
                if self._confirm_tool_proposal():
                    self._execute_single_tool_call_and_update_history()
                else:
                    if self.pending_tool_call is not None:
                        tool_call_id = self.pending_tool_call.id
                        function_name = self.pending_tool_call.function.name
                        self._send_tool_cancellation_to_llm(tool_call_id, function_name)
                        self.pending_tool_call = None
                        ai_response = self._get_llm_response_from_agent()
                        self._process_llm_message(ai_response)
                    else:
                        break
        except Exception as e:
            self.console.print(f"[bold red]Error in assistant: {e}[/bold red]")
            logger.error(f"Error in assistant conversational logic: {e}", exc_info=True)

    def _resolve_and_validate_ip(
        self, proposed_ip_str: Optional[str], param_name: str, function_name: str
    ) -> Optional[str]:
        """
        Resolves a proposed IP/hostname to a valid numeric IP address.
        Prioritizes already valid IPs, then session target IP, then DNS resolution.
        """
        logger.debug(
            f"Resolving/validating IP for param '{param_name}' ('{proposed_ip_str}') in function '{function_name}'"
        )

        # If proposed_ip_str is already a valid numeric IP, use it.
        if proposed_ip_str and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", proposed_ip_str):
            logger.debug(
                f"Proposed value '{proposed_ip_str}' is already a valid IP for param '{param_name}'."
            )
            return proposed_ip_str

        # Special handling for ffuf_vhost_enum's 'ip' parameter:
        # It MUST be the numeric IP of the server being scanned.
        if function_name == "ffuf_vhost_enum" and param_name == "ip":
            session_target_ip = self.get_target_ip()
            if session_target_ip:
                # If proposed_ip_str was not a numeric IP (e.g., it was a domain, or empty), use session_target_ip.
                logger.info(
                    f"For '{function_name}' param '{param_name}', using session target IP: {session_target_ip} (original proposal: '{proposed_ip_str}')."
                )
                return session_target_ip
            else:
                # No session target IP. If proposed_ip_str is a hostname, we might try to resolve it (below).
                # If proposed_ip_str is empty or also not a hostname, this is an error for ffuf_vhost_enum.
                if not proposed_ip_str:
                    logger.error(
                        f"Cannot run {function_name}: '{param_name}' is empty, and no session target IP is set."
                    )
                    return None
                logger.warning(
                    f"No session target IP for {function_name}. Will attempt to resolve '{proposed_ip_str}' if it's a hostname."
                )
                # Fall through to general DNS resolution at the end of this function for proposed_ip_str

        # General case: if proposed_ip_str is not numeric at this point (and not handled by ffuf_vhost_enum specific logic directly above)
        # or if proposed_ip_str was empty initially.
        if not proposed_ip_str:  # If proposed is empty or became empty
            session_target_ip = self.get_target_ip()
            if session_target_ip:
                logger.debug(
                    f"No/invalid IP proposed for '{param_name}', using session target IP: {session_target_ip}"
                )
                return session_target_ip

            session_target_hostname = self.get_target_hostname()
            if session_target_hostname:
                proposed_ip_str = session_target_hostname  # Prepare for DNS resolution if IP was needed
                logger.debug(
                    f"No/invalid IP proposed for '{param_name}', using session target hostname for DNS resolution: {proposed_ip_str}"
                )
            else:
                logger.warning(
                    f"Cannot resolve IP for '{param_name}': No value provided and no session target context."
                )
                return None

        # If proposed_ip_str is still None or empty after above fallbacks, it's an issue.
        if not proposed_ip_str:
            logger.error(
                f"IP resolution failed for '{param_name}': effective value to resolve is empty."
            )
            return None

        # Attempt DNS resolution if proposed_ip_str is (now potentially) a hostname
        logger.debug(
            f"Attempting to resolve '{proposed_ip_str}' as a hostname for param '{param_name}'."
        )
        try:
            resolved_ip = socket.gethostbyname(proposed_ip_str)
            logger.info(
                f"Resolved '{proposed_ip_str}' to IP: {resolved_ip} for param '{param_name}'."
            )
            return resolved_ip
        except socket.gaierror:
            logger.error(
                f"DNS resolution failed for '{proposed_ip_str}' for param '{param_name}'."
            )
            return None
        except Exception as e:
            logger.error(
                f"Unexpected error during DNS resolution for '{proposed_ip_str}': {e}"
            )
            return None
