# src/alienrecon/core/session.py
import json
import logging
import os
import re
from typing import Any, Optional

from openai.types.chat.chat_completion_message import ChatCompletionMessage
from openai.types.chat.chat_completion_message_tool_call import (
    ChatCompletionMessageToolCall,
)
from rich.console import Console
from rich.markdown import Markdown
from rich.spinner import Spinner

# Tool imports
from ..tools.gobuster import GobusterTool
from ..tools.http_fetcher import HttpPageFetcherTool  # ADDED
from ..tools.hydra import HydraTool
from ..tools.nikto import NiktoTool
from ..tools.nmap import NmapTool
from ..tools.smb import SmbTool
from .agent import (
    AGENT_SYSTEM_PROMPT,
    AGENT_WELCOME_MESSAGE,
    get_llm_response,
)
from .config import (
    DEFAULT_PASSWORD_LIST,
    DEFAULT_WORDLIST,
    initialize_openai_client,
)

logger = logging.getLogger(__name__)


class SessionController:
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

        self.nmap_tool: Optional[NmapTool] = None
        self.gobuster_tool: Optional[GobusterTool] = None
        self.nikto_tool: Optional[NiktoTool] = None
        self.smb_tool: Optional[SmbTool] = None
        self.hydra_tool: Optional[HydraTool] = None
        self.http_fetcher_tool: Optional[HttpPageFetcherTool] = None  # ADDED
        self._initialize_tools()

        logger.info("SessionController initialized successfully.")

    def _initialize_tools(self):
        logger.debug("Initializing reconnaissance tools...")
        # For tools that are classes derived from CommandTool
        command_tool_classes = {
            "nmap_tool": NmapTool,
            "gobuster_tool": GobusterTool,
            "nikto_tool": NiktoTool,
            "smb_tool": SmbTool,
            "hydra_tool": HydraTool,
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

    def display_session_status(self):
        self.console.print(Markdown("### Alien Recon Session Status"))
        self.console.print(
            f"  🎯 Target: [bold cyan]{self.current_target or '[NOT SET]'}[/bold cyan]"
        )
        mode_text = "Novice" if self.is_novice_mode else "Expert"
        mode_style = "bold green" if self.is_novice_mode else "bold yellow"
        self.console.print(f"  🤖 Mode: [{mode_style}]{mode_text}[/{mode_style}]")
        if DEFAULT_WORDLIST:
            self.console.print(
                f"  📖 Default Gobuster Wordlist: {os.path.basename(DEFAULT_WORDLIST)}"
            )
        if DEFAULT_PASSWORD_LIST:
            self.console.print(
                f"  🔑 Default Hydra Password List: {os.path.basename(DEFAULT_PASSWORD_LIST)}"
            )
        else:
            self.console.print(
                "  🔑 Default Hydra Password List: [Not Set/Found - User/AI must specify]"
            )
        self.console.print("-" * 50)

    def set_target(self, target_address: str):
        is_valid_target = False
        if target_address:
            if (
                re.match(
                    r"^\d{1,3}(\.\d{1,3}){3}(?:/\d{1,2})?$", target_address.strip()
                )
                or "." in target_address.strip()
            ):
                is_valid_target = True

        if is_valid_target:
            clean_target = target_address.strip()
            if self.current_target != clean_target:
                self.current_target = clean_target
                self.console.print(
                    f"[bold blue]Session Target Locked:[/bold blue] {self.current_target}"
                )
                logger.info(f"Target set to: {self.current_target}")
                self.chat_history = []
                self.pending_tool_call = None
                logger.debug("Chat history cleared due to new target.")
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

    def set_novice_mode(self, novice: bool):
        if self.is_novice_mode != novice:
            self.is_novice_mode = novice
            mode_text = "Novice (more guidance)" if novice else "Expert (less guidance)"
            self.console.print(
                f"[cyan]Guidance mode set to: [bold]{mode_text}[/bold][/cyan]"
            )
            logger.info(f"Novice mode set to: {self.is_novice_mode}")
        else:
            mode_text = "Novice" if novice else "Expert"
            self.console.print(
                f"[cyan]Guidance mode is already [bold]{mode_text}[/bold].[/cyan]"
            )

    def start_interactive_recon_session(self):
        if not self.current_target:
            self.console.print(
                "[bold red]Recon Error: No target set. Use 'target <addr>' or `recon --target <addr>`.[/bold red]"
            )
            return

        self.console.print(Markdown(AGENT_WELCOME_MESSAGE))
        self.display_session_status()
        self.console.print("Type 'exit' or 'quit' to end recon and return to CLI.")
        self.console.print("-" * 50)

        logger.info(f"Starting interactive reconnaissance for {self.current_target}")

        if not self.chat_history:
            # Construct initial message that includes target information for the AI's first turn.
            # The AGENT_SYSTEM_PROMPT guides it to check for HTTP first.
            initial_user_msg = (
                f"Initiate reconnaissance for primary target coordinates: {self.current_target}. "
                "I am a beginner Earthling specimen. Please analyze any initial web presence and then propose broader scans like Nmap if needed."
            )
            self.chat_history.append({"role": "user", "content": initial_user_msg})
            ai_response = self._get_llm_response_from_agent()
            self._process_llm_message(ai_response)

        while True:
            try:
                if self.pending_tool_call:
                    if self._confirm_tool_proposal():
                        self._execute_and_process_tool_call()
                    else:
                        self._send_tool_cancellation_to_llm(
                            self.pending_tool_call.id,
                            self.pending_tool_call.function.name,
                        )
                        self.pending_tool_call = None
                        ai_response = self._get_llm_response_from_agent()
                        self._process_llm_message(ai_response)
                    continue

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

        self.pending_tool_call = None
        message_for_history: dict[str, Any] = {"role": "assistant"}
        if ai_message.content:
            message_for_history["content"] = ai_message.content
        else:
            message_for_history["content"] = None

        if ai_message.tool_calls:
            self.pending_tool_call = ai_message.tool_calls[0]
            logger.debug(
                f"LLM proposed tool call ID: {self.pending_tool_call.id}, "
                f"Func: {self.pending_tool_call.function.name}, "
                f"Args: {self.pending_tool_call.function.arguments}"
            )
            message_for_history["tool_calls"] = [
                tc.model_dump() for tc in ai_message.tool_calls
            ]

        if message_for_history["content"] or message_for_history.get("tool_calls"):
            if message_for_history["content"]:
                self.console.print(
                    Markdown(f"**Alien Recon:** {message_for_history['content']}")
                )
            self.chat_history.append(message_for_history)
        else:
            logger.warning("LLM message had no text content and no tool_calls.")
            self.console.print(
                "[grey50](Alien Recon offered no textual guidance and proposed no actions this turn.)[/grey50]"
            )

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
            self._send_tool_error_to_llm(
                self.pending_tool_call.id,
                tool_name_llm,
                f"Failed to parse arguments: {e}. Arguments received: {self.pending_tool_call.function.arguments}",
            )
            self.pending_tool_call = None
            return False

        tool_display_map = {
            "propose_nmap_scan": "Nmap Scan",
            "propose_gobuster_scan": "Gobuster Scan",
            "propose_nikto_scan": "Nikto Scan",
            "propose_smb_enum": "SMB Enum",
            "propose_hydra_bruteforce": "Hydra Brute-force",
            "propose_fetch_web_content": "Fetch Web Content",  # ADDED
        }
        display_name = tool_display_map.get(
            tool_name_llm,
            tool_name_llm.replace("propose_", "").replace("_", " ").title(),
        )

        self.console.rule(
            f"[bold yellow]Decision Point: {display_name} Proposal[/bold yellow]"
        )

        # Display arguments based on tool type
        if tool_name_llm == "propose_fetch_web_content":
            self.console.print(
                f"  [dim]URL to Fetch:[/dim] [cyan]{tool_args.get('url_to_fetch', 'N/A')}[/cyan]"
            )
        else:  # For other tools that typically have a 'target'
            display_target = tool_args.get("target", self.current_target)
            self.console.print(f"  [dim]Target:[/dim] [cyan]{display_target}[/cyan]")

            if tool_name_llm == "propose_nmap_scan":
                self.console.print(
                    f"  [dim]Nmap Args:[/dim] {tool_args.get('arguments', 'N/A')}"
                )
            elif tool_name_llm == "propose_gobuster_scan":
                self.console.print(f"  [dim]Port:[/dim] {tool_args.get('port', 'N/A')}")
                wl = tool_args.get("wordlist") or DEFAULT_WORDLIST
                self.console.print(
                    f"  [dim]Wordlist:[/dim] {os.path.basename(wl) if wl else 'Default/Not Set'}"
                )
                sc = tool_args.get("status_codes")
                if sc:
                    self.console.print(f"  [dim]Status Codes:[/dim] {sc}")
            elif tool_name_llm == "propose_nikto_scan":
                self.console.print(f"  [dim]Port:[/dim] {tool_args.get('port', 'N/A')}")
                na = tool_args.get("nikto_arguments")
                if na:
                    self.console.print(f"  [dim]Nikto Args:[/dim] {na}")
            elif tool_name_llm == "propose_smb_enum":
                ea = tool_args.get("enum_arguments")
                if ea:
                    self.console.print(f"  [dim]Enum4Linux Args:[/dim] {ea}")
            elif tool_name_llm == "propose_hydra_bruteforce":
                self.console.print(f"  [dim]Port:[/dim] {tool_args.get('port', 'N/A')}")
                self.console.print(
                    f"  [dim]Service:[/dim] {tool_args.get('service_protocol', 'N/A')}"
                )
                self.console.print(
                    f"  [dim]Username:[/dim] {tool_args.get('username', 'N/A')}"
                )
                pwl = tool_args.get("password_list") or DEFAULT_PASSWORD_LIST
                self.console.print(
                    f"  [dim]Password List:[/dim] {os.path.basename(pwl) if pwl else 'Default/Not Set'}"
                )
                if tool_args.get("path"):
                    self.console.print(f"  [dim]Path:[/dim] {tool_args.get('path')}")
                if tool_args.get("threads"):
                    self.console.print(
                        f"  [dim]Threads:[/dim] {tool_args.get('threads')}"
                    )
                if tool_args.get("hydra_options"):
                    self.console.print(
                        f"  [dim]Other Hydra Opts:[/dim] {tool_args.get('hydra_options')}"
                    )

        self.console.rule()

        if self.is_novice_mode:
            # For fetching web content, if it's just for AI context, maybe auto-confirm or make it less prominent?
            # For now, keep confirmation for all tools in novice mode.
            confirmation = (
                self.console.input("  Proceed with this action? (yes/no): ")
                .lower()
                .strip()
            )
            confirmed = confirmation in ["yes", "y"]
            if not confirmed:
                logger.info(f"User declined tool: {display_name} (Args: {tool_args})")
            return confirmed
        else:
            self.console.print(
                "  [italic green]Proceeding in Expert mode (auto-confirming)...[/italic green]"
            )
            return True

    def _send_tool_cancellation_to_llm(self, tool_call_id: str, function_name: str):
        if not tool_call_id or not function_name:
            logger.error(
                f"Cannot send tool cancellation: Missing tool_call_id ({tool_call_id}) or function_name ({function_name})."
            )
            return
        cancellation_content = json.dumps(
            {
                "status": "Cancelled by user",
                "message": "The Earthling specimen has declined the proposed action. Please suggest an alternative or ask for clarification based on previous findings.",
            }
        )
        tool_response_msg = {
            "role": "tool",
            "tool_call_id": tool_call_id,
            "name": function_name,
            "content": cancellation_content,
        }
        self.chat_history.append(tool_response_msg)
        logger.debug(
            f"Appended user cancellation for {function_name} (ID: {tool_call_id}) to history."
        )

    def _send_tool_error_to_llm(
        self, tool_call_id: str, function_name: str, error_message: str
    ):
        if not tool_call_id or not function_name:
            logger.error(
                "Cannot send tool error: Missing tool_call_id or function_name."
            )
            return
        error_content = json.dumps(
            {
                "status": "Error before execution",
                "error": error_message,
                "message": "There was an error processing the arguments for this tool or preparing it for execution. Please review the error and propose a corrected tool call or an alternative action.",
            }
        )
        tool_response_msg = {
            "role": "tool",
            "tool_call_id": tool_call_id,
            "name": function_name,
            "content": error_content,
        }
        self.chat_history.append(tool_response_msg)
        logger.debug(
            f"Appended client-side tool error for {function_name} (ID: {tool_call_id}) to history: {error_message}"
        )

    def _execute_and_process_tool_call(self):
        if not self.pending_tool_call:
            logger.error("Execute called but no tool_call pending/confirmed.")
            return

        tool_to_execute = self.pending_tool_call
        self.pending_tool_call = None

        tool_name_llm = tool_to_execute.function.name
        tool_id = tool_to_execute.id
        tool_args_str = tool_to_execute.function.arguments
        tool_result_content_dict: dict[str, Any] = {"findings": {}}

        try:
            tool_args_from_llm = json.loads(tool_args_str)
        except json.JSONDecodeError as e:
            logger.error(
                f"JSONDecodeError during execute for {tool_name_llm} args: {tool_args_str}. Error: {e}"
            )
            tool_result_content_dict["error"] = (
                f"Internal Error: Invalid arguments from LLM: {e}"
            )
            tool_result_content_dict["scan_summary"] = (
                "Tool argument processing error before execution."
            )
            self._send_tool_error_to_llm(
                tool_id, tool_name_llm, str(tool_result_content_dict["error"])
            )
            ai_follow_up_response = self._get_llm_response_from_agent()
            self._process_llm_message(ai_follow_up_response)
            return

        # For CommandTools, 'target' is primary. For HttpPageFetcher, 'url_to_fetch' is primary.
        # This logic handles the primary identifier for the operation.
        primary_identifier_for_log = ""
        if tool_name_llm == "propose_fetch_web_content":
            primary_identifier_for_log = tool_args_from_llm.get(
                "url_to_fetch", "N/A URL"
            )
        else:
            primary_identifier_for_log = tool_args_from_llm.get(
                "target", self.current_target or "N/A Target"
            )

        tool_display_name = (
            tool_name_llm.replace("propose_", "").replace("_", " ").title()
        )

        # Specific argument validation for HttpPageFetcherTool
        if tool_name_llm == "propose_fetch_web_content":
            url_to_fetch = tool_args_from_llm.get("url_to_fetch")
            if not url_to_fetch or not (
                url_to_fetch.startswith("http://")
                or url_to_fetch.startswith("https://")
            ):
                err_msg = f"Invalid or missing 'url_to_fetch' for {tool_name_llm}. Must be a full URL. Received: '{url_to_fetch}'"
                logger.error(err_msg)
                tool_result_content_dict = {
                    "error": err_msg,
                    "scan_summary": "HTTP Fetcher argument error.",
                }
                # Send error to LLM and get next response
                self._send_tool_error_to_llm(tool_id, tool_name_llm, err_msg)
                ai_follow_up_response = self._get_llm_response_from_agent()
                self._process_llm_message(ai_follow_up_response)
                return
        # General target validation for other tools
        elif (
            not tool_args_from_llm.get("target") and not self.current_target
        ):  # For CommandTools
            err_msg = f"No target available (from LLM args or session) for tool {tool_name_llm}."
            logger.error(err_msg)
            tool_result_content_dict = {
                "error": err_msg,
                "scan_summary": "Target missing for tool execution.",
            }
            self._send_tool_error_to_llm(tool_id, tool_name_llm, err_msg)
            ai_follow_up_response = self._get_llm_response_from_agent()
            self._process_llm_message(ai_follow_up_response)
            return

        # Prepare arguments for actual tool execution
        final_tool_args_for_execution = tool_args_from_llm.copy()
        if tool_name_llm != "propose_fetch_web_content":  # CommandTools expect 'target'
            # Ensure 'target' is the resolved one for CommandTools
            final_tool_args_for_execution["target"] = tool_args_from_llm.get(
                "target", self.current_target
            )

        tool_instance: Any = None  # Using Any for type hint flexibility here
        if tool_name_llm == "propose_nmap_scan":
            tool_instance = self.nmap_tool
        elif tool_name_llm == "propose_gobuster_scan":
            tool_instance = self.gobuster_tool
            if (
                "target" in final_tool_args_for_execution
            ):  # GobusterTool expects 'target_ip'
                final_tool_args_for_execution["target_ip"] = (
                    final_tool_args_for_execution.pop("target")
                )
        elif tool_name_llm == "propose_nikto_scan":
            tool_instance = self.nikto_tool
        elif tool_name_llm == "propose_smb_enum":
            tool_instance = self.smb_tool
        elif tool_name_llm == "propose_hydra_bruteforce":
            tool_instance = self.hydra_tool
        elif tool_name_llm == "propose_fetch_web_content":
            tool_instance = self.http_fetcher_tool

        self.console.print(
            f"[green]Engaging tool [bold]{tool_display_name}[/bold] on [cyan]{primary_identifier_for_log}[/cyan]...[/green]"
        )
        spinner = Spinner("dots", text=f" Executing {tool_display_name}...")
        with self.console.status(spinner):
            if tool_instance:
                # For CommandTool instances, check executable_path
                if (
                    hasattr(tool_instance, "executable_path")
                    and not tool_instance.executable_path
                ):
                    msg = (
                        f"Tool '{tool_name_llm}' cannot be executed because its executable path is not set. "
                        f"Ensure '{getattr(tool_instance, 'executable_name', 'tool')}' is installed and configured."
                    )
                    logger.error(msg)
                    tool_result_content_dict = {
                        "error": msg,
                        "scan_summary": "Tool misconfigured (no executable path).",
                    }
                else:  # Either a CommandTool with path, or a non-CommandTool like HttpPageFetcher
                    tool_result_content_dict = tool_instance.execute(
                        **final_tool_args_for_execution
                    )
            else:  # Tool instance itself is None (failed initialization)
                msg = (
                    f"Tool '{tool_name_llm}' cannot be executed because its instance is not available "
                    f"(it may have failed to initialize)."
                )
                logger.warning(msg)
                tool_result_content_dict = {
                    "error": msg,
                    "scan_summary": "Tool unavailable (initialization failed).",
                }

        if "scan_summary" not in tool_result_content_dict:
            tool_result_content_dict["scan_summary"] = tool_result_content_dict.get(
                "error", "Scan completed with undefined summary."
            )
        if "findings" not in tool_result_content_dict:
            tool_result_content_dict["findings"] = {}
        if (
            "error" in tool_result_content_dict
            and not tool_result_content_dict["error"]
        ):
            del tool_result_content_dict["error"]

        tool_result_for_llm_str = json.dumps(tool_result_content_dict)
        tool_response_message = {
            "role": "tool",
            "tool_call_id": tool_id,
            "name": tool_name_llm,
            "content": tool_result_for_llm_str,
        }
        self.chat_history.append(tool_response_message)
        logger.debug(
            f"Appended execution result for {tool_name_llm} (ID: {tool_id}) to history. Summary: {tool_result_content_dict['scan_summary']}"
        )

        ai_follow_up_response = self._get_llm_response_from_agent()
        self._process_llm_message(ai_follow_up_response)

    def start_auto_recon(self):
        if not self.current_target:
            self.console.print(
                "[bold red]Error: No target set for auto-reconnaissance.[/bold red]"
            )
            return
        self.console.print(
            f"[italic blue]Starting [bold]automated[/bold] reconnaissance for target: "
            f"{self.current_target}[/italic blue]"
        )
        self.console.print(
            "[grey50](Auto-recon is a planned feature and not yet implemented.)[/grey50]"
        )
        logger.info(f"Auto-recon attempt for {self.current_target} (not implemented).")
