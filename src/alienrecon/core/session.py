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

from ..tools.gobuster import GobusterTool
from ..tools.nikto import NiktoTool

# Tool imports
from ..tools.nmap import NmapTool
from ..tools.smb import SmbTool
from .agent import (
    AGENT_SYSTEM_PROMPT,
    AGENT_WELCOME_MESSAGE,
    get_llm_response,
    # tools as llm_tools_defined_in_agent # Not strictly needed by SessionController
)

# Config and Agent imports
from .config import (
    DEFAULT_WORDLIST,
    initialize_openai_client,
)

logger = logging.getLogger(__name__)


class SessionController:
    def __init__(self):
        self.console = Console()
        logger.debug("Initializing SessionController...")  # Changed from INFO to DEBUG
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
        self._initialize_tools()

        logger.info(
            "SessionController initialized successfully."
        )  # Kept as INFO: key component ready

    def _initialize_tools(self):
        logger.debug("Initializing reconnaissance tools...")
        tool_classes = {
            "nmap_tool": NmapTool,
            "gobuster_tool": GobusterTool,
            "nikto_tool": NiktoTool,
            "smb_tool": SmbTool,
        }
        for attr_name, tool_class in tool_classes.items():
            try:
                instance = tool_class()
                if not instance.executable_path:
                    logger.warning(
                        f"{tool_class.__name__} executable not found. Tool unavailable."
                    )
                    setattr(self, attr_name, None)
                else:
                    setattr(self, attr_name, instance)
                    logger.debug(f"{tool_class.__name__} initialized.")
            except Exception as e:
                logger.error(
                    f"Error initializing {tool_class.__name__}: {e}", exc_info=True
                )
                setattr(self, attr_name, None)
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
        self.console.print("-" * 50)

    def set_target(self, target_address: str):
        is_valid_target = False
        if target_address:
            if (
                re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target_address)
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
                logger.info(
                    f"Target set to: {self.current_target}"
                )  # Kept as INFO: important event
                self.chat_history = []
                self.pending_tool_call = None
                logger.debug(
                    "Chat history cleared due to new target."
                )  # Changed from INFO to DEBUG
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
            logger.info(
                f"Novice mode set to: {self.is_novice_mode}"
            )  # Kept as INFO: user-initiated change
        else:
            mode_text = "Novice" if novice else "Expert"
            self.console.print(
                f"[cyan]Guidance mode is already [bold]{mode_text}[/bold].[/cyan]"
            )

    def start_interactive_recon_session(self):
        if not self.current_target:
            self.console.print(
                "[bold red]Recon Error: No target set. Use 'target <addr>'.[/bold red]"
            )
            return

        self.console.print(Markdown(AGENT_WELCOME_MESSAGE))
        self.display_session_status()
        self.console.print("Type 'exit' or 'quit' to end recon and return to CLI.")
        self.console.print("-" * 50)

        logger.info(
            f"Starting interactive reconnaissance for {self.current_target}"
        )  # Kept as INFO

        initial_user_msg = (
            f"Initiate reconnaissance for target: {self.current_target}. "
            "Provide analysis and propose the first logical scan."
        )
        self.chat_history.append({"role": "user", "content": initial_user_msg})
        ai_response = self._get_llm_response_from_agent()
        self._process_llm_message(ai_response)

        while True:
            try:
                if self.pending_tool_call:
                    if self._confirm_tool_proposal():
                        self._execute_and_process_tool_call()  # This gets new LLM response internally
                    else:  # User cancelled
                        self._send_tool_cancellation_to_llm(
                            self.pending_tool_call.id,
                            self.pending_tool_call.function.name,
                        )
                        self.pending_tool_call = None  # Clear it
                        ai_response = (
                            self._get_llm_response_from_agent()
                        )  # Get LLM reaction
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

    def _get_llm_response_from_agent(self) -> Optional[ChatCompletionMessage]:
        logger.debug(
            f"Sending {len(self.chat_history)} messages to LLM. Last: {self.chat_history[-1]['content'][:70] if self.chat_history else 'None'}"
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
            logger.debug(f"LLM response. Content: {log_content}... Tools: {log_tools}")
        else:
            logger.warning("get_llm_response returned None.")
        return ai_message_obj

    def _process_llm_message(self, ai_message: Optional[ChatCompletionMessage]):
        if not ai_message:
            self.console.print("[red](Alien Recon did not respond.)[/red]")
            return

        self.pending_tool_call = None

        message_for_history = {"role": "assistant", "content": ai_message.content}

        if ai_message.tool_calls:
            self.pending_tool_call = ai_message.tool_calls[0]
            logger.debug(  # Changed from INFO to DEBUG
                f"LLM proposed tool call ID: {self.pending_tool_call.id}, "
                f"Func: {self.pending_tool_call.function.name}, "
                f"Args: {self.pending_tool_call.function.arguments}"
            )
            message_for_history["tool_calls"] = [
                tc.model_dump() for tc in ai_message.tool_calls
            ]
            if not ai_message.content:
                message_for_history["content"] = None

        if ai_message.content or ai_message.tool_calls:
            if ai_message.content:
                self.console.print(Markdown(f"**Alien Recon:** {ai_message.content}"))
            self.chat_history.append(message_for_history)
        else:
            logger.warning("LLM message had no content and no tool_calls.")
            self.console.print(
                "[grey50](Alien Recon offered no further guidance.)[/grey50]"
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
                f"JSONDecodeError for {tool_name_llm} args: {self.pending_tool_call.function.arguments}. E: {e}"
            )
            self.console.print(
                "[bold red]Error: AI proposed action with invalid arguments. Aborting.[/bold red]"
            )
            return False

        tool_display_map = {
            "propose_nmap_scan": "Nmap",
            "propose_gobuster_scan": "Gobuster",
            "propose_nikto_scan": "Nikto",
            "propose_smb_enum": "SMB Enum",
        }
        display_name = tool_display_map.get(
            tool_name_llm, tool_name_llm.replace("propose_", "")
        )

        self.console.rule(
            f"[bold yellow]Decision Point: {display_name} Scan Proposal[/bold yellow]"
        )
        display_target = tool_args.get("target", self.current_target)
        self.console.print(f"  [dim]Target:[/dim] [cyan]{display_target}[/cyan]")

        if "arguments" in tool_args:
            self.console.print(f"  [dim]Nmap Args:[/dim] {tool_args['arguments']}")
        if "port" in tool_args:
            self.console.print(f"  [dim]Port:[/dim] {tool_args['port']}")
        if "wordlist" in tool_args or tool_name_llm == "propose_gobuster_scan":
            wl = tool_args.get("wordlist") or DEFAULT_WORDLIST
            self.console.print(
                f"  [dim]Wordlist:[/dim] {os.path.basename(wl) if wl else 'Default'}"
            )
        if "nikto_arguments" in tool_args:
            self.console.print(
                f"  [dim]Nikto Args:[/dim] {tool_args.get('nikto_arguments') or 'Default'}"
            )
        if "enum_arguments" in tool_args and self.smb_tool:
            default_smb_args = (
                self.smb_tool.DEFAULT_ARGS if self.smb_tool else "-A (default)"
            )
            self.console.print(
                f"  [dim]SMB Enum Args:[/dim] {tool_args.get('enum_arguments') or default_smb_args}"
            )
        self.console.rule()

        if self.is_novice_mode:
            confirmation = (
                self.console.input("  Proceed with this action? (yes/no): ")
                .lower()
                .strip()
            )
            confirmed = confirmation in ["yes", "y"]
            if not confirmed:
                logger.info(  # Kept as INFO: User explicitly declined a proposal
                    f"User declined tool: {display_name} for target {display_target}"
                )
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
                "message": "The Earthling specimen has declined the proposed scan. Please suggest an alternative or ask for clarification.",
            }
        )
        tool_response_msg = {
            "role": "tool",
            "tool_call_id": tool_call_id,
            "name": function_name,
            "content": cancellation_content,
        }
        self.chat_history.append(tool_response_msg)
        logger.debug(  # Changed from INFO to DEBUG
            f"Appended user cancellation for {function_name} (ID: {tool_call_id}) to history."
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
        tool_result_content_dict = {"findings": {}}

        try:
            tool_args_from_llm = json.loads(tool_args_str)
        except json.JSONDecodeError as e:
            logger.error(
                f"JSONDecodeError for {tool_name_llm} args: {tool_args_str}. E: {e}"
            )
            tool_result_content_dict["error"] = f"Invalid arguments from LLM: {e}"
            tool_result_content_dict["scan_summary"] = "Tool argument processing error."
        else:
            target_for_tool = tool_args_from_llm.get("target", self.current_target)
            if not target_for_tool:
                err_msg = f"No target available (from LLM args or session) for tool {tool_name_llm}."
                logger.error(err_msg)
                tool_result_content_dict["error"] = err_msg
                tool_result_content_dict["scan_summary"] = (
                    "Target missing for tool execution."
                )
            else:
                final_tool_args = tool_args_from_llm.copy()
                final_tool_args["target"] = target_for_tool

                tool_display_name = tool_name_llm.replace("propose_", "")
                self.console.print(
                    f"[green]Engaging tool [bold]{tool_display_name}[/bold] on target [cyan]{target_for_tool}[/cyan]...[/green]"
                )
                spinner = Spinner("dots", text=f" Executing {tool_display_name}...")
                with self.console.status(spinner):
                    if tool_name_llm == "propose_nmap_scan" and self.nmap_tool:
                        tool_result_content_dict = self.nmap_tool.execute(
                            **final_tool_args
                        )
                    elif (
                        tool_name_llm == "propose_gobuster_scan" and self.gobuster_tool
                    ):
                        gb_exec_args = {
                            "target_ip": final_tool_args.get("target"),
                            "port": final_tool_args.get("port"),
                            "wordlist": final_tool_args.get("wordlist"),
                        }
                        gb_exec_args_clean = {
                            k: v for k, v in gb_exec_args.items() if v is not None
                        }
                        tool_result_content_dict = self.gobuster_tool.execute(
                            **gb_exec_args_clean
                        )
                    elif tool_name_llm == "propose_nikto_scan" and self.nikto_tool:
                        tool_result_content_dict = self.nikto_tool.execute(
                            **final_tool_args
                        )
                    elif tool_name_llm == "propose_smb_enum" and self.smb_tool:
                        tool_result_content_dict = self.smb_tool.execute(
                            **final_tool_args
                        )
                    else:
                        msg = f"Tool '{tool_name_llm}' is not available/recognized or failed to init."
                        logger.warning(msg)
                        tool_result_content_dict = {
                            "error": msg,
                            "scan_summary": "Tool unavailable.",
                        }

        if "scan_summary" not in tool_result_content_dict:
            tool_result_content_dict["scan_summary"] = tool_result_content_dict.get(
                "error", "Scan completed."
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
        logger.debug(  # Changed from INFO to DEBUG
            f"Appended execution result for {tool_name_llm} (ID: {tool_id}) to history."
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
            "[grey50]Auto-recon (Phase 3 - TODO: Implement TaskQueue logic)...[/grey50]"
        )
