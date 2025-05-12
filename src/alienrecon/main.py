#!/usr/bin/env python3

import json
import logging
import os
import re

# subprocess might still be used implicitly by run_command, leave it for now
import sys

# tempfile is no longer needed here as SmbTool handles it
# import tempfile
from rich.markdown import Markdown
from rich.spinner import Spinner

# --- Dependency Checks & Imports ---
# F401: `openai` imported but unused - REMOVED
# try:
# import openai
# except ImportError:
# print(
# "[-] Error: OpenAI library not found. Please install it using "
# "'pip install openai'"
# )
# sys.exit(1)
# --- Import from config module ---
# --- Import from agent module ---
from alienrecon.agent import (
    AGENT_SYSTEM_PROMPT,
    AGENT_WELCOME_MESSAGE,
    get_llm_response,
)
from alienrecon.config import (
    DEFAULT_WORDLIST,
    console,
    initialize_openai_client,
)
from alienrecon.tools.gobuster import GobusterTool
from alienrecon.tools.nikto import NiktoTool

# --- Import Tool Classes ---
from alienrecon.tools.nmap import NmapTool
from alienrecon.tools.smb import SmbTool  # <<< Added SmbTool import

# --- Core Tool Execution & Formatting Functions ---
# REMOVED: Old SMB functions are now handled by SmbTool class
# def execute_smb_enum(...): ...
# def format_smb_enum_results(...): ...

# --- Main Execution Loop ---
if __name__ == "__main__":
    console.print(Markdown("# Alien Recon AI Assistant - Initializing..."))
    openai_client = initialize_openai_client()
    if not openai_client:
        sys.exit(1)

    # --- Instantiate tools ---
    # Using individual try-except for now as per the original structure
    nmap_tool: NmapTool | None = None
    gobuster_tool: GobusterTool | None = None
    nikto_tool: NiktoTool | None = None
    smb_tool: SmbTool | None = None  # <<< Added SmbTool variable

    try:
        nmap_tool = NmapTool()
        if not nmap_tool.executable_path:
            console.print(
                "[bold orange_red1]Warning:[/bold orange_red1] Executable for "
                "'NmapTool' not found. This tool will be unavailable."
            )
            nmap_tool = None  # Mark as unavailable
    except Exception as e:
        console.print(f"[bold red]Error initializing NmapTool: {e}.[/bold red]")

    try:
        gobuster_tool = GobusterTool()
        if not gobuster_tool.executable_path:
            console.print(
                "[bold orange_red1]Warning:[/bold orange_red1] Executable for "
                "'GobusterTool' not found. This tool will be unavailable."
            )
            gobuster_tool = None
    except Exception as e:
        console.print(f"[bold red]Error initializing GobusterTool: {e}.[/bold red]")

    try:
        nikto_tool = NiktoTool()
        if not nikto_tool.executable_path:
            console.print(
                "[bold orange_red1]Warning:[/bold orange_red1] Executable for "
                "'NiktoTool' not found. This tool will be unavailable."
            )
            nikto_tool = None
    except Exception as e:
        console.print(f"[bold red]Error initializing NiktoTool: {e}.[/bold red]")

    try:  # <<< Added SmbTool instantiation
        smb_tool = SmbTool()
        if not smb_tool.executable_path:
            console.print(
                "[bold orange_red1]Warning:[/bold orange_red1] Executable for "
                "'SmbTool' (enum4linux-ng) not found. This tool will be "
                "unavailable."
            )
            smb_tool = None
    except Exception as e:
        console.print(f"[bold red]Error initializing SmbTool: {e}.[/bold red]")

    console.print(Markdown(f"**Alien Recon:** {AGENT_WELCOME_MESSAGE}"))
    console.print(
        f"Using default wordlist: {DEFAULT_WORDLIST if DEFAULT_WORDLIST else 'Not Set'}"
    )
    console.print("\nType 'exit' or 'quit' to end the session.")
    console.print("-" * 50)

    chat_history = []
    current_target = None
    pending_tool_call = None

    while True:
        try:
            if pending_tool_call:
                tool_name = pending_tool_call.function.name
                try:
                    tool_args = json.loads(pending_tool_call.function.arguments)
                except json.JSONDecodeError:
                    logging.error(
                        f"Failed to decode JSON args for {tool_name}: "
                        f"{pending_tool_call.function.arguments}"
                    )
                    console.print(
                        "[bold red]Error processing AI arguments. "
                        "Aborting proposal.[/bold red]"
                    )
                    pending_tool_call = None
                    continue

                # Construct confirmation prompt (remains mostly the same)
                prompt_text = "[bold yellow]Confirmation Required:[/bold yellow]\n"
                # Map proposed name to the internal tool name for display/logging
                tool_display_name_map = {
                    "propose_nmap_scan": "Nmap",
                    "propose_gobuster_scan": "Gobuster",
                    "propose_nikto_scan": "Nikto",
                    "propose_smb_enum": "SMB Enum (enum4linux-ng)",
                }
                display_name = tool_display_name_map.get(
                    tool_name, tool_name
                )  # Fallback to raw name

                prompt_details = f"  Tool: {display_name}\n"
                prompt_details += f"  Target: {tool_args.get('target')}\n"
                if "arguments" in tool_args:
                    prompt_details += f"  Nmap Args: {tool_args.get('arguments')}\n"
                if "port" in tool_args:
                    prompt_details += f"  Port: {tool_args.get('port')}\n"
                if "wordlist" in tool_args or tool_name == "propose_gobuster_scan":
                    wl = tool_args.get("wordlist") or DEFAULT_WORDLIST
                    prompt_details += (
                        f"  Wordlist: {os.path.basename(wl) if wl else 'Default'}\n"
                    )
                if "nikto_arguments" in tool_args:
                    prompt_details += (
                        f"  Nikto Args: "
                        f"{tool_args.get('nikto_arguments') or 'Default'}\n"
                    )
                if "enum_arguments" in tool_args:
                    prompt_details += (
                        f"  Enum Args: "
                        f"{tool_args.get('enum_arguments') or SmbTool.DEFAULT_ARGS}\n"
                    )
                prompt_text += prompt_details
                prompt_text += "Shall Alien Recon proceed? (yes/no): "

                confirmation = console.input(prompt_text).lower().strip()
                ai_message_after_tool = None

                if confirmation in ["yes", "y", "ok", "proceed", "affirmative"]:
                    console.print(
                        f"[green]Affirmative. Executing {display_name}...[/green]"
                    )
                    tool_result_content_dict = {}  # Store result as dict

                    # --- Execute the Confirmed Tool using Tool Classes ---
                    spinner = Spinner("dots", text=f" Executing {display_name}...")
                    with console.status(spinner):
                        try:
                            if tool_name == "propose_nmap_scan":
                                if nmap_tool:
                                    tool_result_content_dict = nmap_tool.execute(
                                        target=tool_args.get("target"),
                                        arguments=tool_args.get("arguments", "-sV -T4"),
                                    )
                                else:
                                    tool_result_content_dict = {
                                        "scan_summary": "Nmap execution failed.",
                                        "error": "NmapTool not available or "
                                        "failed to initialize.",
                                        "findings": {},
                                    }

                            elif tool_name == "propose_gobuster_scan":
                                if gobuster_tool:
                                    tool_result_content_dict = gobuster_tool.execute(
                                        target_ip=tool_args.get("target"),
                                        port=tool_args.get("port"),
                                        wordlist=tool_args.get("wordlist"),
                                    )
                                else:
                                    tool_result_content_dict = {
                                        "scan_summary": "Gobuster execution failed.",
                                        "error": "GobusterTool not available or "
                                        "failed to initialize.",
                                        "findings": {},
                                    }

                            elif tool_name == "propose_nikto_scan":
                                if nikto_tool:
                                    tool_result_content_dict = nikto_tool.execute(
                                        target=tool_args.get("target"),
                                        port=tool_args.get("port"),
                                        nikto_arguments=tool_args.get(
                                            "nikto_arguments"
                                        ),
                                    )
                                else:
                                    tool_result_content_dict = {
                                        "scan_summary": "Nikto execution failed.",
                                        "error": "NiktoTool not available or "
                                        "failed to initialize.",
                                        "findings": {},
                                    }

                            elif (
                                tool_name == "propose_smb_enum"
                            ):  # <<< Updated SMB block
                                if smb_tool:
                                    tool_result_content_dict = smb_tool.execute(
                                        target=tool_args.get("target"),
                                        enum_arguments=tool_args.get("enum_arguments"),
                                    )
                                else:
                                    tool_result_content_dict = {
                                        "scan_summary": "SMB Enumeration failed.",
                                        "error": "SmbTool not available or "
                                        "failed to initialize.",
                                        "findings": {},
                                    }

                            else:
                                logging.warning(
                                    "Attempted to execute unimplemented tool "
                                    f"function: {tool_name}"
                                )
                                tool_result_content_dict = {
                                    "scan_summary": f"{tool_name} execution failed.",
                                    "error": f"Tool function '{tool_name}' "
                                    "execution logic not implemented.",
                                    "findings": {},
                                }

                        except Exception as exec_err:
                            # Catch errors during tool's execute method
                            logging.error(
                                f"Error during {display_name} execution: {exec_err}",
                                exc_info=True,
                            )
                            tool_result_content_dict = {
                                "scan_summary": f"{display_name} execution "
                                "failed unexpectedly.",
                                "error": str(exec_err),
                                "findings": {},  # Ensure findings key exists
                            }

                    # Add Tool Call & Result to History
                    # Ensure findings key exists if tool failed badly
                    if "findings" not in tool_result_content_dict:
                        tool_result_content_dict["findings"] = {}
                    tool_result_content_str = json.dumps(tool_result_content_dict)
                    assistant_tool_call_message = {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": pending_tool_call.id,
                                "type": "function",
                                "function": {
                                    "name": pending_tool_call.function.name,
                                    "arguments": pending_tool_call.function.arguments,
                                },
                            }
                        ],
                    }
                    chat_history.append(assistant_tool_call_message)
                    tool_result_message = {
                        "role": "tool",
                        "tool_call_id": pending_tool_call.id,
                        "name": tool_name,
                        "content": tool_result_content_str,
                    }
                    chat_history.append(tool_result_message)
                    logging.info(
                        f"Appended tool result for {tool_name} "
                        f"(ID: {pending_tool_call.id}) to history."
                    )

                    pending_tool_call = None
                    ai_message_after_tool = get_llm_response(
                        openai_client, chat_history, AGENT_SYSTEM_PROMPT
                    )

                elif confirmation in ["no", "n", "negative", "cancel", "stop"]:
                    console.print(
                        "[yellow]Understood. Aborting the proposed scan.[/yellow]"
                    )
                    # Standard cancellation message logic
                    assistant_tool_call_message = {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": pending_tool_call.id,
                                "type": "function",
                                "function": {
                                    "name": pending_tool_call.function.name,
                                    "arguments": pending_tool_call.function.arguments,
                                },
                            }
                        ],
                    }
                    chat_history.append(assistant_tool_call_message)
                    cancellation_message = {
                        "role": "tool",
                        "tool_call_id": pending_tool_call.id,
                        "name": tool_name,
                        "content": json.dumps(
                            {
                                "status": "Cancelled",
                                "message": "User declined the proposed scan.",
                            }
                        ),
                    }
                    chat_history.append(cancellation_message)
                    logging.info(
                        f"Appended user cancellation for {tool_name} "
                        f"(ID: {pending_tool_call.id}) to history."
                    )
                    pending_tool_call = None
                    ai_message_after_tool = get_llm_response(
                        openai_client, chat_history, AGENT_SYSTEM_PROMPT
                    )

                else:  # Unclear confirmation
                    console.print(
                        "[yellow]Unclear response. Please answer 'yes' or 'no'. "
                        "Aborting scan proposal.[/yellow]"
                    )
                    # Standard unclear confirmation message logic
                    assistant_tool_call_message = {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": pending_tool_call.id,
                                "type": "function",
                                "function": {
                                    "name": pending_tool_call.function.name,
                                    "arguments": pending_tool_call.function.arguments,
                                },
                            }
                        ],
                    }
                    chat_history.append(assistant_tool_call_message)
                    unclear_message = {
                        "role": "tool",
                        "tool_call_id": pending_tool_call.id,
                        "name": tool_name,
                        "content": json.dumps(
                            {
                                "status": "Cancelled",
                                "message": "User provided unclear confirmation.",
                            }
                        ),
                    }
                    chat_history.append(unclear_message)
                    logging.info(
                        f"Appended unclear confirmation for {tool_name} "
                        f"(ID: {pending_tool_call.id}) to history."
                    )
                    pending_tool_call = None
                    ai_message_after_tool = get_llm_response(
                        openai_client, chat_history, AGENT_SYSTEM_PROMPT
                    )

                # Process LLM response AFTER handling confirmation/execution
                if ai_message_after_tool:
                    if ai_message_after_tool.tool_calls:
                        pending_tool_call = ai_message_after_tool.tool_calls[0]
                        logging.info(
                            "LLM proposed new tool call immediately: "
                            f"{pending_tool_call.function.name}"
                        )
                        if ai_message_after_tool.content:
                            console.print(
                                Markdown(
                                    f"**Alien Recon:** {ai_message_after_tool.content}"
                                )
                            )
                            chat_history.append(
                                {
                                    "role": "assistant",
                                    "content": ai_message_after_tool.content,
                                }
                            )
                    elif ai_message_after_tool.content:
                        ai_response_text = ai_message_after_tool.content
                        console.print(Markdown(f"**Alien Recon:** {ai_response_text}"))
                        chat_history.append(
                            {"role": "assistant", "content": ai_response_text}
                        )
                    else:
                        logging.warning(
                            "LLM message after tool handling had no content or "
                            "tool calls."
                        )
                        console.print(
                            "[grey50](Alien Recon provided no "  # CORRECTED LINE
                            "further guidance)[/grey50]"  # CORRECTED LINE
                        )
                else:
                    console.print(
                        "[bold red]AI assistant did not provide a response after "
                        "tool execution/cancellation.[/bold red]"
                    )

                continue  # Skip normal user input prompt

            # Step 2: Get User Input
            user_input = console.input("[bold cyan]You:[/bold cyan] ")
            user_input_lower = user_input.lower().strip()

            # Step 3: Handle Exit
            if user_input_lower in ["exit", "quit"]:
                console.print(
                    "[bold magenta]Deactivating Alien Recon Assistant. "
                    "Safe travels, Earthling.[/bold magenta]"
                )
                break
            if not user_input_lower:
                continue

            # Step 4: Process User Input
            chat_history.append({"role": "user", "content": user_input})

            # Handle Target Setting
            extracted_target = None
            target_command = False
            target_prefixes = ("target ", "analyze ", "set target ")
            if user_input_lower.startswith(target_prefixes):
                for prefix in target_prefixes:
                    if user_input_lower.startswith(prefix):
                        extracted_target = user_input[len(prefix) :].strip()
                        target_command = True
                        break
            elif current_target is None and (
                re.match(r"^\d{1,3}(\.\d{1,3}){3}$", user_input_lower)
                or (
                    "." in user_input_lower
                    and " " not in user_input_lower
                    and "/" not in user_input_lower
                )
            ):
                extracted_target = user_input_lower
                target_command = True
            if target_command:
                if extracted_target and (
                    re.match(r"^\d{1,3}(\.\d{1,3}){3}$", extracted_target)
                    or "." in extracted_target
                ):
                    current_target = extracted_target
                    console.print(
                        "[bold blue]Target Coordinates Updated:[/bold blue] "
                        f"{current_target}"
                    )
                else:
                    console.print(
                        f"[bold red]Invalid target format specified: "
                        f"'{extracted_target}'. Please provide a valid IP or "
                        f"domain name.[/bold red]"
                    )
                    # Pop invalid command from history
                    if (
                        chat_history
                        and chat_history[-1]["role"] == "user"
                        and chat_history[-1]["content"] == user_input
                    ):
                        chat_history.pop()
                continue  # Skip sending target command to LLM

            # Step 5: Get LLM Response
            ai_message = get_llm_response(
                openai_client, chat_history, AGENT_SYSTEM_PROMPT
            )

            # Step 6: Process LLM Response
            if ai_message:
                if ai_message.tool_calls:
                    pending_tool_call = ai_message.tool_calls[0]
                    logging.info(
                        f"LLM proposed tool call: {pending_tool_call.function.name}"
                    )
                    if ai_message.content:
                        console.print(
                            Markdown(f"**Alien Recon:** {ai_message.content}")
                        )
                        chat_history.append(
                            {"role": "assistant", "content": ai_message.content}
                        )
                elif ai_message.content:
                    ai_response_text = ai_message.content
                    console.print(Markdown(f"**Alien Recon:** {ai_response_text}"))
                    chat_history.append(
                        {"role": "assistant", "content": ai_response_text}
                    )
                else:
                    logging.warning(
                        "LLM message received with no content or tool calls."
                    )
                    console.print(
                        "[grey50](Alien Recon provided no actionable response)[/grey50]"
                    )
            else:  # Error handled in get_llm_response
                console.print(
                    "[bold red]AI assistant failed to respond. Please check "
                    "connection/API key and try again, or type 'exit'.[/bold red]"
                )

        except KeyboardInterrupt:
            console.print(
                "\n[bold magenta]Deactivation signal received (Ctrl+C). "
                "Shutting down.[/bold magenta]"
            )
            break
        except Exception as e:
            logging.critical(
                f"An critical error occurred in the main loop: {e}", exc_info=True
            )
            console.print(
                f"[bold red]\n!!! An unexpected critical error occurred: {e} "
                f"!!![/bold red]"
            )
            console.print("[bold red]Exiting Alien Recon due to error.[/bold red]")
            break
