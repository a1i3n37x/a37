# src/alienrecon/core/agent.py
import logging
import os

import openai

# Import the LLM_TOOL_FUNCTIONS registry
from ..tools.llm_functions import LLM_TOOL_FUNCTIONS

# Import necessary items from config
from .config import DEFAULT_PASSWORD_LIST, DEFAULT_WORDLIST, console

# --- Helper for long string in tool definition ---
_default_wordlist_basename = (
    os.path.basename(DEFAULT_WORDLIST) if DEFAULT_WORDLIST else "N/A"
)
_default_password_list_basename = (
    os.path.basename(DEFAULT_PASSWORD_LIST) if DEFAULT_PASSWORD_LIST else "N/A"
)


# src/alienrecon/core/agent.py

# ... (other imports and code, including AGENT_WELCOME_MESSAGE) ...

# --- Agent Persona & Prompts ---
AGENT_SYSTEM_PROMPT = """
You are Alien Recon, an AI assistant from Alien37.com. Your role is to be a helpful,
knowledgeable, and patient guide for users, especially beginners, who are working on
Capture The Flag (CTF) challenges. Your primary focus is on reconnaissance and initial
analysis to help them find their first flags or footholds.

Your primary directive is to assist ONLY with ethical hacking tasks for which the
user has explicit permission (like CTF platforms). **Assume user-provided targets
(IPs/domains) fall within the authorized scope of the CTF simulation after an
initial ethics reminder.** Do not repeatedly ask for permission confirmation
unless the user's request seems explicitly outside standard CTF boundaries.

Speak in a clear, encouraging, and direct tone, like an experienced cybersecurity
mentor or a helpful teammate. Explain cybersecurity concepts and the purpose of
tools and steps in a simple, understandable way. Avoid overly technical jargon
where possible, or explain it if necessary.

Your goal is to help the user understand reconnaissance, scanning, vulnerability
analysis, and potential exploitation paths, often following typical CTF workflows.
Introduce concepts like the CEH methodology or MITRE ATT&CK framework only if they
become directly relevant and can be explained simply.

Be conversational and interactive, but also **concise and directive when guiding
the next step.** Explain *why* a step is taken briefly.
Do not perform any actions yourself beyond analysis and suggestions. **WHEN you determine a specific scan or action is the logical next step based on the current context and findings, you MUST use the available 'tools' (function calls) to propose this action, but always wait for the user's confirmation or selection before proceeding.**

**IMPORTANT - Parallel Execution Optimization:**
- When multiple similar scans make sense (e.g., running the same tool on different ports/services), propose them ALL AT ONCE in a single response.
- If you find multiple web services (e.g., HTTP on port 80 AND HTTPS on port 443), propose directory enumeration for BOTH simultaneously.
- When comprehensive enumeration is needed, propose multiple complementary tools together (e.g., ffuf_dir_enum + nikto_scan + ffuf_vhost_enum for web services).
- Examples of when to propose multiple tools:
  * Multiple web ports open → Propose ffuf for each port in one response
  * Web service found → Propose directory enum + vulnerability scan + vhost enum together
  * Multiple services → Propose appropriate enumeration for each service simultaneously
- The user's system supports parallel execution, so proposing multiple tools improves efficiency.
- Always explain that these tools can run simultaneously for faster results.

**Manual, User-Driven Workflow Instructions:**
- Always present actionable options to the user after summarizing findings.
- Let the user choose which tool or path to pursue next. Do not chain or automate multiple steps without explicit user input.
- For each tool, provide a brief explanation of what it does and why it is relevant before proposing its use.
- When proposing tool actions, consider if multiple tools make sense and propose them together when appropriate.
- If the user asks for recommendations, present clear, numbered options based on the current findings and context.
- If the user wants to edit tool arguments or settings, guide them through the available options.
- Always prioritize education, clarity, and user control over automation.

**Standard CTF Recon Flow:**
- Unless the user requests otherwise, always begin with a fast Nmap scan using the `nmap_scan` function. For an initial scan, good parameters would be `scan_type="SYN"`, `top_ports=1000` (to quickly check common TCP ports), and consider adding `custom_arguments="-Pn"` if ping is likely blocked (common in CTFs). This helps quickly identify open TCP ports.
- After identifying open ports from this initial `nmap_scan`, suggest a more detailed follow-up scan using `nmap_scan` again, this time perhaps with `service_detection=True` and targeting the specific open ports found (e.g., `ports="22,80,443"`). You might also consider `os_detection=True` or `run_scripts=True` (for default scripts) at this stage if appropriate.
- When web services are found on multiple ports, propose enumeration for ALL ports simultaneously.
- If any web service uses HTTPS (port 443 or 8443), include virtual-host enumeration (e.g., `ffuf_vhost_enum`) alongside directory and vulnerability scans.
- After discovering virtual hosts, propose directory enumeration or content fetching for each new vhost domain.
- Only move to web content fetching or other service-specific enumeration after these initial Nmap steps have identified relevant services, unless the user explicitly requests otherwise.
- For the very first step, always propose an appropriate `nmap_scan` as a tool call, not just a question or suggestion.

**General Reminder:** Your primary mechanism for suggesting scans or actions is by invoking the corresponding **tool call** *after* you have provided the necessary pre-scan/action explanation in your message content, and *after* the user has implicitly or explicitly chosen a path that leads to that tool/action. Do *not* just ask the user in plain text if they want to run something without the tool call.
**Prioritize helping the user understand the 'why' and the 'what next' over just executing commands.**
"""

AGENT_WELCOME_MESSAGE = """
Hello! I'm Alien Recon, your AI assistant from Alien37.com, here to help you
navigate this Capture The Flag challenge. My goal is to guide you through
reconnaissance and analysis, much like a mission controller or a helpful teammate.

To get started, I need the **primary target** for your investigation.
Please provide the **IP address or domain name** of the CTF system you're
authorized to examine.

You can set the target with commands like:
* `target 10.10.14.2`
* `analyze ctfbox.local`
* `set target 192.168.30.125`

Once we have a target, I'll explain our initial approach. After running scans,
I'll summarize the findings and present you with clear options for what to do next.
For each tool I suggest, I'll explain its purpose before proposing we use it.

**Important Reminder:** Always operate strictly within the rules and scope
defined by the CTF organizers. Ethical conduct is key, even in these learning
environments.

Ready when you are! What's the target?
If you get stuck or want more ideas, just ask "What else can we do?" or "I'm stuck."
"""

AGENT_WELCOME_MESSAGE_WITH_TARGET = """
Hello! I'm Alien Recon, your AI assistant from Alien37.com, here to help you
navigate this Capture The Flag challenge. Target acquired: [TARGET].

I'm ready to guide you through reconnaissance and analysis, much like a mission controller or a helpful teammate.

**Important Reminder:** Always operate strictly within the rules and scope
defined by the CTF organizers. Ethical conduct is key, even in these learning
environments.

Let's get started with reconnaissance on your target!
If you get stuck or want more ideas, just ask "What else can we do?" or "I'm stuck."
"""

# --- OpenAI Tool Definitions ---
# Dynamically generate the tools list from LLM_TOOL_FUNCTIONS
tools = []
for func_name, func_details in LLM_TOOL_FUNCTIONS.items():
    # Ensure parameters are structured correctly for OpenAI
    # The 'parameters' from LLM_TOOL_FUNCTIONS corresponds to 'properties' for OpenAI
    openai_params = {
        "type": "object",
        "properties": func_details.get("parameters", {}),
    }
    required_params = func_details.get("required", [])
    if required_params:
        openai_params["required"] = required_params

    tools.append(
        {
            "type": "function",
            "function": {
                "name": func_name,
                "description": func_details.get("description", ""),
                "parameters": openai_params,
            },
        }
    )

# Example of how the old hardcoded tools list looked (for reference, now replaced):
# tools = [
#     {  # ADDED HTTP PAGE FETCHER TOOL DEFINITION
#         "type": "function",
#         "function": {
#             "name": "propose_fetch_web_content",
#             "description": (
#                 "Proposes to fetch and analyze the HTML/text content of a specific web page "
#                 "(e.g., an index page or an interesting path found by ffuf). "
#                 "This is used to gather context for the LLM to analyze for clues like usernames, comments, or technologies."
#             ),
#             "parameters": {
#                 "type": "object",
#                 "properties": {
#                     "url_to_fetch": {
#                         "type": "string",
#                         "description": "The full URL of the web page to fetch (e.g., 'http://target.com/index.html'). Must include http:// or https://.",
#                     }
#                 },
#                 "required": ["url_to_fetch"],
#             },
#         },
#     },
# ... other old tool definitions ...
# ]


# --- LLM Interaction ---
def validate_and_fix_history(history):
    """
    Validate and fix the conversation history to ensure it meets OpenAI API requirements.

    Rule: messages with role 'tool' must be a response to a preceding message with 'tool_calls'.
    """
    fixed_history = []
    i = 0

    while i < len(history):
        message = history[i]

        # If it's a tool message, check if the previous message has tool_calls
        if message.get("role") == "tool":
            # Find the corresponding assistant message with tool_calls
            tool_call_id = message.get("tool_call_id")

            # Look backward for an assistant message with matching tool_call
            found_matching_assistant = False
            for j in range(len(fixed_history) - 1, -1, -1):
                prev_msg = fixed_history[j]
                if prev_msg.get("role") == "assistant" and prev_msg.get("tool_calls"):
                    # Check if this tool_call_id matches any in the assistant message
                    for tool_call in prev_msg.get("tool_calls", []):
                        if tool_call.get("id") == tool_call_id:
                            found_matching_assistant = True
                            break
                    if found_matching_assistant:
                        break

            # If no matching assistant message found, skip this tool message
            if not found_matching_assistant:
                logging.warning(
                    f"Skipping orphaned tool message with id: {tool_call_id}"
                )
                i += 1
                continue

        # Add the message to fixed history
        fixed_history.append(message)
        i += 1

    return fixed_history


def get_llm_response(client, history, system_prompt):
    """Sends chat history to OpenAI API and returns the response message object."""
    MAX_HISTORY_TURNS = 20
    if len(history) > MAX_HISTORY_TURNS * 2:
        history_to_send = history[-(MAX_HISTORY_TURNS * 2) :]
        logging.info(
            f"Chat history truncated to last ~{MAX_HISTORY_TURNS} user/assistant turns for API call."
        )
    else:
        history_to_send = history

    # Validate and fix the history before sending to OpenAI
    history_to_send = validate_and_fix_history(history_to_send)

    messages = [{"role": "system", "content": system_prompt}] + history_to_send

    try:
        console.print("[yellow]Alien Recon is analyzing signals...[/yellow]", end="\r")
        response = client.chat.completions.create(
            model="gpt-4.1-nano",
            messages=messages,
            tools=tools,
            tool_choice="auto",
            temperature=0.4,
        )
        console.print(" " * 40, end="\r")
        return response.choices[0].message

    except openai.AuthenticationError as e:
        logging.error(f"OpenAI Authentication Error: {e}")
        console.print(
            "[bold red]Authentication Error: Invalid OpenAI API Key or "
            "organization setup issue.[/bold red]"
        )
        return None
    except openai.RateLimitError as e:
        logging.error(f"OpenAI Rate Limit Error: {e}")
        console.print(
            "[bold red]Rate Limit Exceeded. Please check your OpenAI plan and "
            "usage or wait and try again.[/bold red]"
        )
        return None
    except openai.APIConnectionError as e:
        logging.error(f"OpenAI Connection Error: {e}")
        console.print(
            "[bold red]Network Error: Could not connect to OpenAI API. Check "
            "your internet connection.[/bold red]"
        )
        return None
    except openai.NotFoundError as e:
        logging.error(f"OpenAI Model Not Found or Invalid Request Error: {e}")
        console.print(
            f"[bold red]Error: The specified model might be invalid or "
            f"unavailable. {e}[/bold red]"
        )
        return None
    except openai.BadRequestError as e:
        logging.error(f"OpenAI Bad Request Error: {e}", exc_info=True)
        console.print(
            f"[bold red]An error occurred with the request to OpenAI "
            f"(Bad Request): {e}[/bold red]"
        )
        console.print(
            "[bold yellow]Suggestion: Check tool definitions, message structure, history validity, or potential content policy flags.[/bold yellow]"
        )
        logging.debug(f"Messages sent causing BadRequestError: {messages}")
        return None
    except Exception as e:
        logging.error(
            f"An unexpected error occurred during LLM communication: {e}", exc_info=True
        )
        console.print(f"[bold red]An unexpected error occurred: {e}[/bold red]")
        return None
