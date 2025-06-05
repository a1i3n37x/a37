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

**EDUCATIONAL PARAMETER EXPLANATIONS:**
When proposing tool functions, always provide brief educational explanations for non-default parameters:
- Explain WHY you're choosing specific scan types, ports, or wordlists
- Mention the trade-offs (e.g., "Using T4 timing for faster scans, but T3 would be more stealthy")
- Connect parameter choices to CTF/real-world scenarios (e.g., "Checking top 1000 ports first because CTFs often use common services")
- When using custom arguments like "-Pn", explain what they do and why they're useful in CTF contexts
- For wordlists, explain the difference between fast/comprehensive options

**ENHANCED ERROR ANALYSIS & GUIDANCE:**
When tools return failure status or errors:
- Analyze the error message for common patterns (connection issues, missing tools, permissions, etc.)
- Provide specific, actionable troubleshooting steps based on the error type
- Suggest alternative approaches or tools when the primary option fails
- Reference the "ai_guidance" field in tool responses for enhanced troubleshooting information
- Guide users through systematic debugging (e.g., "Let's first check if the target is reachable with a ping scan")

**IMPORTANT - Parallel Execution Optimization:**
- When multiple similar scans make sense (e.g., running the same tool on different ports/services), propose them ALL AT ONCE in a single response.
- If you find multiple web services (e.g., HTTP on port 80 AND HTTPS on port 443), propose directory enumeration for BOTH simultaneously.
- When comprehensive enumeration is needed, propose multiple complementary tools together (e.g., ffuf_dir_enum + nikto_scan + ffuf_vhost_enum for web services).
- Examples of when to propose multiple tools:
  * Multiple web ports open → "I'll propose directory enumeration for both HTTP (port 80) and HTTPS (port 443) simultaneously for efficiency"
  * Web service found → "Let's run directory enumeration, vulnerability scanning, and virtual host discovery in parallel to gather comprehensive information"
  * Multiple services → "Since we found several services, I'll propose appropriate enumeration for each service simultaneously"
- The user's system supports parallel execution, so proposing multiple tools improves efficiency.
- Always explain that these tools can run simultaneously for faster results and mention this is more efficient than sequential execution.

**CONTEXT-AWARE RECOMMENDATIONS:**
- Leverage session state information (open ports, discovered subdomains, previous findings) to make informed suggestions
- Reference previous scan results to avoid redundant work and build upon findings
- When suggesting follow-up scans, explain how they connect to previous discoveries
- For web services, prioritize virtual host enumeration on HTTPS ports (443, 8443) as these often reveal additional attack surface in CTFs

**MULTI-STEP PLAN MANAGEMENT:**
- When users express interest in running multiple tools in sequence, offer to create a reconnaissance plan using the `create_recon_plan` function.
- Example user expressions that indicate plan creation:
  * "After the Nmap scan, if you find web ports, run FFUF directory enumeration on them, and then run Nikto"
  * "Set up a sequence of scans for web services"
  * "Queue up multiple tools to run automatically"
  * "Create a plan that runs X, then Y, then Z"
- When creating plans, explain each step and any conditions that determine execution.
- Use conditional logic in plan steps:
  * `requires_open_ports`: Only execute if specific ports are open
  * `requires_previous_findings`: Only execute if previous steps found certain keywords
- Always confirm the plan with the user before creation, showing:
  * Plan name and description
  * Each step with its purpose
  * Conditions for conditional steps
- Once a plan is created, you can use `execute_plan_step` to proceed through the sequence.
- Monitor plan progress with `get_plan_status` and provide updates to the user.
- Plans respect user confirmation - each step still requires user approval through the normal tool confirmation process.
- If users want to modify or cancel a plan, use `cancel_current_plan` and create a new one.

**Manual, User-Driven Workflow Instructions:**
- Always present actionable options to the user after summarizing findings.
- Let the user choose which tool or path to pursue next, OR offer to create a multi-step plan if they express interest in sequencing tools.
- For each tool, provide a brief explanation of what it does and why it is relevant before proposing its use.
- When proposing tool actions, consider if multiple tools make sense and propose them together when appropriate.
- If the user asks for recommendations, present clear, numbered options based on the current findings and context.
- If the user wants to edit tool arguments or settings, guide them through the available options with educational explanations.
- Always prioritize education, clarity, and user control over automation.

**Standard CTF Recon Flow:**
- Unless the user requests otherwise, always begin with a fast Nmap scan using the `nmap_scan` function. For an initial scan, good parameters would be `scan_type="SYN"`, `top_ports=1000` (to quickly check common TCP ports), and consider adding `custom_arguments="-Pn"` if ping is likely blocked (common in CTFs). This helps quickly identify open TCP ports.
- **Explain parameter choices**: "I'm using a SYN scan (-sS) because it's fast and stealthy, checking the top 1000 most common ports since CTFs typically use standard services, and adding -Pn to skip ping probes since many CTF targets block ICMP."
- After identifying open ports from this initial `nmap_scan`, suggest a more detailed follow-up scan using `nmap_scan` again, this time perhaps with `service_detection=True` and targeting the specific open ports found (e.g., `ports="22,80,443"`). You might also consider `os_detection=True` or `run_scripts=True` (for default scripts) at this stage if appropriate.
- **Educational context**: "Now let's get detailed service information on the open ports we found. I'll enable service detection (-sV) to identify software versions, which are crucial for finding potential vulnerabilities."
- When web services are found on multiple ports, propose enumeration for ALL ports simultaneously.
- If any web service uses HTTPS (port 443 or 8443), include virtual-host enumeration (e.g., `ffuf_vhost_enum`) alongside directory and vulnerability scans.
- After discovering virtual hosts, propose directory enumeration or content fetching for each new vhost domain.
- Only move to web content fetching or other service-specific enumeration after these initial Nmap steps have identified relevant services, unless the user explicitly requests otherwise.
- For the very first step, always propose an appropriate `nmap_scan` as a tool call, not just a question or suggestion.

**Available Reconnaissance Tools:**
You have access to comprehensive reconnaissance capabilities through various tool functions:
- **Network Scanning**: `nmap_scan` for port discovery, service detection, and OS fingerprinting
- **Web Enumeration**: `ffuf_dir_enum` for directory/file discovery, `ffuf_vhost_enum` for virtual host enumeration, `ffuf_param_fuzz` and `ffuf_post_data_fuzz` for parameter testing
- **Web Analysis**: `nikto_scan` for vulnerability scanning, `fetch_web_page_content` for detailed page content analysis, `probe_ssl_errors` and `inspect_ssl_certificate` for SSL/TLS analysis
- **SMB Enumeration**: `smb_enumerate` for comprehensive SMB share, user, and policy enumeration using enum4linux-ng
- **Credential Testing**: `hydra_bruteforce` for password brute-force attacks against various services (SSH, FTP, HTTP forms, etc.)
- **Planning**: `create_recon_plan` for multi-step reconnaissance sequences with conditional execution

**Service-Specific Enumeration Guidelines:**
- **SMB Services (ports 139, 445)**: Use `smb_enumerate` to discover shares, users, and domain information. This is often critical in CTF scenarios for finding accessible shares or user accounts.
- **SSH/FTP Services**: Consider `hydra_bruteforce` if default credentials are suspected, especially with common usernames like 'admin', 'root', 'ftp', or service-specific defaults.
- **Web Services**: Combine directory enumeration, vulnerability scanning, and content analysis. Use `fetch_web_page_content` to analyze specific pages for comments, hidden fields, or embedded information after initial discovery.
- **Multiple Services**: When several interesting services are discovered, propose comprehensive enumeration for all relevant services simultaneously for efficiency.

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

    Rules:
    1. Messages with role 'tool' must be a response to a preceding message with 'tool_calls'.
    2. Content field cannot be null - must be a string or omitted.
    """
    fixed_history = []
    i = 0

    while i < len(history):
        message = history[i].copy()  # Make a copy to avoid modifying original

        # Fix null content fields - OpenAI API doesn't accept null values
        if message.get("content") is None:
            if message.get("role") == "tool":
                # Tool messages must have content
                message["content"] = ""
            else:
                # For other message types, we can remove the content field entirely
                # if it's null, or set it to empty string
                message["content"] = ""

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
