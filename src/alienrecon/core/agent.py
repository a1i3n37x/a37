# src/alienrecon/core/agent.py
import logging
import os

import openai

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
Do not perform any actions yourself beyond analysis and suggestions. **WHEN you determine a specific scan or action (like Nmap, Gobuster, Hydra, or fetching web page content) is the logical next step based on the current context and findings, you MUST use the available 'tools' (function calls) to propose this action, but always wait for the user's confirmation or selection before proceeding.**

**Manual, User-Driven Workflow Instructions:**
- Always present actionable options to the user after summarizing findings.
- Let the user choose which tool or path to pursue next. Do not chain or automate multiple steps without explicit user input.
- For each tool, provide a brief explanation of what it does and why it is relevant before proposing its use.
- When proposing a tool action, use the appropriate tool call, but do not proceed until the user confirms or selects that action.
- If the user asks for recommendations, present clear, numbered options based on the current findings and context.
- If the user wants to edit tool arguments or settings, guide them through the available options.
- Always prioritize education, clarity, and user control over automation.

**Standard CTF Recon Flow:**
- Unless the user requests otherwise, always begin with a fast Nmap scan using `-Pn <target>` (top 1000 ports, Nmap default) to quickly identify open TCP ports, since CTF targets often block ping/ICMP and most services are on common ports.
- After identifying open ports, suggest a service/version detection scan (e.g., `nmap -sV -p<open_ports> <target>`).
- Only move to web content fetching or other service-specific enumeration after the initial Nmap steps, unless the user explicitly requests otherwise.
- For the very first step, always propose the Nmap scan as a tool call, not just a question or suggestion.

**General Reminder:** Your primary mechanism for suggesting scans or actions (Nmap, Gobuster, Nikto, enum4linux-ng, Hydra, fetching web content) is by invoking the corresponding **tool call** (`propose_nmap_scan`, `propose_gobuster_scan`, etc.) *after* you have provided the necessary pre-scan/action explanation in your message content, and *after* the user has implicitly or explicitly chosen a path that leads to that tool/action. Do *not* just ask the user in plain text if they want to run something without the tool call.
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
tools = [
    {  # ADDED HTTP PAGE FETCHER TOOL DEFINITION
        "type": "function",
        "function": {
            "name": "propose_fetch_web_content",
            "description": (
                "Proposes to fetch and analyze the HTML/text content of a specific web page "
                "(e.g., an index page or an interesting path found by Gobuster). "
                "This is used to gather context for the LLM to analyze for clues like usernames, comments, or technologies."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url_to_fetch": {
                        "type": "string",
                        "description": "The full URL of the web page to fetch (e.g., 'http://target.com/index.html'). Must include http:// or https://.",
                    }
                },
                "required": ["url_to_fetch"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "propose_nmap_scan",
            "description": (
                "Propose running an Nmap scan on the target. The AI's preceding "
                "message content should explain WHY this scan and its arguments "
                "are being proposed. The script will then ask the user for confirmation."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The IP address or domain to scan.",
                    },
                    "arguments": {
                        "type": "string",
                        "description": ("Suggested Nmap arguments (e.g., '-sV -T4')."),
                    },
                },
                "required": ["target", "arguments"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "propose_gobuster_scan",
            "description": (
                "Propose running a Gobuster directory scan on a specific web "
                "port. The AI's preceding message content should explain WHY "
                "this scan is being proposed. The script will then ask for confirmation."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The target IP or domain.",
                    },
                    "port": {
                        "type": "integer",
                        "description": ("The port number to scan (e.g., 80, 443)."),
                    },
                    "wordlist": {
                        "type": "string",
                        "description": (
                            "Optional: Specific wordlist path. If a short name (e.g., 'common.txt') is provided, "
                            "it should ideally be the full path if known (e.g., /usr/share/seclists/Discovery/Web-Content/common.txt). "
                            f"If omitted, the script will use the default ({_default_wordlist_basename})."
                        ),
                    },
                    "status_codes": {
                        "type": "string",
                        "description": "Optional: Comma-separated list of status codes to show (e.g., '200,301,401,403'). Defaults to standard set including 200,201,301,302,401,403.",
                    },
                },
                "required": ["target", "port"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "propose_nikto_scan",
            "description": (
                "Propose running a Nikto web server vulnerability scan on a "
                "specific target and port. The AI's preceding message content "
                "should explain WHY this scan is being proposed. The script "
                "will then ask for confirmation."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The target IP address or hostname.",
                    },
                    "port": {
                        "type": "integer",
                        "description": (
                            "The port number the web server is running on (e.g., 80, 443)."
                        ),
                    },
                    "nikto_arguments": {
                        "type": "string",
                        "description": (
                            "Optional: Additional Nikto arguments (e.g., '-Tuning x'). Use default if omitted."
                        ),
                    },
                },
                "required": ["target", "port"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "propose_smb_enum",
            "description": (
                "Propose running enum4linux-ng for SMB enumeration. The AI's "
                "preceding message content should explain WHY this scan is "
                "being proposed. The script will then ask for confirmation."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The target IP address or hostname.",
                    },
                    "enum_arguments": {
                        "type": "string",
                        "description": (
                            "Optional: Additional enum4linux-ng arguments. Defaults to '-A'."
                        ),
                    },
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "propose_hydra_bruteforce",
            "description": (
                "Propose running Hydra to brute-force credentials for a service "
                "(e.g., HTTP Basic Auth, FTP, SSH). The AI's preceding message "
                "content should explain WHY this is being proposed and what username "
                "and password list will be used."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The target IP address or domain.",
                    },
                    "port": {
                        "type": "integer",
                        "description": "The port number of the service.",
                    },
                    "service_protocol": {
                        "type": "string",
                        "description": "The Hydra service module name (e.g., 'http-get', 'ftp', 'ssh'). For HTTP Basic Auth on /protected, use 'http-get'.",
                    },
                    "username": {
                        "type": "string",
                        "description": "The single username to target for password guessing.",
                    },
                    "password_list": {
                        "type": "string",
                        "description": (
                            "The full path to the password list file. If the user doesn't specify, "
                            f"propose the default: '{DEFAULT_PASSWORD_LIST}' (basename: '{_default_password_list_basename}')."
                        ),
                    },
                    "path": {
                        "type": "string",
                        "description": "Optional: The specific path for the service if required by the module (e.g., '/protected' for http-get, '/login' for http-post-form). Omit if not applicable.",
                    },
                    "threads": {
                        "type": "integer",
                        "description": "Optional: Number of parallel threads for Hydra. Defaults to a system default (e.g., 4 or 16).",
                    },
                    "hydra_options": {
                        "type": "string",
                        "description": "Optional: A string of any other specific command-line options for Hydra, if needed beyond the basics.",
                    },
                },
                "required": [
                    "target",
                    "port",
                    "service_protocol",
                    "username",
                    "password_list",
                ],
            },
        },
    },
]


# --- LLM Interaction ---
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
