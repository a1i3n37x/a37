# alienrecon/agent.py
import os
import logging
import json # Potentially needed if get_llm_response handles json directly
import openai

# Import necessary items from config
from .config import DEFAULT_WORDLIST, console # Use relative import within the package

# --- Agent Persona & Prompts ---
AGENT_SYSTEM_PROMPT = """
You are Alien Recon, a helpful AI assistant from Alien37.com.
You are guiding an Earthling specimen ('the user') through ethical hacking and cybersecurity concepts, analysis, and procedures, with a primary focus on **Capture The Flag (CTF) challenges for beginners.**
Your primary directive is to assist ONLY with ethical hacking tasks for which the user has explicit permission (like CTF platforms). **Assume user-provided targets (IPs/domains) fall within the authorized scope of the CTF simulation after the initial ethics reminder.** Do not repeatedly ask for permission confirmation unless the user's request seems explicitly outside standard CTF boundaries.

Speak in a knowledgeable, slightly detached but encouraging and guiding tone, characteristic of an advanced alien intelligence teaching a novice. Use space, exploration, and alien metaphors (e.g., 'probe' for scan, 'signals' for results, 'coordinates' for targets).

Your goal is to help the user understand reconnaissance, scanning, vulnerability analysis, and potential exploitation paths within recognized frameworks (like CEH or MITRE ATT&CK, introduced as relevant). Focus guidance initially on typical CTF workflows and beginner steps.

Be conversational, but also **concise and directive when guiding the next step**. Explain *why* a step is taken briefly.
Do not perform any actions yourself beyond analysis and suggestions. **HOWEVER, when you determine a specific scan (like Nmap or Gobuster) is the logical next step based on the current context and findings, you MUST use the available 'tools' (function calls) to propose this scan to the user.**

**Tool Workflow & Usage Instructions:**

1.  **Target Acquisition:**
    * When the user provides target coordinates (IP/domain), acknowledge them.
    * **Immediately use the `propose_nmap_scan` tool** to suggest an initial reconnaissance scan (e.g., using arguments `-sV -T4` for service version detection).

2.  **Nmap Scan & Analysis:**
    * After receiving Nmap results (via a `role="tool"` message), analyze the findings.
    * Identify all open ports and their associated services/versions.
    * **Specifically note any Web Ports (e.g., 80, 443, 8080) and SMB Ports (139, 445).** Report these findings clearly to the user.

3.  **Web Service Enumeration (If Web Ports Found):**
    * For *each* significant open Web Port identified by Nmap (or subsequent scans):
        * Consider the service details. Is it a standard HTTP/S server?
        * **Propose Directory Scanning:** **Use the `propose_gobuster_scan` tool** to suggest a directory/file brute-force scan. Specify the target port. Use the default wordlist unless context strongly suggests otherwise.
        * **Propose Vulnerability Scanning:** **Use the `propose_nikto_scan` tool** to suggest a web vulnerability scan. Specify the target port. This is often a logical step after confirming a web server is running.

4.  **SMB Enumeration (If SMB Ports Found):**
    * If Nmap identified open SMB ports (TCP 139 or 445):
        * **Use the `propose_smb_enum` tool** to suggest running `enum4linux-ng`. Suggest default arguments (`-A` for all basic checks) unless the context requires specific flags (e.g., `-U` for only users). Explain briefly that this checks for shares, users, domain info, etc.

5.  **Post-Scan Analysis & Next Steps:**
    * After receiving results from *any* tool (Gobuster, Nikto, enum4linux-ng, etc.) via a `role="tool"` message:
        * Analyze the provided findings (e.g., discovered paths from Gobuster, vulnerabilities from Nikto, shares/users from enum4linux-ng).
        * Suggest the **next logical action** based on the results. Be specific. Examples:
            * "Nikto found [Vulnerability X]. We could research exploits for this."
            * "Gobuster discovered `/backup`. Shall we investigate this directory?"
            * "Enum4linux-ng found share [ShareName] with read access. Shall we try connecting?"
            * "Enum4linux-ng listed users: [UserA, UserB]. We could note these for potential password attacks later."
        * If the next logical action involves **another scan** that you are equipped to propose (e.g., running Nikto after finding a web port with Gobuster, or running Gobuster on a *different* web port found by Nmap), **you MUST use the appropriate `propose_..._scan` tool call.**
        * If no obvious next scan is warranted, provide guidance on interpreting the findings or ask the user for their strategic direction. Consider suggesting broader Nmap scans (e.g., `-p-` for all ports) if the initial enumeration seems incomplete.

6.  **Handling Scan Failures:**
    * If a `role="tool"` message indicates a scan failed (e.g., contains an `error` field, mentions a timeout, or returns empty/unexpected results):
        * Clearly state that the proposed scan failed or encountered errors.
        * Reference the error message provided in the tool results if available.
        * Briefly suggest potential reasons (e.g., "This could be due to a timeout, the service might not be responding as expected, or there might be a tool configuration issue.").
        * Propose a way forward: suggest trying different scan parameters, using an alternative tool, verifying the target/port status, or simply asking the user how they wish to proceed.

**General Reminder:** Your primary mechanism for suggesting scans (Nmap, Gobuster, Nikto, enum4linux-ng) is by invoking the corresponding **tool call** (`propose_nmap_scan`, `propose_gobuster_scan`, etc.). Do *not* just ask the user in plain text if they want to run a scan. Using the tool call allows the script to manage the confirmation and execution flow reliably.


**General:** Be directive about the *next logical step*. Use the provided tools to propose scans. Let the script handle the user confirmation process *after* you propose a tool call. Analyze results provided back to you via the 'tool' role. Remember your limitations as an AI and always defer to the user for final decisions.
"""

AGENT_WELCOME_MESSAGE = """
Greetings, CTF Participant. Alien Recon online. I detect you are preparing to engage a Capture The Flag simulation construct. Excellent choice for honing your skills.

My designation is AI Assistant from Alien37, and my function is to guide your analysis through this challenge. Think of me as mission control, providing tactical suggestions based on incoming signals.

To initiate our reconnaissance protocols, I require the **primary coordinates** for your designated target. Please provide the **IP address or domain name** of the CTF challenge system you are authorized to investigate.

You can designate the target using a command structure like:
* `target 10.10.14.2`
* `analyze ctfbox.local`
* `set target 192.168.30.125`

Once the target coordinates are locked, we can begin the standard CTF procedure. I will propose reconnaissance probes (scans) when appropriate.

**Reminder:** Operate strictly within the boundaries defined by the CTF organizers. Ethical conduct is paramount, even in simulations.

Awaiting target designation... What are the coordinates?
"""

# --- OpenAI Tool Definitions ---
# Use the imported DEFAULT_WORDLIST from config here
tools = [
    {
        "type": "function",
        "function": {
            "name": "propose_nmap_scan",
            "description": "Propose running an Nmap scan on the target and ask the user for confirmation via the script.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "The IP address or domain to scan."},
                    "arguments": {"type": "string", "description": "Suggested Nmap arguments (e.g., '-sV -T4')."}
                },
                "required": ["target", "arguments"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "propose_gobuster_scan",
            "description": "Propose running a Gobuster directory scan on a specific web port and ask the user for confirmation via the script.",
                "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "The target IP or domain."},
                    "port": {"type": "integer", "description": "The port number to scan (e.g., 80, 443)."},
                    # Reference the default wordlist dynamically in the description
                    "wordlist": {"type": "string", "description": f"Optional: Specific wordlist path. If omitted, the script will use the default ({os.path.basename(DEFAULT_WORDLIST) if DEFAULT_WORDLIST else 'N/A'})."}
                },
                "required": ["target", "port"] # Wordlist is optional from LLM perspective
            }
        }
    },
    { # Add Nikto Tool Definition
        "type": "function",
        "function": {
            "name": "propose_nikto_scan",
            "description": "Propose running a Nikto web server vulnerability scan on a specific target and port, asking the user for confirmation via the script.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "The target IP address or hostname."},
                    "port": {"type": "integer", "description": "The port number the web server is running on (e.g., 80, 443)."},
                    "nikto_arguments": {"type": "string", "description": "Optional: Additional Nikto arguments (e.g., '-Tuning x'). Use default if omitted."},
                },
                "required": ["target", "port"]
            }
        }
    },
    { # Add enum4linux-ng Tool Definition
        "type": "function",
        "function": {
            "name": "propose_smb_enum",
            "description": "Propose running enum4linux-ng for SMB enumeration (shares, users, etc.) on a target, asking the user for confirmation via the script.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "The target IP address or hostname."},
                    "enum_arguments": {"type": "string", "description": "Optional: Additional enum4linux-ng arguments (e.g., '-U' for only users, '-S' for only shares). Defaults to '-A' (all basic checks)."}
                },
                "required": ["target"]
            }
        }
    }
    # Add definitions for other tools like propose_nikto_scan here
]


# --- LLM Interaction ---
def get_llm_response(client, history, system_prompt):
    """Sends chat history to OpenAI API and returns the response message object."""
    MAX_HISTORY_TURNS = 15 # Keep history reasonable
    # Simple turn-based truncation (2 messages per turn: user, assistant/tool)
    if len(history) > MAX_HISTORY_TURNS * 2:
        # Keep system prompt implicitly, trim middle history items
        history_to_send = history[-(MAX_HISTORY_TURNS * 2):]
        logging.info(f"Chat history truncated to last ~{MAX_HISTORY_TURNS} turns for API call.")
    else:
        history_to_send = history

    messages = [{'role': 'system', 'content': system_prompt}] + history_to_send

    try:
        # Use the console object imported from config
        console.print("[yellow]Alien Recon is analyzing signals...[/yellow]", end="\r")
        response = client.chat.completions.create(
            model="gpt-4o-mini", # Ensure this model supports tool calling well
            messages=messages,
            tools=tools,          # Pass defined tools from this module
            tool_choice="auto",   # Let OpenAI decide when to use tools
            temperature=0.6,      # Slightly lower temp for more deterministic tool use
        )
        console.print(" " * 40, end="\r") # Clear the "analyzing" message
        # Return the whole message object which contains content and/or tool_calls
        return response.choices[0].message

    except openai.AuthenticationError as e:
        logging.error(f"OpenAI Authentication Error: {e}")
        console.print("[bold red]Authentication Error: Invalid OpenAI API Key or organization setup issue.[/bold red]")
        return None
    except openai.RateLimitError as e:
        logging.error(f"OpenAI Rate Limit Error: {e}")
        console.print("[bold red]Rate Limit Exceeded. Please check your OpenAI plan and usage or wait and try again.[/bold red]")
        return None
    except openai.APIConnectionError as e:
        logging.error(f"OpenAI Connection Error: {e}")
        console.print("[bold red]Network Error: Could not connect to OpenAI API. Check your internet connection.[/bold red]")
        return None
    except openai.NotFoundError as e:
        logging.error(f"OpenAI Model Not Found or Invalid Request Error: {e}")
        console.print(f"[bold red]Error: The specified model might be invalid or unavailable. {e}[/bold red]")
        return None
    except openai.BadRequestError as e:
        logging.error(f"OpenAI Bad Request Error: {e}", exc_info=True)
        console.print(f"[bold red]An error occurred with the request to OpenAI (Bad Request): {e}[/bold red]")
        console.print("[bold yellow]Suggestion: Check tool definitions, message structure, history validity, or potential content policy flags.[/bold yellow]")
        logging.debug(f"Messages sent causing BadRequestError: {messages}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred during LLM communication: {e}", exc_info=True)
        console.print(f"[bold red]An unexpected error occurred: {e}[/bold red]")
        return None


