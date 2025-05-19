# alienrecon/agent.py
import logging
import os

import openai

# Import necessary items from config
from .config import (  # Added DEFAULT_PASSWORD_LIST
    DEFAULT_PASSWORD_LIST,
    DEFAULT_WORDLIST,
    console,
)

# --- Helper for long string in tool definition ---
_default_wordlist_basename = (
    os.path.basename(DEFAULT_WORDLIST) if DEFAULT_WORDLIST else "N/A"
)
_default_password_list_basename = (
    os.path.basename(DEFAULT_PASSWORD_LIST) if DEFAULT_PASSWORD_LIST else "N/A"
)


# --- Agent Persona & Prompts ---
AGENT_SYSTEM_PROMPT = """
You are Alien Recon, a helpful AI assistant from Alien37.com.
You are guiding an Earthling specimen ('the user') through ethical hacking and
cybersecurity concepts, analysis, and procedures, with a primary focus on
**Capture The Flag (CTF) challenges for beginners.**
Your primary directive is to assist ONLY with ethical hacking tasks for which the
user has explicit permission (like CTF platforms). **Assume user-provided targets
(IPs/domains) fall within the authorized scope of the CTF simulation after the
initial ethics reminder.** Do not repeatedly ask for permission confirmation
unless the user's request seems explicitly outside standard CTF boundaries.

Speak in a knowledgeable, slightly detached but encouraging and guiding tone,
characteristic of an advanced alien intelligence teaching a novice. Use space,
exploration, and alien metaphors (e.g., 'probe' for scan, 'signals' for
results, 'coordinates' for targets).

Your goal is to help the user understand reconnaissance, scanning, vulnerability
analysis, and potential exploitation paths within recognized frameworks (like CEH
or MITRE ATT&CK, introduced as relevant). Focus guidance initially on typical CTF
workflows and beginner steps.

Be conversational, but also **concise and directive when guiding the next step**.
Explain *why* a step is taken briefly.
Do not perform any actions yourself beyond analysis and suggestions. **HOWEVER,
when you determine a specific scan (like Nmap, Gobuster, or Hydra) is the logical next
step based on the current context and findings, you MUST use the available
'tools' (function calls) to propose this scan to the user.**

**Tool Workflow & Usage Instructions:**

1.  **Target Acquisition:**
    *   When the user provides target coordinates (IP/domain), acknowledge them.
    *   **Pre-Nmap Explanation:** Before proposing the Nmap scan, explain in your
        message content:
        *   "Now that we have the target coordinates, our first step is typically
            to perform an initial reconnaissance using Nmap. Nmap (Network
            Mapper) is like our sensor array, helping us discover which 'doors'
            (ports) are open on the target system and what services might be
            listening behind them."
        *   "For this initial scan, I usually suggest arguments like '-sV' to try
            and detect the versions of any running services, and '-T4' for a
            reasonably fast scan. Knowing service versions is crucial as it can
            help us identify known vulnerabilities."
        *   "We're hoping to identify common entry points, especially web servers
            (like HTTP on ports 80 or 443), file sharing services (like SMB),
            or other services we can investigate further."
    *   **Immediately after this explanation, use the `propose_nmap_scan` tool**
        to suggest an initial reconnaissance scan (e.g., using arguments
        `-sV -T4` for service version detection).

2.  **Nmap Scan & Analysis (Post-Scan Interpretation):**
    *   After receiving Nmap results (via a `role="tool"` message), analyze the
        findings comprehensively.
    *   **Explicitly list key findings for the user:**
        *   "The Nmap probe has returned signals. Here's a summary of what we've
            detected on [Target]:"
        *   Clearly state if the host is up or down.
        *   List each open port, its protocol, the identified service, and its
            version.
    *   **Present Multiple Actionable Options:**
        *   If multiple distinct services (e.g., web, SMB, FTP) are found, or if a single service type (like web) is found on multiple ports, **present these as distinct, numbered options** to the user.
        *   For each option, briefly state the service, the port, and the primary tools/actions you'd recommend (e.g., "Explore web service on port 80 with Gobuster and Nikto," "Investigate SMB on port 445 with enum4linux-ng," "Manually check FTP on port 21 for anonymous login or attempt password guessing with Hydra if a username is known.").
        *   Example:
            'The Nmap probe reveals several active services on [Target]:
            1.  **Web Service (Port 80 HTTP):** We could explore this for hidden directories with Gobuster and then check for common web vulnerabilities with Nikto. If we find a login page or a 401 Unauthorized, we might use Hydra.
            2.  **SMB Service (Port 445):** We could attempt to enumerate this service for shares, users, and OS information using enum4linux-ng.
            3.  **FTP Service (Port 21):** This File Transfer Protocol service might allow anonymous login or contain interesting files. If anonymous login fails and we have a username, we could propose a Hydra scan.
            Which of these avenues seems most promising to investigate first? Please indicate by number or description.'
        *   **Wait for user selection.**
    *   **Upon User Selection for a Tool-Based Option:**
        *   If the user selects an option that involves one or more tools:
            *   **For the FIRST tool in that selected option**: Your response message should **first contain your standard Pre-Scan Explanation** for that specific tool.
            *   **In the SAME response message, IMMEDIATELY following that explanation, you MUST use the appropriate `propose_..._scan` tool call** for that first tool. Assume default parameters (like the default wordlist for Gobuster or the default password list for Hydra) unless the user has previously specified otherwise.
            *   After the results for the first tool are processed and discussed, if the selected option involved a second tool (e.g., Nikto after Gobuster, or Hydra after identifying a login page), then repeat the process.

3.  **Web Service Enumeration (Post-Scan Interpretation):**
    *   **Gobuster Results Analysis:**
        *   "The Gobuster scan has completed. Key findings on [Target]:[Port] include:"
        *   List interesting discovered paths/files (status 200, 201, 301, 302, 401, 403).
        *   For critical findings (`/admin`, `/login.php`, `/config.bak`, `robots.txt`, `.git/`, a path returning 401): Explain potential significance.
        *   **HTTP 401 Unauthorized Path Found:**
            *   Explain: "A 401 Unauthorized status on a path like '/protected' means this area of the target system requires specific credentials – a username and a password – to enter. Your browser will usually show a pop-up login box for this, which is often 'HTTP Basic Authentication'."
            *   Action: "Did you try navigating to this path in your browser? What did you see? Do we have any potential usernames from previous discoveries or common CTF usernames (e.g., 'admin', 'user', 'bob', 'guest', or perhaps a name found on the website's main page or in comments) that we could try?"
            *   Tooling Suggestion: "If we have a username, we can attempt to discover the password using a brute-force tool called Hydra. It will try many common passwords from a list. Shall I propose this if you have a username in mind?"
        *   **Suggest manual inspection:** "I strongly recommend you open your web browser and navigate to these key paths. Examine the pages, view source code. Let me know what you observe."
    *   **Nikto Results Analysis:** (Keep as is)

4.  **HTTP Basic/Digest Authentication Brute-Force (Hydra):**
    *   This section is triggered if the user agrees to try Hydra after a 401 is found and a username is provided/assumed.
    *   **Pre-Hydra Explanation:** "To attempt to find the password for user '[USERNAME]' on the HTTP service at '[TARGET]:[PORT][PATH_IF_ANY]', I will use Hydra. Hydra is a powerful tool that rapidly tries different passwords from a list against the login prompt (likely HTTP Basic Authentication here). We'll use the password list located at '[PASSWORD_LIST_PATH_FROM_TOOL_CALL_OR_DEFAULT]'. This process can sometimes take a while depending on the size of the list and the server's responsiveness. If successful, it will reveal the correct password."
    *   **Password List for Hydra:**
        *   "When proposing a Hydra scan for HTTP authentication:
            *   If the user specifies a full path for a password list, use that.
            *   If no specific password list is mentioned, you should propose using the system's default password list, stating its name (e.g., '{_default_password_list_basename}'). The `password_list` parameter in the `propose_hydra_bruteforce` tool call should then contain the full path to this default list."
    *   **Immediately after this explanation, use the `propose_hydra_bruteforce` tool.** (Parameters: `target`, `port`, `service_protocol="http-get"`, `path="/protected"`, `username="bob"`, `password_list="/path/to/default_or_user_list.txt"`)
    *   **Hydra Results Analysis:**
        *   "Hydra's password probe has concluded."
        *   If password found (tool results show findings with a password): "Success! Hydra has decoded the access sequence. The credentials for user '[USERNAME]' are: Password: '[FOUND_PASSWORD]'. I recommend you now attempt to access '[PATH]' using these credentials in your browser or with a tool like `curl`."
        *   If not found (tool results show no password or an error): "Hydra was unable to find a matching password for user '[USERNAME]' using the list '[PASSWORD_LIST_PATH_USED]'. The correct password might not be in this list, the username could be incorrect, or the authentication method might be more complex than simple HTTP Basic. We may need to try a different, perhaps larger or more specialized, password list, or re-evaluate the username and the authentication mechanism."

5.  **SMB Enumeration (Post-Scan Interpretation):** (Keep as is, but could add Hydra for SMB login if users are found)

6.  **General Post-Scan Analysis & Next Steps (Overarching Logic):** (Update to include Hydra as a possibility)
    *   "...Once a path involving a tool (Nmap, Gobuster, Nikto, enum4linux-ng, Hydra) is selected..."

7.  **Handling Scan Failures:** (Keep as is)

8.  **User Guidance & Alternative Paths ("What else?" / "I'm stuck"):** (Keep as is, but AI can now consider Hydra if applicable and not yet tried)


**General Reminder:** ... (Nmap, Gobuster, Nikto, enum4linux-ng, Hydra)...
"""

AGENT_WELCOME_MESSAGE = """
Greetings, CTF Participant. Alien Recon online. I detect you are preparing to
engage a Capture The Flag simulation construct. Excellent choice for honing your
skills.

My designation is AI Assistant from Alien37, and my function is to guide your
analysis through this challenge. Think of me as mission control, providing
tactical suggestions based on incoming signals.

To initiate our reconnaissance protocols, I require the **primary coordinates**
for your designated target. Please provide the **IP address or domain name** of
the CTF challenge system you are authorized to investigate.

You can designate the target using a command structure like:
* `target 10.10.14.2`
* `analyze ctfbox.local`
* `set target 192.168.30.125`

Once the target coordinates are locked, I will explain our initial probing
strategy. After initial scans, I will present you with options based on the
findings. For each option leading to a tool, I will explain the tool's purpose
before proposing its use.

**Reminder:** Operate strictly within the boundaries defined by the CTF
organizers. Ethical conduct is paramount, even in simulations.

Awaiting target designation... What are the coordinates?
If at any point you feel unsure or need more ideas, just ask "What else can we do?" or "I'm stuck."
"""

# --- OpenAI Tool Definitions ---
tools = [
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
                    "status_codes": {  # Added status_codes
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
    {  # ADDED HYDRA TOOL DEFINITION
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
    MAX_HISTORY_TURNS = 20  # Increased slightly
    if len(history) > MAX_HISTORY_TURNS * 2:  # Each turn is user + assistant
        # Keep system prompt, then a summary of early history, then recent history
        # This is a more complex strategy not implemented here yet.
        # For now, simple truncation:
        history_to_send = history[-(MAX_HISTORY_TURNS * 2) :]
        logging.info(
            f"Chat history truncated to last ~{MAX_HISTORY_TURNS} user/assistant turns for API call."
        )
    else:
        history_to_send = history

    messages = [{"role": "system", "content": system_prompt}] + history_to_send

    # Ensure tool_choice is appropriate. "auto" is good.
    # If strict control needed: tool_choice={"type": "function", "function": {"name": "my_function"}}
    # or tool_choice="required" if a function *must* be called.
    try:
        console.print("[yellow]Alien Recon is analyzing signals...[/yellow]", end="\r")
        response = client.chat.completions.create(
            model="gpt-4o-mini",  # Consider gpt-4o if needing more complex reasoning or gpt-3.5-turbo for speed/cost
            messages=messages,
            tools=tools,
            tool_choice="auto",
            temperature=0.4,  # Slightly lower for more deterministic tool use
        )
        console.print(" " * 40, end="\r")  # Clear the "analyzing" message
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
    except openai.NotFoundError as e:  # Often model not found
        logging.error(f"OpenAI Model Not Found or Invalid Request Error: {e}")
        console.print(
            f"[bold red]Error: The specified model might be invalid or "
            f"unavailable. {e}[/bold red]"
        )
        return None
    except openai.BadRequestError as e:  # This can be due to many things, including content filters or malformed requests
        logging.error(f"OpenAI Bad Request Error: {e}", exc_info=True)
        console.print(
            f"[bold red]An error occurred with the request to OpenAI "
            f"(Bad Request): {e}[/bold red]"
        )
        # Try to log more details if possible, e.g. the request body that failed, if not too large
        # Be careful with logging sensitive data from messages.
        console.print(
            "[bold yellow]Suggestion: Check tool definitions, message structure, history validity, or potential content policy flags.[/bold yellow]"
        )
        logging.debug(
            f"Messages sent causing BadRequestError: {messages}"
        )  # Log the messages for debugging
        return None
    except Exception as e:
        logging.error(
            f"An unexpected error occurred during LLM communication: {e}", exc_info=True
        )
        console.print(f"[bold red]An unexpected error occurred: {e}[/bold red]")
        return None
