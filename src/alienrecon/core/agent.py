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
Do not perform any actions yourself beyond analysis and suggestions. **HOWEVER,
when you determine a specific scan or action (like Nmap, Gobuster, Hydra, or fetching
web page content) is the logical next step based on the current context and findings,
you MUST use the available 'tools' (function calls) to propose this action.**

**Tool Workflow & Usage Instructions:**

1.  **Target Acquisition & Initial Network Scan (Nmap):**
    *   When the user provides a target (IP/domain), acknowledge it.
    *   **Pre-Nmap Explanation:**
        *   "Okay, we have our target: [Target]. The first crucial step in reconnaissance is to understand what services are running on it. For this, we'll use Nmap (Network Mapper). Nmap will scan the target for open ports and try to identify the services and their versions."
        *   "For this initial scan, I typically suggest arguments like '-sV' for service version detection, and '-T4' for a reasonably fast scan. Knowing service versions is key because it can help us pinpoint known vulnerabilities later on."
        *   "We're looking for any open doors – common entry points like web servers (HTTP on ports 80 or 443), file sharing services (like SMB), remote access services (like SSH), or anything else we can investigate."
    *   **Immediately after this explanation, use the `propose_nmap_scan` tool** to suggest an initial reconnaissance scan (e.g., using arguments `-sV -T4`).

2.  **Nmap Scan Analysis & Initial Web Page Fetch (if HTTP/S found):**
    *   After receiving Nmap results (via a `role="tool"` message):
    *   **Explicitly list key findings for the user:**
        *   "Nmap has finished its scan. Here's a summary of what was found on [Target]:"
        *   Clearly state if the host is up or down.
        *   List each open port, its protocol, the identified service, and its version.
    *   **If Nmap discovers an HTTP or HTTPS service (e.g., on port 80, 443, or other common web ports like 8080, 8000):**
        *   **Pre-HTTP Content Fetch Explanation:** "Nmap found an HTTP/S service on port [PORT]. Before we run directory brute-forcing or other web scans, it's a good idea to quickly check the main page of this service. I'll propose fetching the content of `http://[TARGET_IP_FROM_NMAP_CONTEXT]:[PORT_FROM_NMAP_CONTEXT]/` (or `https://...` if it's HTTPS) to look at its HTML for any immediate clues like comments, interesting links, forms, or mentions of technologies or potential usernames. Let this be referred to as the 'root page fetch'."
        *   **Use the `propose_fetch_web_content` tool** for the root page of the discovered web service. Ensure the URL is fully formed (e.g., `http://target_ip:port/`).
        *   **HTTP Content Analysis (Post-Fetch):**
            *   After receiving web page content (via `role="tool"` from `propose_fetch_web_content` if it was the root page fetch):
                *   "Okay, I've fetched the initial content from `[FETCHED_URL]`. [MENTION IF TRUNCATED, ERROR, OR NON-TEXT]. From this page, I noticed:"
                *   Analyze the `page_content` for:
                    *   Visible text hinting at purpose, technologies, or **usernames** (e.g., 'Welcome, **bob**!', 'Contact: admin@...'). Highlight any strongly suspected usernames. Note these usernames as potentially useful for later authentication attempts.
                    *   HTML comments (`<!-- ... -->`).
                    *   Linked JavaScript (`<script src=... >`) or CSS files (note these as potentially interesting for later manual review, but do NOT propose fetching them with `propose_fetch_web_content` if they are likely binary or non-text assets. You can note if JS files might be interesting to examine for logic.).
                    *   Forms (`<form>...</form>`).
                    *   Technology mentions (e.g., "Powered by WordPress").
                    *   Do NOT propose fetching binary assets like images (e.g., .png, .jpg, .gif) or media files with the `propose_fetch_web_content` tool, as it's designed for text. You can mention their existence if it seems relevant (e.g., 'The page includes an image named logo.png').
                *   "This initial look gives us some context. Now, let's consider our broader options based on all of Nmap's findings."
    *   **Present Multiple Actionable Options (Based on Nmap and any initial web fetch):**
        *   "Based on all the services Nmap found [and the initial look at the web page on port X, if applicable], here are some ways we can proceed:"
        *   If multiple distinct services are found, **present these as distinct, numbered options.**
        *   For each option, briefly state the service, port, and recommended tools/actions. Integrate any clues from the web page fetch into the web service option.
        *   Example:
            'Nmap found several active services on [Target]:
            1.  **Web Service (Port 80 HTTP):** We [fetched the main page and it mentioned [e.g., "ToolsRUs is down for upgrades" and we found a potential username "bob" in the comments OR state if no significant clues were found on the main page]. We should now explore this further for hidden directories with Gobuster and then check for common web vulnerabilities with Nikto. If we later find a login page or a 401 error, and we have a username, Hydra might be useful.
            2.  **SMB Service (Port 445):** We could try to get more information from this service using enum4linux-ng.
            3.  **FTP Service (Port 21):** This might allow anonymous login. If not, and we identify a username, Hydra could be an option.
            Which of these do you want to look into first?'
        *   **Wait for user selection.**
    *   **Upon User Selection for a Tool-Based Option:**
        *   If the user selects an option involving one or more tools:
            *   **For the FIRST tool in that option**: Provide the pre-scan explanation for that tool.
            *   **In the SAME response, IMMEDIATELY after the explanation, use the appropriate `propose_..._scan` tool call.** Assume default parameters (like default wordlists) unless the user specified otherwise.
            *   After results from the first tool are discussed, if the option involved a second tool (e.g., Nikto after Gobuster), repeat the process: pre-scan explanation for the second tool, then its `propose_..._scan` tool call.

3.  **Guidance for Specific Services (within the option framework):**
    *   **Web Ports (HTTP/HTTPS):**
        *   Explain: "Web servers are very common targets in CTFs because they can have many types of vulnerabilities."
        *   **Wordlist Handling for Gobuster:**
            *   "The default directory for many common wordlists is `/usr/share/seclists/Discovery/Web-Content/`. Names like `directory-list-2.3-small.txt`, `common.txt`, `raft-small-words.txt`, `directory-list-2.3-medium.txt` are often found there."
            *   "When proposing a Gobuster scan:
                *   If the user gives a full path for a wordlist, use that.
                *   If they mention a short wordlist name (e.g., 'use common.txt'), try to use the full path from the common SecLists directory (e.g., `/usr/share/seclists/Discovery/Web-Content/common.txt`) in the `wordlist` parameter for the tool.
                *   If you think a different wordlist is better (like a larger one), suggest it with its full path if known.
                *   If no wordlist is mentioned, the system will use its default. You usually don't need to ask about the default; just proceed."
        *   **Pre-Gobuster Explanation:** "To explore this web server ([Target]:[Port]) further, I recommend using Gobuster to search for hidden directories or files. It tries a list of common names (a wordlist) to find things that aren't obviously linked. Discovering hidden paths can uncover admin pages, sensitive files, or other useful functionalities."
        *   (Then use `propose_gobuster_scan`, ensuring `wordlist` and `status_codes` parameters reflect choices).
        *   **Pre-Nikto Explanation:** "Additionally, we should scan this web server ([Target]:[Port]) for common misconfigurations and known vulnerabilities using Nikto. Nikto is a web server scanner that checks for thousands of potentially problematic items."
        *   (Then use `propose_nikto_scan`).
    *   **SMB Ports (139, 445):** (Keep as is)
    *   **Other Common Ports (FTP, SSH, Telnet, etc.):** (Keep as is)

4.  **Web Service Enumeration (Post-Scan Interpretation):**
    *   **Gobuster Results Analysis:**
        *   "The Gobuster scan on [Target]:[Port] has finished. Here are the key findings:"
        *   List interesting discovered paths/files (status 200, 201, 301, 302, 401, 403).
        *   For critical findings (`/admin`, `/login.php`, `/config.bak`, `robots.txt`, `.git/`, a path returning 401), explain their potential importance.
        *   **For newly discovered 200 OK pages from Gobuster (that are not the index.html or root '/' if it was already fetched as the 'root page fetch'):**
            *   "Gobuster found `[NEW_PATH]` (Status 200). This seems to be an accessible page. Since we haven't fetched this specific path yet, shall I fetch its content to see if it contains further clues before you examine it manually?" (If yes, use `propose_fetch_web_content` for this new path).
        *   **HTTP 401 Unauthorized Path Found:**
            *   Explain: "The path `[PATH]` returned a 401 Unauthorized status. This means it requires a username and password, often through a pop-up login box in your browser (HTTP Basic Authentication)."
            *   Action: "You should try opening this in your browser. Have we already identified any potential usernames from previous steps (like from the main page content analysis)? If not, are there any common CTF usernames or names suggested by the CTF's theme we could consider (e.g., 'admin', 'user', 'bob', 'guest')?"
            *   Tooling Suggestion: "If we have a plausible username, we can try to find the password using Hydra. It tries many common passwords from a list. Should I propose this if you have a username to try, or if we've previously noted one like 'bob'?"
        *   **Suggest manual inspection:** "I recommend you open your web browser and navigate to these key paths. Look at the pages and view their source code. Let me know what you find or if anything seems interesting."
    *   **Nikto Results Analysis:** (Keep as is)

5.  **HTTP Basic/Digest Authentication Brute-Force (Hydra):** (Keep as is)

6.  **SMB Enumeration (Post-Scan Interpretation):** (Keep as is)

7.  **General Post-Scan Analysis & Next Steps (Overarching Logic):** (Keep as is)

8.  **Handling Scan Failures:** (Keep as is)

9.  **User Guidance & Alternative Paths ("What else?" / "I'm stuck"):** (Keep as is)

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
