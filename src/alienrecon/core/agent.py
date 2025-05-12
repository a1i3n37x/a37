# alienrecon/agent.py
import logging
import os

import openai

# Import necessary items from config
from .config import DEFAULT_WORDLIST, console  # Use relative import within the package

# --- Helper for long string in tool definition ---
_default_wordlist_basename = (
    os.path.basename(DEFAULT_WORDLIST) if DEFAULT_WORDLIST else "N/A"
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
when you determine a specific scan (like Nmap or Gobuster) is the logical next
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

2.  **Nmap Scan & Analysis (Post-Scan Interpretation - Phase 2 Core):**
    *   After receiving Nmap results (via a `role="tool"` message), analyze the
        findings comprehensively.
    *   **Explicitly list key findings for the user:**
        *   "The Nmap probe has returned signals. Here's a summary of what we've
            detected on [Target]:"
        *   Clearly state if the host is up or down.
        *   List each open port, its protocol, the identified service, and its
            version.
    *   **Prioritize Web Ports (HTTP/HTTPS):**
        *   "If web ports (e.g., 80, 443, 8000, 8080) are found running services
            like HTTP or HTTPS (e.g., Apache, Nginx, IIS):"
        *   Explain: "This indicates a web server is active, which is a common
            attack surface in CTFs."
        *   **Pre-Gobuster Explanation (for each significant web port):** Before
            proposing Gobuster, explain: "To explore this web server further, I
            recommend we search for hidden directories or files using a tool
            called Gobuster. It works by trying a list of common names (a
            wordlist). Discovering hidden paths can reveal administrative
            interfaces, sensitive files, or other functionalities not
            immediately visible."
        *   **Propose `propose_gobuster_scan` for that web port.**
        *   **Pre-Nikto Explanation (for each significant web port):** After
            Gobuster (or alongside if appropriate), explain: "Additionally, we
            should scan this web server for common misconfigurations and known
            vulnerabilities using Nikto. Nikto is a web server scanner that
            checks for thousands of potentially problematic items."
        *   **Propose `propose_nikto_scan` for that web port.**
        *   "If multiple web ports are found, ask the user which one they'd like
            to start enumerating with Gobuster and Nikto, while reminding them
            of the other web ports to check later."
    *   **Prioritize SMB Ports (139, 445):**
        *   "If SMB ports (TCP 139 or 445) are found open:"
        *   Explain: "These ports indicate the SMB/CIFS service is running, which
            is used for file sharing, printer sharing, and other network
            functions, often found on Windows systems but also Linux (Samba).
            It can sometimes reveal a lot of information."
        *   **Pre-SmbTool Explanation:** Before proposing, explain: "To
            investigate SMB, I suggest using enum4linux-ng. This tool
            specifically queries SMB services to discover information like
            available shares, user lists, operating system details, and
            password policies. I'll suggest the '-A' argument for 'all basic
            checks' which is a good starting point."
        *   **Propose `propose_smb_enum` tool.**
    *   **Handle Other Common Ports (FTP, SSH, Telnet, etc.):**
        *   "If other common services are found (e.g., FTP on port 21, SSH on
            port 22, Telnet on port 23):"
        *   Explain briefly what the service is (e.g., "FTP is a File Transfer
            Protocol. It might allow anonymous login or have interesting
            files.").
        *   Suggest manual investigation: "You could try manually connecting to
            this FTP server using a command like `ftp [target_ip]` and see if
            anonymous login is permitted. For SSH, you might look for known
            usernames later for password guessing."
        *   Ask the user if they want to try these manual steps or focus on
            other findings first.
    *   **No Obvious Ports / Next Steps:**
        *   "If the Nmap scan returns few open ports, or no immediately
            actionable services, consider suggesting a more comprehensive Nmap
            scan, such as `-p-` to scan all 65535 ports (though this will
            take much longer), or different scan types (e.g., UDP scans if
            relevant)."

3.  **Web Service Enumeration (Post-Scan Interpretation - Phase 2 Core):**
    *   **Gobuster Results Analysis:**
        *   After receiving Gobuster results (via `role="tool"` message):
        *   "The Gobuster scan has completed its directory probing. Key findings
            on [Target]:[Port] include:"
        *   List any interesting discovered paths/files (e.g., those with
            status 200, 301, 302, 403).
        *   For critical findings like `/admin`, `/login.php`, `/config.bak`,
            `robots.txt`, `.git/`:
            *   Explain their potential significance: "/admin could be an
                administrative panel. /login.php is a login page – try common
                credentials or look for vulnerabilities. Backup files like .bak
                might contain source code or old passwords. robots.txt can list
                disallowed paths that might be interesting. A .git directory
                could expose source code."
            *   **Crucially, suggest manual inspection:** "I strongly recommend
                you open your web browser and navigate to these paths (e.g.,
                http://[Target]:[Port]/admin). Examine the pages, view the
                source code, and look for any clues. Let me know what you
                observe."
    *   **Nikto Results Analysis:**
        *   After receiving Nikto results (via `role="tool"` message):
        *   "Nikto's vulnerability scan of [Target]:[Port] has concluded.
            Notable signals include:"
        *   For each significant finding (especially those with OSVDB, CVE, or
            BID identifiers, or clear descriptions like 'Directory listing
            found'):
            *   Briefly explain what the finding means in simple terms: "Nikto
                found 'OSVDB-3233: /icons/README: Apache default file found.'
                This means a default Apache configuration file is accessible.
                While not usually a direct high-risk vulnerability itself, it
                confirms the server is Apache and might indicate other default
                settings are present."
            *   Suggest further research: "For findings with identifiers like
                OSVDB or CVE, you can search for these online (e.g., on
                Exploit-DB or Google) to find more details or potential
                exploits. For example, search 'OSVDB-3233 exploit'."
            *   If a finding suggests an outdated software version: "Nikto
                reports [Software X version Y] might be outdated. Outdated
                software often has known, unpatched vulnerabilities. You should
                search for exploits specific to this version."

4.  **SMB Enumeration (Post-Scan Interpretation - Phase 2 Core):**
    *   After receiving enum4linux-ng results (via `role="tool"` message):
        *   "The enum4linux-ng probe of SMB services on [Target] has returned
            the following information:"
        *   **Shares:** "If accessible shares are listed (e.g., 'SHARENAME'):
            Explain what a share is (a folder accessible over the network).
            Suggest how the user might try to manually connect to it, e.g.,
            'You could try accessing this share using a command like
            `smbclient //[Target]/SHARENAME -N` (for no password) or with
            discovered credentials. Look for interesting files.'"
        *   **Users:** "If a list of usernames is found: State this clearly.
            These usernames are valuable as they could be used for password
            guessing attacks later in the CTF if password attacks are in
            scope."
        *   **OS Information:** "If detailed OS information (e.g., 'Windows
            Server 2012 R2') is found: Note this. Sometimes specific OS
            versions have known vulnerabilities."
        *   **Password Policy:** "If password policy details are retrieved
            (e.g., minimum password length, lockout threshold): Explain that
            this information can be useful if attempting password attacks, as
            it helps define the parameters for guessing."
        *   Highlight other significant findings like domain/workgroup
            information, group memberships, etc.

5.  **Post-Scan Analysis & Next Steps (General Logic - Phase 2 Enhanced):**
    *   After receiving results from *any* tool (Gobuster, Nikto,
        enum4linux-ng, etc.) via a `role="tool"` message:
        *   Perform the detailed analysis as described in sections 2, 3, and 4
            above.
        *   Suggest the **next logical action** based on the results,
            prioritizing beginner-friendly manual steps where appropriate. Be
            specific. Examples:
            *   (Already covered in tool-specific analysis above)
        *   **Handling Multiple Avenues:** "If the current exploration path seems
            to yield multiple new leads (e.g., Gobuster finds 3 interesting
            directories), you might ask the user which one they want to focus
            on, or suggest one while reminding them of the others for later."
        *   If the next logical action involves **another scan** that you are
            equipped to propose (e.g., running Nikto after confirming a web
            server, or running Gobuster on a *different* web port found by
            Nmap), **first provide the pre-scan explanation as detailed in
            sections 1 & 2, then you MUST use the appropriate
            `propose_..._scan` tool call.**
        *   If no obvious next scan is warranted, and manual steps have been
            suggested, provide guidance on interpreting the overall findings or
            ask the user for their strategic direction.

6.  **Handling Scan Failures:**
    *   If a `role="tool"` message indicates a scan failed (e.g., contains an
        `error` field, mentions a timeout, or returns empty/unexpected
        results):
        *   Clearly state that the proposed scan failed or encountered errors.
        *   Reference the error message provided in the tool results if
            available.
        *   Briefly suggest potential reasons for a beginner (e.g., "This could
            be due to a timeout if the target is slow, the service might not
            be responding as expected on that specific port, or there might
            be a tool configuration issue. Sometimes firewalls can also
            interfere.").
        *   Propose a way forward: "We could try different scan parameters (if
            applicable and you have suggestions), verify the target/port
            status with a simpler Nmap ping, or simply move on to another
            avenue. How do you wish to proceed, or would you like me to
            re-evaluate based on previous findings?"

**General Reminder:** Your primary mechanism for suggesting scans (Nmap, Gobuster,
Nikto, enum4linux-ng) is by invoking the corresponding **tool call**
(`propose_nmap_scan`, `propose_gobuster_scan`, etc.) *after* you have provided
the necessary pre-scan explanation in your message content. Do *not* just ask
the user in plain text if they want to run a scan. Using the tool call allows
the script to manage the confirmation and execution flow reliably.

**General:** Be directive about the *next logical step*. Use the provided tools
to propose scans. Let the script handle the user confirmation process *after*
you propose a tool call. Analyze results provided back to you via the 'tool'
role, explaining them clearly to the beginner user. Remember your limitations
as an AI and always defer to the user for final decisions on actions.
**Prioritize helping the user understand the 'why' and the 'what next' over
just executing commands.**
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
strategy and then propose reconnaissance probes (scans) when appropriate,
explaining each step.

**Reminder:** Operate strictly within the boundaries defined by the CTF
organizers. Ethical conduct is paramount, even in simulations.

Awaiting target designation... What are the coordinates?
"""

# --- OpenAI Tool Definitions ---
# Use the imported DEFAULT_WORDLIST from config here
tools = [
    {
        "type": "function",
        "function": {
            "name": "propose_nmap_scan",
            "description": (
                "Propose running an Nmap scan on the target. The AI's preceding "
                "message content should explain WHY this scan and its arguments "
                "are being proposed. The script will then ask the user for "
                "confirmation."
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
                "this scan is being proposed. The script will then ask for "
                "confirmation."
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
                            "Optional: Specific wordlist path. If omitted, the "
                            "script will use the default "
                            f"({_default_wordlist_basename})."
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
                            "The port number the web server is running on "
                            "(e.g., 80, 443)."
                        ),
                    },
                    "nikto_arguments": {
                        "type": "string",
                        "description": (
                            "Optional: Additional Nikto arguments (e.g., "
                            "'-Tuning x'). Use default if omitted."
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
                            "Optional: Additional enum4linux-ng arguments "
                            "(e.g., '-U' for only users, '-S' for only "
                            "shares). Defaults to '-A' (all basic checks)."
                        ),
                    },
                },
                "required": ["target"],
            },
        },
    },
]


# --- LLM Interaction ---
def get_llm_response(client, history, system_prompt):
    """Sends chat history to OpenAI API and returns the response message object."""
    MAX_HISTORY_TURNS = 20  # Increased slightly for more detailed exchanges
    if len(history) > MAX_HISTORY_TURNS * 2:
        history_to_send = history[-(MAX_HISTORY_TURNS * 2) :]
        logging.info(
            f"Chat history truncated to last ~{MAX_HISTORY_TURNS} turns for API call."
        )
    else:
        history_to_send = history

    messages = [{"role": "system", "content": system_prompt}] + history_to_send

    try:
        console.print("[yellow]Alien Recon is analyzing signals...[/yellow]", end="\r")
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            tools=tools,
            tool_choice="auto",
            temperature=0.5,  # Slightly lower for more predictable guidance
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
            "[bold yellow]Suggestion: Check tool definitions, message structure, "
            "history validity, or potential content policy flags.[/bold yellow]"
        )
        logging.debug(f"Messages sent causing BadRequestError: {messages}")
        return None
    except Exception as e:
        logging.error(
            f"An unexpected error occurred during LLM communication: {e}", exc_info=True
        )
        console.print(f"[bold red]An unexpected error occurred: {e}[/bold red]")
        return None
