# Alien Recon (a37) - Architecture and Modules

## High-Level Directory Structure
The project follows a `src`-layout:
\`\`\`
a37/
├── .github/workflows/        # CI/CD pipeline (ci.yml)
├── .alienrecon_session.json  # Stores current session state (target, history, mode)
├── src/alienrecon/           # Main source code for the 'alienrecon' package
│   ├── cli.py                # Typer-based Command Line Interface entry point
│   ├── core/                 # Core logic and foundational components
│   │   ├── __init__.py
│   │   ├── agent.py          # AI agent persona, system prompts, LLM interaction
│   │   ├── config.py         # API keys, default wordlists, tool path configurations
│   │   ├── session.py        # Session management, tool initialization, interactive loop
│   │   └── types.py          # Shared TypedDict definitions (e.g., ToolResult)
│   ├── tools/                # Wrappers for external and internal reconnaissance tools
│   │   ├── __init__.py
│   │   ├── base.py           # Abstract base class 'CommandTool' for external tools
│   │   ├── ffuf.py           # FFUF tool wrapper
│   │   ├── hydra.py          # Hydra tool wrapper
│   │   ├── llm_functions.py  # Dedicated functions for LLM tool calling and parameter handling
│   │   ├── nikto.py          # Nikto tool wrapper
│   │   └── nmap.py           # Nmap tool wrapper
│   │   └── smb.py            # enum4linux-ng (SMB enumeration) tool wrapper
│   ├── wordlists/            # Project-specific wordlists (e.g., dns-fast-clean.txt)
│   └── __main__.py           # Allows running the package as a script (if configured)
├── tests/                    # Unit and integration tests
│   ├── fixtures/             # Sample outputs for testing parsers
│   └── tools/                # Tests for individual tool wrappers (e.g., test_nmap.py)
├── .gitignore
├── .pre-commit-config.yaml   # Configuration for pre-commit hooks (ruff)
├── a37-roadmap.md            # Project roadmap and development phases
├── DEDICATED_FUNCTIONS.md    # Documentation for LLM-callable tool functions
├── README.md                 # Main project README
└── pyproject.toml            # Poetry project configuration and dependencies
\`\`\`

## Key Modules & Their Roles

* **`src/alienrecon/cli.py`**:
    * Entry point for the `alienrecon` command-line tool, built using Typer.
    * Defines subcommands (e.g., `recon`, `target`, `doctor`, `manual tool calls`).
    * Initializes and invokes `SessionController` for assistant-driven workflows.

* **`src/alienrecon/core/session.py` (`SessionController`)**:
    * Manages the overall state of a reconnaissance session, including the current target, chat history, and mode (novice/expert).
    * Initializes instances of all available tools (e.g., `NmapTool`).
    * Handles the interactive loop with the user, sending user input to the LLM and processing responses.
    * Orchestrates tool execution based on LLM proposals and user confirmation, including parameter editing.
    * Saves and loads session state to/from `.alienrecon_session.json`.

* **`src/alienrecon/core/agent.py`**:
    * Defines the AI agent's persona and system prompt (`AGENT_SYSTEM_PROMPT`).
    * Contains the `get_llm_response` function to interact with the OpenAI API.
    * Dynamically generates the `tools` list for OpenAI function calling based on `LLM_TOOL_FUNCTIONS`.

* **`src/alienrecon/core/config.py`**:
    * Loads essential configurations like `OPENAI_API_KEY`.
    * Defines default paths for wordlists (`DEFAULT_WORDLIST`) and password lists (`DEFAULT_PASSWORD_LIST`).
    * Resolves and stores paths to external tool executables (`TOOL_PATHS`) using `shutil.which` and fallback paths.

* **`src/alienrecon/core/cache.py`**:
    * Implements TTL-based result caching to avoid redundant tool executions.
    * Provides the `ResultCache` class and `@cache_result` decorator.
    * Stores cached results in `.alienrecon/cache/` with configurable expiration times.
    * Includes cache management features (statistics, invalidation).

* **`src/alienrecon/core/parallel_executor.py`**:
    * Enables parallel execution of multiple reconnaissance tools.
    * Uses `asyncio` and `ThreadPoolExecutor` for concurrent tool runs.
    * Provides progress tracking and formatted result display.
    * Intelligently determines when parallel execution is safe and beneficial.

* **`src/alienrecon/tools/` (Individual Tool Wrappers, e.g., `nmap.py`, `ffuf.py`)**:
    * Each file typically defines a class inheriting from `CommandTool` (from `base.py`).
    * Responsibilities include:
        * `build_command()`: Constructs the command-line arguments for the specific tool.
        * `parse_output()`: Parses the raw stdout/stderr from the tool into the structured `ToolResult` format (defined in `src/alienrecon/core/types.py`).
    * `http_fetcher.py` is an internal tool, not a `CommandTool` subclass, and directly uses the `requests` library.

* **`src/alienrecon/tools/llm_functions.py`**:
    * Contains dedicated Python functions (e.g., `nmap_scan`, `ffuf_vhost_enum`) designed to be called by the LLM.
    * These functions handle parameter validation, call the appropriate tool wrapper's `execute` method, and return structured results.
    * They are registered in `LLM_TOOL_FUNCTIONS` dictionary, which is used by `agent.py` to define tools for the LLM.
    * Implements logic for smart wordlist selection and default parameter values.

## Data Flow for a Typical Command (e.g., `alienrecon recon --target 10.10.10.10`)

1.  User runs `alienrecon recon --target <target_ip>` via the command line.
2.  **`cli.py`** parses the command and arguments.
3.  `cli.py` instantiates `SessionController` from **`core/session.py`**.
4.  `SessionController` initializes tools (Nmap, ffuf, etc.) by checking `TOOL_PATHS` from **`core/config.py`**.
5.  `SessionController` sets the target and novice/expert mode.
6.  `SessionController.start_interactive_recon_session()` begins the main loop:
    a.  If chat history is empty for a new target, an initial prompt is constructed to guide the AI (e.g., to suggest an Nmap scan).
    b.  User input is collected.
    c.  The chat history and system prompt (from **`core/agent.py`**) are sent to the LLM via `_get_llm_response_from_agent()`.
    d.  The LLM response is processed by `_process_llm_message()`:
        i.  Text content is displayed.
        ii. If `tool_calls` are present, `_confirm_tool_proposal()` allows user to edit/confirm parameters for the function in **`tools/llm_functions.py`**.
        iii. If confirmed, `_execute_single_tool_call_and_update_history()` calls the relevant function from **`tools/llm_functions.py`**.
        iv. The `llm_function` then calls the `execute()` method of the corresponding tool wrapper (e.g., `NmapTool.execute()`).
        v. The tool wrapper builds the command, runs it, parses the output, and returns a `ToolResult`.
        vi. The `llm_function` returns this `ToolResult` (or a slightly modified version) as a JSON string.
        vii. This JSON string is added to the chat history with `role: "tool"`.
        viii. The updated history is sent back to the LLM for the next turn.
    e.  The loop continues.
7.  Session state (target, history, mode) is saved to `.alienrecon_session.json` periodically.
