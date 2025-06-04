# Alien Recon (a37) - AI Integration Guide

This document outlines how the AI agent in Alien Recon is designed to interact with users and tools, primarily for use as context with AI development assistants like Cursor.

## Agent System Prompt (`src/alienrecon/core/agent.py`)
The core behavior of the Alien Recon AI is guided by `AGENT_SYSTEM_PROMPT`. Key directives include:
-   **Role**: Act as a helpful, knowledgeable, and patient guide for CTF reconnaissance, especially for beginners.
-   **Ethical Hacking Focus**: Assist ONLY with ethical hacking tasks for which the user has explicit permission (e.g., CTF platforms). Assume user-provided targets are authorized.
-   **Communication Style**: Clear, encouraging, direct, like an experienced mentor. Explain concepts simply.
-   **Workflow**:
    -   Propose actions using available 'tools' (function calls) after explaining their relevance.
    -   Always wait for user confirmation/selection before proceeding with a tool.
    -   Prioritize education, clarity, and user control.
    -   Suggest a typical CTF recon flow: initial fast Nmap, then detailed Nmap on open ports, then service-specific enumeration.

## LLM Tool Functions (`src/alienrecon/tools/llm_functions.py`)
-   Alien Recon uses dedicated, purpose-built Python functions for each tool interaction the LLM can propose. These are defined in `src/alienrecon/tools/llm_functions.py`.
-   Each function (e.g., `nmap_scan`, `ffuf_vhost_enum`) is designed with clear parameters, type hints, and often intelligent defaults (e.g., for wordlists, threads).
-   These functions call the respective tool wrappers' `execute()` methods and return structured `ToolResult` data as a JSON string.
-   A comprehensive list and details of these functions, their parameters, and return formats are documented in `DEDICATED_FUNCTIONS.md`.

## Function Calling Mechanism
1.  **Registration**: The `LLM_TOOL_FUNCTIONS` registry in `llm_functions.py` maps function names to their Python callables, descriptions, and parameter schemas.
2.  **Tool Definition for LLM**: In `agent.py`, this registry is used to dynamically generate the `tools` list in the format required by the OpenAI API. This list tells the LLM which functions it can call and what parameters they expect.
3.  **LLM Proposal**: When the LLM decides an action is needed, it responds with `tool_calls` in its message. Each call includes the `function.name` and `function.arguments` (as a JSON string).
4.  **User Confirmation (`SessionController._confirm_tool_proposal`)**:
    -   The `SessionController` in `src/alienrecon/core/session.py` intercepts these `tool_calls`.
    -   For each proposed tool call, it displays the tool name, description, and current/default parameters to the user.
    -   The user can then **[C]onfirm**, **[E]dit** parameters, or **[S]kip** the action.
5.  **Execution (`SessionController._execute_single_tool_call_and_update_history`)**:
    -   If confirmed, the corresponding Python function from `llm_functions.py` is executed with the (potentially edited) arguments.
    -   The function's return value (a dictionary, typically a `ToolResult`) is converted to a JSON string.
6.  **Feedback to LLM**: This JSON string result is then added to the chat history with `role: "tool"`, `tool_call_id`, and `name` (function name). The updated history is sent back to the LLM for the next conversational turn.

## Chat History Management
-   The `SessionController` maintains the `chat_history` as a list of message objects.
-   This history includes messages from the `user`, `assistant`, and `tool` roles.
-   The session (including `chat_history`, `current_target`, and `is_novice_mode`) is saved to `.alienrecon_session.json` after significant events (e.g., adding a message, changing target) and can be loaded when `a37` starts.

## Smart Defaults and Parameter Handling
-   Many LLM tool functions in `llm_functions.py` incorporate intelligent defaults:
    -   **Wordlists**: DNS-related functions (e.g., `ffuf_vhost_enum`) attempt to use smaller, DNS-optimized wordlists first (like `dns-fast-clean.txt`). Directory enumeration functions use `DEFAULT_WORDLIST` from `config.py`.
    -   **Ports/Protocols**: Functions often auto-detect HTTP vs. HTTPS based on port numbers, or have sensible defaults (e.g., port 80/443).
    -   **Threads/Timeouts**: Reasonable defaults are provided for performance and stability.
-   IP address parameters (like `ip` in `nmap_scan` or `ffuf_vhost_enum`) have specific handling in `SessionController._resolve_and_validate_ip` to ensure a numeric IP is used, prioritizing explicit user input, then the session target IP, then DNS resolution.
