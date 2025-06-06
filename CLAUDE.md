# CLAUDE.md
#
This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AlienRecon (a37) is an AI-augmented reconnaissance framework for CTF challenges and security assessments. It provides a conversational AI assistant that guides users through reconnaissance workflows while maintaining educational value.

## Development Commands

### Setup and Dependencies
```bash
# Install dependencies (requires Poetry)
poetry install

# Activate virtual environment
poetry shell
```

### Running the Application
```bash
# Main entry points
alienrecon recon --target <IP>          # Start AI-assisted recon session
alienrecon quick-recon --target <IP>    # Execute predefined recon sequence
alienrecon manual <tool> [options]      # Direct tool execution (bypasses AI)
alienrecon doctor                       # Check system setup
alienrecon init --ctf <box_identifier>  # Initialize CTF mission folder
```

### Code Quality Commands
```bash
# Linting (using Ruff)
poetry run ruff check .              # Check for linting issues
poetry run ruff check . --fix        # Auto-fix linting issues
poetry run ruff format .             # Format code

# Type checking
poetry run mypy src/                 # Run type checking on source code

# Testing
poetry run pytest                    # Run all tests
poetry run pytest -v                 # Verbose test output
poetry run pytest tests/unit/        # Run unit tests only
poetry run pytest tests/integration/ # Run integration tests only
poetry run pytest -k "test_name"     # Run specific test by name
poetry run pytest --cov=src          # Run tests with coverage

# Pre-commit hooks
poetry run pre-commit install        # Install git hooks
poetry run pre-commit run --all-files # Run all checks manually
```

## High-Level Architecture

### Core Flow Pattern
1. **CLI Entry** (`src/alienrecon/cli.py`) → Typer-based command routing
2. **Session Management** (`src/alienrecon/core/session.py`) → Central orchestrator maintaining state
3. **AI Agent** (`src/alienrecon/core/agent.py`) → OpenAI API integration for conversational guidance
4. **Tool Execution** (`src/alienrecon/tools/`) → Security-validated tool wrappers
5. **Results Processing** → Structured JSON + raw output preservation

### Key Architectural Decisions

**Session-Centric Design**: The `Session` class is the central orchestrator that:
- Maintains conversation history with the AI
- Tracks target state (IP, discovered services, findings)
- Manages tool execution through the AI's function calling
- Persists state to `.alienrecon_session.json`

**Tool Integration Pattern**: All tools inherit from `BaseTool` which provides:
- Command injection prevention via `shlex.quote()`
- Input validation framework
- Consistent error handling
- Cache integration for result reuse

**AI Function Calling**: Tools are exposed to the AI via `llm_functions.py`:
- Each tool has an LLM-aware wrapper function
- Functions include educational parameter descriptions
- Error messages provide troubleshooting guidance

**Security First**:
- All user inputs are validated before tool execution
- Command construction uses secure patterns (no shell=True)
- IP addresses, ports, and URLs are strictly validated

### Important Implementation Notes

**Adding New Tools**:
1. Create tool class in `src/alienrecon/tools/` inheriting from `BaseTool`
2. Implement `validate_*` methods for input validation
3. Add LLM function wrapper in `llm_functions.py`
4. Register in `Session._initialize_tools()`

**Session State Management**:
- State saved after each interaction to `.alienrecon_session.json`
- Includes: target info, chat history, discovered findings, active plans
- Recovery from interruptions is automatic

**Multi-Step Planning**:
- Plans stored in session state with conditional execution
- Each step can depend on results of previous steps
- User approval required for each plan execution

**Error Handling Philosophy**:
- Tools should fail gracefully with helpful error messages
- AI should provide troubleshooting suggestions
- Never expose raw system errors to users

## Environment Requirements

- **Python 3.11+** (uses modern type hints with Union syntax)
- **OpenAI API Key** must be set as `OPENAI_API_KEY` environment variable
- External tools must be in PATH: `nmap`, `nikto`, `enum4linux-ng`, `hydra`, `ffuf`, `searchsploit`
- Optional: SecLists for comprehensive wordlists

## Testing Strategy

- **Unit tests** (`tests/unit/`): Test individual components in isolation
- **Integration tests** (`tests/integration/`): Test tool orchestration and workflows
- **Fixtures** (`tests/fixtures/`): Sample tool outputs for consistent testing
- Run tests before committing changes to ensure stability
