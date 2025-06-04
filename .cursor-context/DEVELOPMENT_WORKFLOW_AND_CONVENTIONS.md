# Alien Recon (a37) - Development Workflow and Conventions

## Version Control
-   **Main Branch**: `main`
-   **Feature Branches**: All development should be done on feature branches and merged into `main` via pull requests (standard practice).

## Dependency Management
-   **Poetry**: The project uses Poetry for dependency management and packaging.
    -   Install dependencies: `poetry install`
    -   Activate virtual environment: `poetry shell`
-   **Python Version**: Requires Python 3.11+ (as specified in `pyproject.toml` and `.github/workflows/ci.yml`).

## Linting & Formatting
-   **Ruff**: Used for both linting and formatting, replacing tools like Flake8, Black, and isort.
-   **Pre-commit**: Enforces linting and formatting checks before commits. Configuration is in `.pre-commit-config.yaml`.
    -   To install: `poetry run pre-commit install`
    -   To run manually: `poetry run pre-commit run --all-files`

## CI Pipeline
-   **GitHub Actions**: The CI pipeline is defined in `.github/workflows/ci.yml`.
-   **Triggers**: Runs on pushes and pull requests to the `main` branch.
-   **Jobs**:
    1.  Checks out repository code.
    2.  Sets up Python 3.11.
    3.  Installs Poetry.
    4.  Caches and installs dependencies using `poetry install`.
    5.  Installs the project itself.
    6.  Runs linters and formatters via `pre-commit run --all-files`.
    7.  (Future: Test execution with `pytest`).

## Testing
-   **Location**: Parser unit tests and fixtures are located in the `tests/` directory, with subdirectories for `fixtures` and `tools` (e.g., `tests/tools/test_nmap.py`).
-   **Fixtures**: Sample raw outputs for tools are stored in the `tests/fixtures/` directory, with subdirectories for `fixtures` and `tools` (e.g., `nmap_sample.xml`).
-   **Schema**: All tool parsers must produce results conforming to the `ToolResult` TypedDict schema defined in `src/alienrecon/core/types.py`.
-   **Coverage**: Aim for >80% test coverage for parsers, including success, failure, and edge cases.

## Adding New Tools
1.  **Tool Wrapper (`src/alienrecon/tools/`)**:
    * If it's an external command-line tool, create a new Python module (e.g., `newtool.py`).
    * Define a class inheriting from `CommandTool` (from `src/alienrecon/tools/base.py`).
    * Set `executable_name`.
    * Implement `build_command(**kwargs) -> list[str]` to construct the command arguments.
    * Implement `parse_output(stdout, stderr, **kwargs) -> ToolResult` to parse its output into the standard `ToolResult` schema. Add sample output to `tests/fixtures/` and create corresponding tests in `tests/tools/`.
2.  **Configuration (`src/alienrecon/core/config.py`)**:
    * If the tool executable path needs to be discoverable, add its `executable_name` and a fallback path to `KNOWN_TOOL_FALLBACK_PATHS`.
3.  **LLM Function (`src/alienrecon/tools/llm_functions.py`)**:
    * Create a dedicated function (e.g., `newtool_action(param1, param2)`) that takes well-defined parameters.
    * This function should call the `NewTool.execute()` method.
    * It should handle parameter validation and provide intelligent defaults if applicable.
    * Register this function in the `LLM_TOOL_FUNCTIONS` dictionary with its description, parameters (types, descriptions, defaults), and required parameters. This makes it available for the AI to call.
4.  **Documentation**:
    * Update `DEDICATED_FUNCTIONS.md` with the new LLM function.
    * Add new tool to `ARCHITECTURE_AND_MODULES.md`.
