"""
Parallel execution support for Alien Recon tools.

Enables running multiple reconnaissance tools simultaneously for faster results.
"""

import asyncio
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from ..tools.llm_functions import LLM_TOOL_FUNCTIONS

logger = logging.getLogger(__name__)


class ParallelExecutor:
    """Handles parallel execution of multiple tool calls."""

    def __init__(self, console: Console, max_workers: int = 5):
        """
        Initialize the parallel executor.

        Args:
            console: Rich console for output
            max_workers: Maximum number of concurrent tool executions
        """
        self.console = console
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        logger.info(f"Parallel executor initialized with {max_workers} workers")

    async def execute_tools_parallel(
        self, tool_calls: list[tuple[str, str, str, dict[str, Any]]]
    ) -> list[dict[str, Any]]:
        """
        Execute multiple tools in parallel.

        Args:
            tool_calls: List of tuples (tool_call_id, function_name, display_name, arguments)

        Returns:
            List of results in the same order as tool_calls
        """
        # Create progress display
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=self.console,
        )

        # Create tasks for each tool
        tasks = []
        task_ids = []

        with progress:
            for tool_call_id, function_name, display_name, arguments in tool_calls:
                task_id = progress.add_task(f"Running {display_name}...", total=None)
                task_ids.append(task_id)

                # Create async task
                task = self._execute_tool_async(
                    tool_call_id, function_name, arguments, progress, task_id
                )
                tasks.append(task)

            # Execute all tasks concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Mark all tasks as complete
            for task_id in task_ids:
                progress.stop_task(task_id)

        # Process results
        processed_results = []
        for i, (result, (tool_call_id, function_name, display_name, _)) in enumerate(
            zip(results, tool_calls)
        ):
            if isinstance(result, Exception):
                logger.error(f"Error executing {function_name}: {result}")
                processed_results.append(
                    {
                        "tool_call_id": tool_call_id,
                        "function_name": function_name,
                        "result": {
                            "status": "failure",
                            "error": f"Execution error: {str(result)}",
                        },
                    }
                )
            else:
                processed_results.append(
                    {
                        "tool_call_id": tool_call_id,
                        "function_name": function_name,
                        "result": result,
                    }
                )

        return processed_results

    async def _execute_tool_async(
        self,
        tool_call_id: str,
        function_name: str,
        arguments: dict[str, Any],
        progress: Progress,
        task_id: int,
    ) -> dict[str, Any]:
        """
        Execute a single tool asynchronously.

        Args:
            tool_call_id: Unique ID for this tool call
            function_name: Name of the function to execute
            arguments: Arguments for the function
            progress: Progress display object
            task_id: Progress task ID

        Returns:
            Tool execution result
        """
        try:
            # Get the tool function
            tool_info = LLM_TOOL_FUNCTIONS.get(function_name)
            if not tool_info or not callable(tool_info.get("function")):
                raise ValueError(f"Tool function '{function_name}' not found")

            actual_tool_function = tool_info["function"]

            # Create a wrapper function that calls the tool with keyword arguments
            def tool_wrapper():
                return actual_tool_function(**arguments)

            # Run the tool in a thread pool (since most tools are blocking I/O)
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(self.executor, tool_wrapper)

            # Update progress
            progress.update(
                task_id, description=f"[green]✓[/green] {function_name} complete"
            )

            return result

        except Exception as e:
            logger.error(f"Error in _execute_tool_async for {function_name}: {e}")
            progress.update(task_id, description=f"[red]✗[/red] {function_name} failed")
            raise

    def display_parallel_results(
        self, results: list[dict[str, Any]], show_details: bool = True
    ):
        """
        Display results from parallel execution in a formatted way.

        Args:
            results: List of result dictionaries from execute_tools_parallel
            show_details: Whether to show detailed findings
        """
        # Create summary table
        table = Table(title="Parallel Execution Results", show_header=True)
        table.add_column("Tool", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Summary", style="dim")
        table.add_column("Cache", style="green")

        for result_info in results:
            function_name = result_info["function_name"]
            result = result_info["result"]

            status = result.get("status", "unknown")
            status_display = (
                "[green]Success[/green]" if status == "success" else "[red]Failed[/red]"
            )

            summary = result.get("scan_summary", result.get("error", "No summary"))
            if len(summary) > 50:
                summary = summary[:47] + "..."

            from_cache = result.get("_from_cache", False)
            cache_display = "✓" if from_cache else "-"

            table.add_row(function_name, status_display, summary, cache_display)

        self.console.print(table)

        # Show detailed results if requested
        if show_details:
            self.console.print("\n[bold]Detailed Results:[/bold]")
            for result_info in results:
                function_name = result_info["function_name"]
                result = result_info["result"]

                # Remove cache metadata from display
                display_result = result.copy() if isinstance(result, dict) else result
                if isinstance(display_result, dict) and "_from_cache" in display_result:
                    from_cache = display_result.pop("_from_cache")
                else:
                    from_cache = False

                cache_indicator = " [green](CACHED)[/green]" if from_cache else ""

                if display_result.get("status") == "failure":
                    self.console.print(
                        Panel(
                            f"[red]Error: {display_result.get('error', 'Unknown error')}[/red]",
                            title=f"{function_name} Failed{cache_indicator}",
                            border_style="red",
                        )
                    )
                elif "findings" in display_result and display_result["findings"]:
                    findings_json = json.dumps(display_result["findings"], indent=2)
                    self.console.print(
                        Panel(
                            findings_json[:1000]
                            + ("..." if len(findings_json) > 1000 else ""),
                            title=f"{function_name} Findings{cache_indicator}",
                            border_style="green",
                        )
                    )
                else:
                    self.console.print(
                        Panel(
                            display_result.get("scan_summary", "No findings"),
                            title=f"{function_name} Summary{cache_indicator}",
                            border_style="blue",
                        )
                    )

    def should_run_parallel(
        self, tool_calls: list[tuple[str, str, str, dict[str, Any]]]
    ) -> bool:
        """
        Determine if tools should be run in parallel.

        Args:
            tool_calls: List of tool calls to execute

        Returns:
            True if parallel execution is recommended
        """
        # Don't parallelize single tool
        if len(tool_calls) <= 1:
            return False

        # Check if all tools are read-only (safe to parallelize)
        read_only_tools = {
            "nmap_scan",
            "nikto_scan",
            "ffuf_dir_enum",
            "ffuf_vhost_enum",
            "http_fetch",
            "inspect_ssl_certificate",
        }

        all_read_only = all(call[1] in read_only_tools for call in tool_calls)

        return all_read_only

    def cleanup(self):
        """Cleanup resources."""
        self.executor.shutdown(wait=False)


# Utility function for backwards compatibility
async def execute_tools_parallel(
    console: Console,
    tool_calls: list[tuple[str, str, str, dict[str, Any]]],
    max_workers: int = 5,
) -> list[dict[str, Any]]:
    """
    Execute multiple tools in parallel (convenience function).

    Args:
        console: Rich console for output
        tool_calls: List of tuples (tool_call_id, function_name, display_name, arguments)
        max_workers: Maximum number of concurrent executions

    Returns:
        List of results
    """
    executor = ParallelExecutor(console, max_workers)
    try:
        results = await executor.execute_tools_parallel(tool_calls)
        return results
    finally:
        executor.cleanup()
