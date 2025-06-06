# src/alienrecon/core/tool_orchestrator.py
"""Tool orchestration and execution management."""

import asyncio
import logging
from typing import Any, Optional

from ..tools.base import CommandTool
from ..tools.ffuf import FFUFTool
from ..tools.http_fetcher import HttpPageFetcherTool
from ..tools.http_ssl_probe import HTTPSSLProbeTool
from ..tools.hydra import HydraTool
from ..tools.nikto import NiktoTool
from ..tools.nmap import NmapTool
from ..tools.searchsploit import SearchsploitTool
from ..tools.smb import SmbTool
from ..tools.ssl_inspector import SSLInspectorTool
from .cache import ResultCache
from .exceptions import ToolExecutionError, ValidationError
from .input_validator import InputValidator

logger = logging.getLogger(__name__)


class ToolOrchestrator:
    """Manages tool instantiation, execution, and result processing."""

    # Tool registry
    TOOL_REGISTRY: dict[str, type[CommandTool]] = {
        "nmap": NmapTool,
        "nikto": NiktoTool,
        "ffuf": FFUFTool,
        "smb": SmbTool,
        "hydra": HydraTool,
        "http_fetcher": HttpPageFetcherTool,
        "ssl_inspector": SSLInspectorTool,
        "http_ssl_probe": HTTPSSLProbeTool,
        "searchsploit": SearchsploitTool,
    }

    def __init__(self, cache: Optional[ResultCache] = None):
        self.cache = cache or ResultCache()
        self.tools: dict[str, CommandTool] = {}
        self._initialize_tools()

    def _initialize_tools(self) -> None:
        """Initialize all registered tools."""
        for tool_name, tool_class in self.TOOL_REGISTRY.items():
            try:
                self.tools[tool_name] = tool_class()
                logger.info(f"Initialized tool: {tool_name}")
            except Exception as e:
                logger.error(f"Failed to initialize {tool_name}: {e}")

    def get_tool(self, tool_name: str) -> Optional[CommandTool]:
        """Get a tool instance by name."""
        return self.tools.get(tool_name)

    def register_tool(self, name: str, tool_class: type[CommandTool]) -> None:
        """Register a new tool."""
        try:
            self.TOOL_REGISTRY[name] = tool_class
            self.tools[name] = tool_class()
            logger.info(f"Registered new tool: {name}")
        except Exception as e:
            raise ToolExecutionError(f"Failed to register tool {name}: {e}")

    def validate_tool_args(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Validate and sanitize tool arguments."""
        validated_args = {}

        # Common validations
        if "target" in args:
            validated_args["target"] = InputValidator.validate_target(args["target"])

        if "port" in args:
            validated_args["port"] = InputValidator.validate_port(args["port"])

        if "ports" in args:
            validated_args["ports"] = InputValidator.validate_port_list(args["ports"])

        # Tool-specific validations
        if tool_name == "nmap":
            if "arguments" in args:
                # Sanitize additional nmap arguments
                validated_args["arguments"] = " ".join(
                    InputValidator.sanitize_command_args(args["arguments"])
                )

        elif tool_name == "hydra":
            if "username" in args:
                validated_args["username"] = InputValidator.validate_username(args["username"])
            if "wordlist" in args:
                validated_args["wordlist"] = str(
                    InputValidator.validate_wordlist_path(args["wordlist"])
                )

        elif tool_name in ["ffuf", "nikto"]:
            if "url" in args:
                validated_args["url"] = InputValidator.validate_url(args["url"])

        # Copy over other args that don't need validation
        for key, value in args.items():
            if key not in validated_args:
                validated_args[key] = value

        return validated_args

    async def execute_tool_async(
        self, tool_name: str, args: dict[str, Any], use_cache: bool = True
    ) -> dict[str, Any]:
        """Execute a tool asynchronously with validation."""
        tool = self.get_tool(tool_name)
        if not tool:
            raise ToolExecutionError(f"Tool not found: {tool_name}")

        try:
            # Validate arguments
            validated_args = self.validate_tool_args(tool_name, args)

            # Check cache if enabled
            if use_cache:
                cache_key = f"{tool_name}:{validated_args}"
                cached_result = self.cache.get(cache_key)
                if cached_result:
                    logger.info(f"Returning cached result for {tool_name}")
                    return cached_result

            # Execute tool
            logger.info(f"Executing {tool_name} with args: {validated_args}")

            # Build command
            command = tool.build_command(**validated_args)

            # Execute command
            output = await asyncio.to_thread(tool.execute_command, command)

            # Parse output
            result = tool.parse_output(output)

            # Cache result if successful
            if use_cache and result.get("success"):
                self.cache.set(cache_key, result)

            return result

        except ValidationError as e:
            logger.error(f"Validation error for {tool_name}: {e}")
            return {"success": False, "error": f"Validation error: {e}"}
        except Exception as e:
            logger.error(f"Error executing {tool_name}: {e}")
            return {"success": False, "error": f"Execution error: {e}"}

    def execute_tool(
        self, tool_name: str, args: dict[str, Any], use_cache: bool = True
    ) -> dict[str, Any]:
        """Execute a tool synchronously."""
        return asyncio.run(self.execute_tool_async(tool_name, args, use_cache))

    async def execute_tools_parallel(
        self, tool_requests: list[dict[str, Any]], use_cache: bool = True
    ) -> list[dict[str, Any]]:
        """Execute multiple tools in parallel."""
        tasks = []
        for request in tool_requests:
            tool_name = request.get("tool")
            args = request.get("args", {})
            if tool_name:
                task = self.execute_tool_async(tool_name, args, use_cache)
                tasks.append(task)

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            # Convert exceptions to error results
            processed_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    processed_results.append({
                        "success": False,
                        "error": str(result),
                        "tool": tool_requests[i].get("tool", "unknown")
                    })
                else:
                    processed_results.append(result)
            return processed_results
        return []

    def get_available_tools(self) -> list[str]:
        """Get list of available tools."""
        return list(self.tools.keys())

    def get_tool_info(self, tool_name: str) -> Optional[dict[str, Any]]:
        """Get information about a specific tool."""
        tool = self.get_tool(tool_name)
        if tool:
            return {
                "name": tool_name,
                "class": tool.__class__.__name__,
                "description": tool.__class__.__doc__,
                "available": True,
            }
        return None

    def clear_cache(self) -> None:
        """Clear the result cache."""
        self.cache.clear()
        logger.info("Tool result cache cleared")
