"""
Shared types for Alien Recon tool results and core data structures.

ToolResult: Standard result schema for all tool wrappers.
Import and use this in all tool classes and tests to ensure consistency.
"""

from typing import Any, Literal, Optional, TypedDict


class ToolResult(TypedDict, total=False):
    tool_name: str
    status: Literal["success", "failure", "partial"]
    scan_summary: str
    error: Optional[str]
    findings: Any
    raw_stdout: Optional[str]
    raw_stderr: Optional[str]
