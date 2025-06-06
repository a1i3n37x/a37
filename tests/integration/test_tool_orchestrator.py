# tests/integration/test_tool_orchestrator.py
"""Integration tests for tool orchestrator."""

import pytest
from unittest.mock import Mock, patch

from src.alienrecon.core.tool_orchestrator import ToolOrchestrator
from src.alienrecon.core.exceptions import ToolExecutionError, ValidationError, SecurityError


class TestToolOrchestrator:
    """Test tool orchestrator functionality."""
    
    @pytest.fixture
    def orchestrator(self):
        """Create tool orchestrator with mocked cache."""
        with patch('src.alienrecon.core.tool_orchestrator.ResultCache') as mock_cache:
            mock_cache_instance = Mock()
            mock_cache_instance.get.return_value = None  # No cache hits by default
            mock_cache.return_value = mock_cache_instance
            
            orchestrator = ToolOrchestrator(cache=mock_cache_instance)
            return orchestrator
    
    def test_tool_registration(self, orchestrator):
        """Test tool registration and retrieval."""
        available_tools = orchestrator.get_available_tools()
        
        # Check that standard tools are registered
        expected_tools = ["nmap", "nikto", "ffuf", "smb", "hydra", "http_fetcher"]
        for tool in expected_tools:
            assert tool in available_tools
        
        # Test getting specific tool
        nmap_tool = orchestrator.get_tool("nmap")
        assert nmap_tool is not None
        assert nmap_tool.__class__.__name__ == "NmapTool"
    
    def test_argument_validation(self, orchestrator):
        """Test argument validation for different tools."""
        # Valid arguments
        valid_nmap_args = orchestrator.validate_tool_args("nmap", {
            "target": "192.168.1.1",
            "port": "80",
            "arguments": "-sV"
        })
        
        assert valid_nmap_args["target"] == "192.168.1.1"
        assert valid_nmap_args["port"] == 80
        
        # Invalid target
        with pytest.raises(ValidationError):
            orchestrator.validate_tool_args("nmap", {"target": "invalid..target"})
        
        # Invalid port
        with pytest.raises(ValidationError):
            orchestrator.validate_tool_args("nmap", {"port": "99999"})
    
    @patch('src.alienrecon.tools.base.run_command')
    def test_tool_execution(self, mock_run_command, orchestrator):
        """Test tool execution through orchestrator."""
        # Mock successful execution
        mock_run_command.return_value = (
            "# Nmap scan report\n80/tcp open http",
            None
        )
        
        result = orchestrator.execute_tool(
            "nmap",
            {"target": "example.com", "scan_type": "quick"}
        )
        
        assert result["success"] is True
        assert "data" in result
    
    @patch('src.alienrecon.tools.base.run_command')
    def test_parallel_execution(self, mock_run_command, orchestrator):
        """Test parallel tool execution."""
        import asyncio
        
        # Mock different outputs for different tools
        mock_run_command.side_effect = [
            ("# Nmap results", None),
            ("+ Nikto results", None)
        ]
        
        tool_requests = [
            {"tool": "nmap", "args": {"target": "example.com"}},
            {"tool": "nikto", "args": {"url": "http://example.com"}}
        ]
        
        results = asyncio.run(
            orchestrator.execute_tools_parallel(tool_requests)
        )
        
        assert len(results) == 2
        assert all(result.get("success") for result in results)
    
    def test_security_validation(self, orchestrator):
        """Test security validation in tool orchestrator."""
        # Test that dangerous arguments are rejected
        with pytest.raises(SecurityError):
            orchestrator.validate_tool_args("nmap", {
                "target": "example.com; rm -rf /"
            })
    
    def test_caching_behavior(self, orchestrator):
        """Test result caching."""
        with patch('src.alienrecon.tools.base.run_command') as mock_run_command:
            mock_run_command.return_value = ("# Nmap results", None)
            
            # First execution
            result1 = orchestrator.execute_tool(
                "nmap",
                {"target": "example.com", "scan_type": "quick"},
                use_cache=True
            )
            
            # Mock cache hit for second execution
            orchestrator.cache.get.return_value = result1
            
            result2 = orchestrator.execute_tool(
                "nmap", 
                {"target": "example.com", "scan_type": "quick"},
                use_cache=True
            )
            
            # Should only call run_command once
            assert mock_run_command.call_count == 1
    
    def test_tool_registration_custom(self, orchestrator):
        """Test registering custom tools."""
        from src.alienrecon.tools.base import CommandTool
        from src.alienrecon.core.types import ToolResult
        
        class CustomTool(CommandTool):
            name = "custom"
            executable_name = "echo"
            
            def build_command(self, **kwargs):
                return ["hello", "world"]
            
            def parse_output(self, stdout, stderr, **kwargs) -> ToolResult:
                return {
                    "success": True,
                    "data": {"output": stdout},
                    "summary": "Custom tool executed"
                }
        
        orchestrator.register_tool("custom", CustomTool)
        
        assert "custom" in orchestrator.get_available_tools()
        custom_tool = orchestrator.get_tool("custom")
        assert custom_tool is not None
    
    def test_error_handling(self, orchestrator):
        """Test error handling in tool execution."""
        # Test with non-existent tool
        result = orchestrator.execute_tool("nonexistent", {})
        assert result["success"] is False
        assert "Tool not found" in result["error"]
        
        # Test with invalid arguments
        result = orchestrator.execute_tool("nmap", {"target": ""})
        assert result["success"] is False
        assert "Validation error" in result["error"]
    
    def test_tool_info(self, orchestrator):
        """Test getting tool information."""
        nmap_info = orchestrator.get_tool_info("nmap")
        
        assert nmap_info is not None
        assert nmap_info["name"] == "nmap"
        assert nmap_info["available"] is True
        
        # Test non-existent tool
        nonexistent_info = orchestrator.get_tool_info("nonexistent")
        assert nonexistent_info is None