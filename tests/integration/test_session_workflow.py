# tests/integration/test_session_workflow.py
"""Integration tests for session workflows with mocked tool execution."""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock

from src.alienrecon.core.refactored_session_controller import RefactoredSessionController
from src.alienrecon.core.exceptions import ValidationError, SecurityError


class TestSessionWorkflow:
    """Test complete session workflows."""
    
    @pytest.fixture
    def mock_openai_client(self):
        """Mock OpenAI client."""
        client = Mock()
        client.chat = Mock()
        client.chat.completions = Mock()
        client.chat.completions.create = Mock()
        return client
    
    @pytest.fixture
    def session_controller(self, tmp_path, mock_openai_client):
        """Create session controller with mocked dependencies."""
        session_file = str(tmp_path / "test_session.json")
        
        with patch('src.alienrecon.core.refactored_session_controller.initialize_openai_client', 
                   return_value=mock_openai_client):
            controller = RefactoredSessionController(session_file=session_file)
        
        return controller
    
    def test_target_setting_workflow(self, session_controller):
        """Test setting and validating targets."""
        # Test valid IP
        session_controller.set_target("192.168.1.1")
        assert session_controller.get_target() == "192.168.1.1"
        
        # Test valid hostname
        session_controller.set_target("example.com")
        assert session_controller.get_target() == "example.com"
        
        # Test invalid target
        with pytest.raises(ValidationError):
            session_controller.set_target("invalid..target")
    
    @patch('src.alienrecon.tools.base.run_command')
    def test_tool_execution_workflow(self, mock_run_command, session_controller):
        """Test tool execution with mocked subprocess calls."""
        # Mock successful nmap execution
        mock_run_command.return_value = (
            """# Nmap scan report for example.com
Host is up (0.1s latency).
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.0
80/tcp   open  http    nginx 1.18""",
            None
        )
        
        session_controller.set_target("example.com")
        result = session_controller.execute_tool(
            "nmap", 
            {"target": "example.com", "scan_type": "quick"}
        )
        
        assert result["success"] is True
        assert "hosts" in result["data"]
        
        # Verify session state was updated
        state = session_controller.session_manager.state
        assert len(state["open_ports"]) > 0
        assert any(port["port"] == 22 for port in state["open_ports"])
        assert any(port["port"] == 80 for port in state["open_ports"])
    
    @patch('src.alienrecon.tools.base.run_command')
    def test_security_validation(self, mock_run_command, session_controller):
        """Test security validation prevents dangerous commands."""
        session_controller.set_target("example.com")
        
        # Test that dangerous arguments are blocked
        with pytest.raises(SecurityError):
            session_controller.execute_tool(
                "nmap",
                {"target": "example.com; rm -rf /", "scan_type": "quick"}
            )
        
        # Verify run_command was never called
        mock_run_command.assert_not_called()
    
    @patch('src.alienrecon.tools.base.run_command')
    def test_plan_execution_workflow(self, mock_run_command, session_controller):
        """Test multi-step plan execution."""
        # Mock command outputs
        mock_run_command.side_effect = [
            # First nmap scan
            ("# Nmap scan report for example.com\n22/tcp open ssh", None),
            # Second nmap scan with service detection
            ("# Nmap scan report for example.com\n22/tcp open ssh OpenSSH 8.0", None)
        ]
        
        session_controller.set_target("example.com")
        
        # Create a plan
        plan = session_controller.create_plan(
            "Test Plan",
            "Test multi-step execution",
            [
                {
                    "tool": "nmap",
                    "args": {"target": "example.com", "scan_type": "quick"},
                    "description": "Quick scan"
                },
                {
                    "tool": "nmap", 
                    "args": {"target": "example.com", "scan_type": "service"},
                    "description": "Service detection"
                }
            ]
        )
        
        # Execute all steps
        step1_result = session_controller.execute_next_plan_step()
        assert step1_result is True
        
        step2_result = session_controller.execute_next_plan_step()
        assert step2_result is True
        
        # Verify plan is completed
        status = session_controller.get_plan_status()
        assert status["status"] == "completed"
        assert status["current_step"] == 2
    
    def test_session_persistence(self, tmp_path, mock_openai_client):
        """Test session persistence across controller instances."""
        session_file = str(tmp_path / "persistence_test.json")
        
        # Create first controller and set some state
        with patch('src.alienrecon.core.refactored_session_controller.initialize_openai_client', 
                   return_value=mock_openai_client):
            controller1 = RefactoredSessionController(session_file=session_file)
        
        controller1.set_target("example.com")
        controller1.session_manager.add_open_port(80, "http", "nginx")
        controller1.save_session()
        
        # Create second controller and verify state is loaded
        with patch('src.alienrecon.core.refactored_session_controller.initialize_openai_client', 
                   return_value=mock_openai_client):
            controller2 = RefactoredSessionController(session_file=session_file)
        
        assert controller2.get_target() == "example.com"
        assert len(controller2.session_manager.state["open_ports"]) == 1
        assert controller2.session_manager.state["open_ports"][0]["port"] == 80
    
    @patch('src.alienrecon.tools.base.run_command')
    def test_parallel_tool_execution(self, mock_run_command, session_controller):
        """Test parallel execution of multiple tools."""
        import asyncio
        
        # Mock different tool outputs
        mock_run_command.side_effect = [
            # Nmap output
            ("# Nmap scan report\n80/tcp open http", None),
            # Nikto output  
            ("+ Server: nginx\n+ Retrieved x-powered-by header: PHP", None)
        ]
        
        session_controller.set_target("example.com")
        
        # Execute tools in parallel
        tool_requests = [
            {"tool": "nmap", "args": {"target": "example.com", "scan_type": "quick"}},
            {"tool": "nikto", "args": {"url": "http://example.com"}}
        ]
        
        results = asyncio.run(
            session_controller.execute_tools_parallel(tool_requests)
        )
        
        assert len(results) == 2
        assert all(result.get("success") for result in results)
    
    def test_input_validation_integration(self, session_controller):
        """Test input validation throughout the system."""
        # Test port validation
        with pytest.raises(ValidationError):
            session_controller.execute_tool(
                "nmap",
                {"target": "example.com", "port": "99999"}  # Invalid port
            )
        
        # Test URL validation
        with pytest.raises(ValidationError):
            session_controller.execute_tool(
                "nikto",
                {"url": "not-a-url"}  # Invalid URL
            )
        
        # Test target validation
        with pytest.raises(ValidationError):
            session_controller.set_target("")  # Empty target
    
    @patch('src.alienrecon.tools.base.run_command')
    def test_error_handling_workflow(self, mock_run_command, session_controller):
        """Test error handling in tool execution."""
        # Mock command failure
        mock_run_command.return_value = (None, "Command failed: Host unreachable")
        
        session_controller.set_target("192.168.1.1")
        result = session_controller.execute_tool(
            "nmap",
            {"target": "192.168.1.1", "scan_type": "quick"}
        )
        
        assert result["success"] is False
        assert "error" in result
    
    def test_cache_functionality(self, session_controller):
        """Test result caching."""
        with patch('src.alienrecon.tools.base.run_command') as mock_run_command:
            mock_run_command.return_value = ("# Nmap results", None)
            
            session_controller.set_target("example.com")
            
            # First execution should call the command
            result1 = session_controller.execute_tool(
                "nmap",
                {"target": "example.com", "scan_type": "quick"}
            )
            
            # Second execution should use cache
            result2 = session_controller.execute_tool(
                "nmap", 
                {"target": "example.com", "scan_type": "quick"}
            )
            
            # Should only have called run_command once due to caching
            assert mock_run_command.call_count == 1
            assert result1 == result2