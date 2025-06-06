# src/alienrecon/core/plan_executor.py
"""Plan execution and management for multi-step workflows."""

import logging
from datetime import datetime
from typing import Any, Optional

from .exceptions import PlanExecutionError
from .tool_orchestrator import ToolOrchestrator

logger = logging.getLogger(__name__)


class PlanExecutor:
    """Manages execution of multi-step reconnaissance plans."""

    def __init__(self, tool_orchestrator: ToolOrchestrator):
        self.tool_orchestrator = tool_orchestrator
        self.current_plan: Optional[dict[str, Any]] = None
        self.plan_history: list[dict[str, Any]] = []
        self.execution_results: dict[str, Any] = {}

    def create_plan(
        self,
        name: str,
        description: str,
        steps: list[dict[str, Any]],
        auto_execute: bool = False
    ) -> dict[str, Any]:
        """Create a new reconnaissance plan."""
        plan = {
            "id": f"plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "name": name,
            "description": description,
            "steps": steps,
            "auto_execute": auto_execute,
            "status": "pending",
            "created_at": datetime.now().isoformat(),
            "current_step": 0,
            "results": {},
        }

        # Validate plan steps
        self._validate_plan(plan)

        self.current_plan = plan
        logger.info(f"Created plan: {name} with {len(steps)} steps")

        return plan

    def _validate_plan(self, plan: dict[str, Any]) -> None:
        """Validate plan structure and steps."""
        if not plan.get("steps"):
            raise PlanExecutionError("Plan must have at least one step")

        for i, step in enumerate(plan["steps"]):
            if "tool" not in step:
                raise PlanExecutionError(f"Step {i} missing 'tool' field")

            if "args" not in step:
                raise PlanExecutionError(f"Step {i} missing 'args' field")

            # Check if tool exists
            if not self.tool_orchestrator.get_tool(step["tool"]):
                raise PlanExecutionError(f"Unknown tool in step {i}: {step['tool']}")

    def execute_next_step(self) -> Optional[dict[str, Any]]:
        """Execute the next step in the current plan."""
        if not self.current_plan:
            raise PlanExecutionError("No active plan")

        if self.current_plan["status"] == "completed":
            logger.info("Plan already completed")
            return None

        current_step_idx = self.current_plan["current_step"]
        steps = self.current_plan["steps"]

        if current_step_idx >= len(steps):
            self._complete_plan()
            return None

        step = steps[current_step_idx]

        # Check if step conditions are met
        if not self._check_step_conditions(step):
            logger.info(f"Step {current_step_idx} conditions not met, skipping")
            self.current_plan["current_step"] += 1
            return self.execute_next_step()

        # Execute the step
        try:
            logger.info(f"Executing step {current_step_idx}: {step.get('name', step['tool'])}")

            # Process dynamic arguments
            processed_args = self._process_dynamic_args(step["args"])

            # Execute tool
            result = self.tool_orchestrator.execute_tool(
                step["tool"],
                processed_args,
                use_cache=step.get("use_cache", True)
            )

            # Store result
            step_key = f"step_{current_step_idx}"
            self.current_plan["results"][step_key] = result
            self.execution_results[step_key] = result

            # Update plan status
            self.current_plan["current_step"] += 1
            self.current_plan["last_executed"] = datetime.now().isoformat()

            # Check if this was the last step
            if self.current_plan["current_step"] >= len(steps):
                self._complete_plan()

            return result

        except Exception as e:
            logger.error(f"Error executing step {current_step_idx}: {e}")
            self.current_plan["status"] = "failed"
            self.current_plan["error"] = str(e)
            raise PlanExecutionError(f"Step execution failed: {e}")

    def _check_step_conditions(self, step: dict[str, Any]) -> bool:
        """Check if step conditions are met."""
        conditions = step.get("conditions", {})

        if not conditions:
            return True

        # Check 'if_previous_success' condition
        if "if_previous_success" in conditions:
            if self.current_plan["current_step"] == 0:
                return True  # No previous step

            prev_key = f"step_{self.current_plan['current_step'] - 1}"
            prev_result = self.current_plan["results"].get(prev_key, {})
            if not prev_result.get("success", False):
                return False

        # Check 'if_port_open' condition
        if "if_port_open" in conditions:
            required_port = conditions["if_port_open"]
            # This would check session state for open ports
            # For now, we'll assume the condition check is handled elsewhere
            logger.debug(f"Port condition check for port {required_port}")

        # Check custom conditions
        if "custom" in conditions:
            # Custom condition evaluation would go here
            logger.debug(f"Custom condition: {conditions['custom']}")

        return True

    def _process_dynamic_args(self, args: dict[str, Any]) -> dict[str, Any]:
        """Process dynamic arguments that reference previous results."""
        processed = {}

        for key, value in args.items():
            if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
                # Dynamic reference to previous result
                ref = value[2:-1]  # Remove ${ and }
                parts = ref.split(".")

                if parts[0] in self.execution_results:
                    result = self.execution_results[parts[0]]
                    # Navigate through nested structure
                    for part in parts[1:]:
                        if isinstance(result, dict):
                            result = result.get(part)
                        else:
                            break
                    processed[key] = result if result is not None else value
                else:
                    processed[key] = value
            else:
                processed[key] = value

        return processed

    def _complete_plan(self) -> None:
        """Mark the current plan as completed."""
        self.current_plan["status"] = "completed"
        self.current_plan["completed_at"] = datetime.now().isoformat()

        # Add to history
        self.plan_history.append(self.current_plan)

        logger.info(f"Plan '{self.current_plan['name']}' completed successfully")

    def cancel_plan(self) -> None:
        """Cancel the current plan."""
        if self.current_plan and self.current_plan["status"] == "pending":
            self.current_plan["status"] = "cancelled"
            self.current_plan["cancelled_at"] = datetime.now().isoformat()
            self.plan_history.append(self.current_plan)
            logger.info(f"Plan '{self.current_plan['name']}' cancelled")

    def get_plan_status(self) -> Optional[dict[str, Any]]:
        """Get the status of the current plan."""
        if not self.current_plan:
            return None

        total_steps = len(self.current_plan["steps"])
        completed_steps = self.current_plan["current_step"]

        return {
            "id": self.current_plan["id"],
            "name": self.current_plan["name"],
            "status": self.current_plan["status"],
            "progress": f"{completed_steps}/{total_steps}",
            "current_step": completed_steps,
            "total_steps": total_steps,
        }

    def get_plan_results(self) -> dict[str, Any]:
        """Get all results from the current plan execution."""
        if not self.current_plan:
            return {}

        return self.current_plan.get("results", {})

    def get_plan_history(self) -> list[dict[str, Any]]:
        """Get the history of executed plans."""
        return [
            {
                "id": plan["id"],
                "name": plan["name"],
                "status": plan["status"],
                "created_at": plan["created_at"],
                "steps_count": len(plan["steps"]),
            }
            for plan in self.plan_history
        ]
