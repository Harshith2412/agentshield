"""Policy-aware execution of safe simulated tools."""

from agentshield.core.events import EventType
from agentshield.core.policies import PolicyAction
from agentshield.runtime.context import ExecutionMode, RunContext, TrustBoundary
from agentshield.runtime.instrumentation import RuntimeInstrumentation
from agentshield.runtime.tools import ToolRegistry, ToolRequest, ToolResult, ToolStatus


class InstrumentedExecutor:
    def __init__(self, tools: ToolRegistry, instrumentation: RuntimeInstrumentation) -> None:
        self.tools = tools
        self.instrumentation = instrumentation

    def execute(self, request: ToolRequest, parent_ids: tuple[str, ...]) -> tuple[ToolResult, str]:
        definition = self.tools.get(request.name)
        context: RunContext = self.instrumentation.context
        authorized = context.authorizes(definition.capability, request.arguments)
        event, decision = self.instrumentation.emit(
            EventType.TOOL_REQUEST,
            "deterministic_planner",
            content={"arguments": dict(request.arguments)},
            parent_ids=parent_ids,
            capability=definition.capability,
            metadata={"tool": request.name, "side_effect_level": definition.side_effect_level.value},
            authorized=authorized,
        )
        trace = self.instrumentation.trace
        trace.tools_requested.append(request)
        enforced = context.mode is ExecutionMode.PROTECTED
        response_parent_id = event.id
        if enforced and decision.action is not PolicyAction.ALLOW:
            status = {
                PolicyAction.BLOCK: ToolStatus.BLOCKED,
                PolicyAction.REVIEW: ToolStatus.REVIEW_REQUIRED,
                PolicyAction.SANITIZE: ToolStatus.SANITIZATION_REQUIRED,
            }[decision.action]
            result = ToolResult(request.name, status, f"execution withheld: {decision.action.value}", definition.side_effect_level)
            trace.tools_blocked.append(request)
        else:
            if authorized and not context.consume_authority(definition.capability, request.arguments):
                result = ToolResult(request.name, ToolStatus.BLOCKED, "authority expired or already consumed", definition.side_effect_level)
                trace.tools_blocked.append(request)
                response, _ = self.instrumentation.emit(
                    EventType.TOOL_RESPONSE, request.name,
                    content={"status": result.status.value, "output": result.output},
                    parent_ids=(event.id,), boundary=definition.output_boundary,
                    metadata={"tool": request.name},
                )
                trace.tool_results.append(result)
                return result, response.id
            result = self.tools.execute(request)
            trace.tools_executed.append(request)
            if definition.side_effect_level.value != "none" and result.status is ToolStatus.SUCCESS:
                action_event, _ = self.instrumentation.emit(
                    EventType.EXTERNAL_ACTION,
                    request.name,
                    content={"simulation": True, "status": result.status.value},
                    parent_ids=(event.id,),
                    boundary=TrustBoundary.TOOL,
                    capability=definition.capability,
                    metadata={"tool": request.name},
                    authorized=authorized,
                )
                response_parent_id = action_event.id
        response, _ = self.instrumentation.emit(
            EventType.TOOL_RESPONSE,
            request.name,
            content={"status": result.status.value, "output": result.output},
            parent_ids=(response_parent_id,),
            boundary=definition.output_boundary,
            metadata={"tool": request.name},
            authorized=authorized,
        )
        trace.tool_results.append(result)
        return result, response.id
