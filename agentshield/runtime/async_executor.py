"""Async protected tool execution with pre-await enforcement."""

import asyncio

from agentshield.core.events import EventType
from agentshield.core.policies import PolicyAction
from agentshield.runtime.context import ExecutionMode
from agentshield.runtime.instrumentation import RuntimeInstrumentation
from agentshield.runtime.tools import ToolRegistry, ToolRequest, ToolResult, ToolStatus


class AsyncInstrumentedExecutor:
    def __init__(self, tools: ToolRegistry, instrumentation: RuntimeInstrumentation) -> None:
        self.tools = tools
        self.instrumentation = instrumentation

    async def execute_async(self, request: ToolRequest, parent_ids: tuple[str, ...]) -> tuple[ToolResult, str]:
        definition = self.tools.get(request.name)
        context = self.instrumentation.context
        authorized = context.authorizes(definition.capability, request.arguments)
        event, decision = self.instrumentation.emit(
            EventType.TOOL_REQUEST, "async_planner", content={"arguments": dict(request.arguments)},
            parent_ids=parent_ids, capability=definition.capability,
            metadata={"tool": request.name, "async": True}, authorized=authorized,
        )
        trace = self.instrumentation.trace
        trace.tools_requested.append(request)
        if context.mode is ExecutionMode.PROTECTED and decision.action is not PolicyAction.ALLOW:
            result = ToolResult(request.name, ToolStatus.BLOCKED, f"execution withheld: {decision.action.value}", definition.side_effect_level)
            trace.tools_blocked.append(request)
        elif authorized and not context.consume_authority(definition.capability, request.arguments):
            result = ToolResult(request.name, ToolStatus.BLOCKED, "authority expired or already consumed", definition.side_effect_level)
            trace.tools_blocked.append(request)
        else:
            result = await self.tools.execute_async(request)
            trace.tools_executed.append(request)
        response, _ = self.instrumentation.emit(
            EventType.TOOL_RESPONSE, request.name,
            content={"status": result.status.value, "output": result.output},
            parent_ids=(event.id,), boundary=definition.output_boundary,
            metadata={"tool": request.name, "async": True}, authorized=authorized,
        )
        trace.tool_results.append(result)
        return result, response.id

    async def execute_many(
        self, requests: tuple[ToolRequest, ...], parent_ids: tuple[str, ...]
    ) -> tuple[tuple[ToolResult, str], ...]:
        return tuple(await asyncio.gather(*(self.execute_async(request, parent_ids) for request in requests)))
