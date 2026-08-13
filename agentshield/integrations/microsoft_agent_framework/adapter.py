"""Protected function and agent middleware for Microsoft Agent Framework."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Mapping

from agentshield import AgentShield, EventType
from agentshield.core.policies import PolicyAction
from agentshield.integrations.base.context import FrameworkContextItem
from agentshield.integrations.base.tools import ProtectedInvocationOutcome, ToolSecurityMetadata
from agentshield.integrations.microsoft_agent_framework.context import MicrosoftAgentContextBridge
from agentshield.integrations.microsoft_agent_framework.errors import MicrosoftAgentFrameworkError, MicrosoftAgentFrameworkUnavailableError
from agentshield.runtime import ExecutionMode, RunContext, TrustBoundary
from agentshield.runtime.executor import InstrumentedExecutor
from agentshield.runtime.instrumentation import RuntimeInstrumentation
from agentshield.runtime.tools import SideEffectLevel, ToolDefinition, ToolRegistry, ToolRequest, ToolResult, ToolStatus


@dataclass(frozen=True)
class ProtectedMicrosoftFunction:
    name: str
    adapter: "MicrosoftAgentFrameworkAdapter"

    def invoke(self, arguments: Mapping[str, Any], context: Mapping[str, Any]) -> ProtectedInvocationOutcome:
        return self.adapter.invoke_protected(self.name, arguments, context)


class MicrosoftAgentFrameworkAdapter:
    framework_name = "microsoft_agent_framework"

    def __init__(self, *, mode: ExecutionMode = ExecutionMode.PROTECTED, tools: ToolRegistry | None = None, bridge: MicrosoftAgentContextBridge | None = None) -> None:
        self.bridge = bridge or MicrosoftAgentContextBridge()
        self.tools = tools or ToolRegistry()
        self.context = RunContext(mode, authorization_grants=self.bridge.authorization_grants)
        self.instrumentation = RuntimeInstrumentation(AgentShield(), self.context)
        self.executor = InstrumentedExecutor(self.tools, self.instrumentation)
        self._metadata: dict[str, ToolSecurityMetadata] = {}
        self._ingested: set[str] = set()
        self._last_agent_event: str | None = None
        self.invocation, _ = self.instrumentation.emit(
            EventType.MODEL_OUTPUT, "microsoft_agent_framework", content={"agent": self.bridge.agent_name},
            boundary=TrustBoundary.SYSTEM, metadata={"framework_event": "agent_invocation", "agent": self.bridge.agent_name},
        )

    @property
    def trace(self):
        return self.instrumentation.trace

    def ensure_dependency(self) -> str:
        try:
            import agent_framework
            from importlib.metadata import version
            return version("agent-framework-core")
        except (ImportError, Exception) as exc:
            raise MicrosoftAgentFrameworkUnavailableError(
                'Microsoft Agent Framework is optional; install AgentShield with ".[microsoft-agent-framework]"'
            ) from exc

    def map_context(self, state: Mapping[str, Any]) -> MicrosoftAgentContextBridge:
        try:
            bridge = MicrosoftAgentContextBridge.from_state(state)
        except (ValueError, TypeError) as exc:
            raise MicrosoftAgentFrameworkError(str(exc)) from exc
        self.bridge = bridge
        self.context = RunContext(self.context.mode, authorization_grants=bridge.authorization_grants, run_id=self.context.run_id)
        self.instrumentation.context = self.context
        groups = (
            (EventType.USER_INPUT, (bridge.user_instruction,) if bridge.user_instruction else ()),
            (EventType.MODEL_OUTPUT, bridge.system_instructions),
            (EventType.RETRIEVAL, bridge.retrieved_sources),
            (EventType.MEMORY_READ, bridge.memories),
            (EventType.TOOL_RESPONSE, bridge.function_outputs),
            (EventType.MODEL_OUTPUT, bridge.model_outputs),
        )
        for event_type, items in groups:
            for item in items:
                key = item.framework_id or f"{event_type.value}:{item.name}:{id(item)}"
                if key in self._ingested:
                    continue
                event, _ = self.instrumentation.emit(
                    event_type, item.name, content=item.content, parent_ids=(self.invocation.id,), boundary=item.boundary,
                    metadata={"framework_id": item.framework_id or "", "framework_event": "context_value", "agent": item.agent_name or bridge.agent_name},
                )
                bridge.event_ids[key] = event.id
                self._ingested.add(key)
        return bridge

    def create_protected_tool(self, name: str, metadata: ToolSecurityMetadata) -> ProtectedMicrosoftFunction:
        try:
            definition = self.tools.get(name)
        except KeyError as exc:
            raise MicrosoftAgentFrameworkError(f"function not registered: {name}") from exc
        if definition.capability is not metadata.capability:
            raise MicrosoftAgentFrameworkError(f"capability mapping mismatch for {name}")
        self._metadata[name] = metadata
        return ProtectedMicrosoftFunction(name, self)

    def wrap_function(self, name: str, handler: Callable[[Mapping[str, Any]], Any], metadata: ToolSecurityMetadata, *, side_effect_level: SideEffectLevel = SideEffectLevel.NONE) -> ProtectedMicrosoftFunction:
        self.tools.register(ToolDefinition(name, metadata.capability, side_effect_level, handler))
        return self.create_protected_tool(name, metadata)

    def invoke_protected(self, name: str, arguments: Mapping[str, Any], state: Mapping[str, Any]) -> ProtectedInvocationOutcome:
        if name not in self._metadata:
            raise MicrosoftAgentFrameworkError(f"no security mapping for function: {name}")
        if not isinstance(arguments, Mapping):
            raise MicrosoftAgentFrameworkError("function arguments must be a mapping")
        bridge = self.map_context(state)
        parents = ((self._last_agent_event,) if self._last_agent_event else bridge.parent_ids())
        if not parents:
            loss, decision = self.instrumentation.emit(
                EventType.SECURITY_ALERT, "microsoft_agent_framework", content={"function": name},
                parent_ids=(self.invocation.id,), metadata={"framework_event": "provenance_loss"},
            )
            raise MicrosoftAgentFrameworkError(f"provenance unavailable; protected invocation failed closed: {loss.id}")
        before = len(self.trace.events)
        result, response_id = self.executor.execute(ToolRequest(name, arguments), parents)
        request = next(event for event in self.trace.events[before:] if event.event_type is EventType.TOOL_REQUEST)
        decision = next(item for item in self.trace.decisions if item.event.id == request.id)
        return ProtectedInvocationOutcome(result, decision.action, result.status is ToolStatus.SUCCESS, request.id, response_id)

    def instrument_agent(self, agent_name: str, function: Callable[[Mapping[str, Any]], Mapping[str, Any]]):
        def wrapped(state: Mapping[str, Any]) -> Mapping[str, Any]:
            bridge = self.map_context(state)
            parents = tuple(dict.fromkeys((*bridge.parent_ids(), *((self._last_agent_event,) if self._last_agent_event else ())))) or (self.invocation.id,)
            entry, _ = self.instrumentation.emit(
                EventType.MODEL_OUTPUT, f"agent.{agent_name}", content={"phase": "entry"}, parent_ids=parents,
                metadata={"framework_event": "agent_entry", "agent": agent_name},
            )
            output = function(state)
            output_event, _ = self.instrumentation.emit(
                EventType.MODEL_OUTPUT, f"agent.{agent_name}", content={"phase": "output"}, parent_ids=(entry.id,),
                metadata={"framework_event": "agent_output", "agent": agent_name},
            )
            self._last_agent_event = output_event.id
            return output
        return wrapped

    def instrument_agent_async(self, agent_name: str, function):
        async def wrapped(state: Mapping[str, Any]) -> Mapping[str, Any]:
            bridge = self.map_context(state)
            parents = tuple(dict.fromkeys((*bridge.parent_ids(), *((self._last_agent_event,) if self._last_agent_event else ())))) or (self.invocation.id,)
            entry, _ = self.instrumentation.emit(
                EventType.MODEL_OUTPUT, f"agent.{agent_name}", content={"phase": "entry"}, parent_ids=parents,
                metadata={"framework_event": "agent_entry", "agent": agent_name, "async": True},
            )
            output = await function(state)
            output_event, _ = self.instrumentation.emit(
                EventType.MODEL_OUTPUT, f"agent.{agent_name}", content={"phase": "output"}, parent_ids=(entry.id,),
                metadata={"framework_event": "agent_output", "agent": agent_name, "async": True},
            )
            self._last_agent_event = output_event.id
            return output
        return wrapped

    async def invoke_protected_async(self, name: str, arguments: Mapping[str, Any], state: Mapping[str, Any]):
        from agentshield.runtime.async_executor import AsyncInstrumentedExecutor
        if name not in self._metadata:
            raise MicrosoftAgentFrameworkError(f"no security mapping for function: {name}")
        bridge = self.map_context(state)
        parents = ((self._last_agent_event,) if self._last_agent_event else bridge.parent_ids())
        if not parents:
            self.instrumentation.emit(
                EventType.SECURITY_ALERT, "microsoft_agent_framework", parent_ids=(self.invocation.id,),
                metadata={"framework_event": "provenance_loss", "async": True},
            )
            raise MicrosoftAgentFrameworkError("provenance unavailable; async invocation failed closed")
        before = len(self.trace.events)
        result, response_id = await AsyncInstrumentedExecutor(self.tools, self.instrumentation).execute_async(ToolRequest(name, arguments), parents)
        request = next(event for event in self.trace.events[before:] if event.event_type is EventType.TOOL_REQUEST)
        decision = next(item for item in self.trace.decisions if item.event.id == request.id)
        return ProtectedInvocationOutcome(result, decision.action, result.status is ToolStatus.SUCCESS, request.id, response_id)

    def function_middleware(self):
        """Official callback-shaped function middleware: context, next callback."""
        async def middleware(context: Any, call_next: Callable[[Any], Awaitable[Any]]):
            function = getattr(context, "function", None)
            name = (
                getattr(context, "function_name", None)
                or getattr(context, "name", None)
                or getattr(function, "name", None)
            )
            arguments = getattr(context, "arguments", None)
            state = getattr(context, "state", None)
            metadata = getattr(context, "metadata", None)
            if state is None and isinstance(metadata, Mapping):
                state = metadata.get("agentshield_state")
            if not isinstance(name, str) or not isinstance(arguments, Mapping) or not isinstance(state, Mapping):
                raise MicrosoftAgentFrameworkError("middleware context lacks function name, arguments, or AgentShield state")
            if name not in self._metadata:
                raise MicrosoftAgentFrameworkError(f"no security mapping for function: {name}")
            bridge = self.map_context(state)
            parents = ((self._last_agent_event,) if self._last_agent_event else bridge.parent_ids())
            if not parents:
                self.instrumentation.emit(
                    EventType.SECURITY_ALERT, "microsoft_agent_framework", parent_ids=(self.invocation.id,),
                    metadata={"framework_event": "provenance_loss", "function": name},
                )
                raise MicrosoftAgentFrameworkError("provenance unavailable; middleware failed closed")
            definition = self.tools.get(name)
            authorized = self.context.authorizes(definition.capability, arguments)
            request, decision = self.instrumentation.emit(
                EventType.TOOL_REQUEST, "microsoft.function_middleware", content={"arguments": dict(arguments)},
                parent_ids=parents, capability=definition.capability,
                metadata={"tool": name, "framework_event": "function_request"}, authorized=authorized,
            )
            tool_request = ToolRequest(name, arguments)
            self.trace.tools_requested.append(tool_request)
            if self.context.mode is ExecutionMode.PROTECTED and decision.action is not PolicyAction.ALLOW:
                result = ToolResult(name, ToolStatus.BLOCKED, f"execution withheld: {decision.action.value}", definition.side_effect_level)
                self.trace.tools_blocked.append(tool_request)
                response, _ = self.instrumentation.emit(
                    EventType.TOOL_RESPONSE, name, content={"status": result.status.value}, parent_ids=(request.id,),
                    metadata={"tool": name, "framework_event": "function_response"},
                )
                self.trace.tool_results.append(result)
                return ProtectedInvocationOutcome(result, decision.action, False, request.id, response.id)
            framework_result = await call_next(context)
            result = ToolResult(name, ToolStatus.SUCCESS, {"framework_result": str(framework_result)}, definition.side_effect_level)
            self.trace.tools_executed.append(tool_request)
            response, _ = self.instrumentation.emit(
                EventType.TOOL_RESPONSE, name, content={"status": result.status.value}, parent_ids=(request.id,),
                metadata={"tool": name, "framework_event": "function_response"}, authorized=authorized,
            )
            self.trace.tool_results.append(result)
            return framework_result
        return middleware

    def agent_middleware(self):
        async def middleware(context: Any, call_next: Callable[[Any], Awaitable[Any]]):
            state = getattr(context, "state", None)
            metadata = getattr(context, "metadata", None)
            if state is None and isinstance(metadata, Mapping):
                state = metadata.get("agentshield_state")
            if not isinstance(state, Mapping):
                raise MicrosoftAgentFrameworkError("agent middleware context lacks AgentShield state")
            self.map_context(state)
            return await call_next(context)
        return middleware

    def normalized_trace(self):
        from agentshield.integrations.base.traces import FrameworkSecurityTrace
        return FrameworkSecurityTrace.from_execution(self.framework_name, self.trace)

    def render_trace(self) -> str:
        decisions = {item.event.id: item for item in self.trace.decisions}
        lines = ["AgentShield Microsoft Agent Framework Trace", "===========================================", f"Run: {self.trace.run_id}", ""]
        for index, event in enumerate(self.trace.events, 1):
            lines.extend([f"[{index}] {event.event_type.name}", f"    source: {event.source}", f"    trust: {event.provenance.trust_level.name}"])
            if event.metadata.get("agent"):
                lines.append(f"    agent: {event.metadata['agent']}")
            if event.capability:
                lines.append(f"    capability: {event.capability.name}")
            if event.id in decisions:
                lines.append(f"    decision: {decisions[event.id].action.name}")
            lines.append("")
        lines.append(f"Functions executed: {len(self.trace.tools_executed)}")
        return "\n".join(lines)
