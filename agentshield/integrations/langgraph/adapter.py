"""Explicit LangGraph-to-AgentShield boundary and protected tool wrappers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from agentshield import AgentShield, EventType
from agentshield.core.policies import PolicyAction
from agentshield.integrations.langgraph.context import FrameworkSource, LangGraphStateBridge
from agentshield.integrations.langgraph.errors import LangGraphUnavailableError, StateBridgeError, ToolMappingError
from agentshield.integrations.langgraph.events import render_langgraph_trace
from agentshield.integrations.langgraph.tools import FrameworkToolOutcome, ToolSecurityMetadata
from agentshield.runtime.context import ExecutionMode, RunContext, TrustBoundary
from agentshield.runtime.executor import InstrumentedExecutor
from agentshield.runtime.instrumentation import RuntimeInstrumentation
from agentshield.runtime.tools import SideEffectLevel, ToolDefinition, ToolRegistry, ToolRequest, ToolStatus


@dataclass(frozen=True)
class ProtectedLangGraphTool:
    name: str
    adapter: "LangGraphAdapter"

    def invoke(self, arguments: Mapping[str, Any], state: Mapping[str, Any]) -> FrameworkToolOutcome:
        return self.adapter.invoke_tool(self.name, arguments, state)

    def __call__(self, **arguments: Any) -> FrameworkToolOutcome:
        raise StateBridgeError("protected framework tools require explicit graph state via invoke()")


class LangGraphAdapter:
    framework_name = "langgraph"
    def __init__(
        self,
        *,
        mode: ExecutionMode = ExecutionMode.PROTECTED,
        tools: ToolRegistry | None = None,
        bridge: LangGraphStateBridge | None = None,
    ) -> None:
        self.bridge = bridge or LangGraphStateBridge()
        self.tools = tools or ToolRegistry()
        self.context = RunContext(mode, authorization_grants=self.bridge.authorization_grants)
        self.instrumentation = RuntimeInstrumentation(AgentShield(), self.context)
        self.executor = InstrumentedExecutor(self.tools, self.instrumentation)
        self._metadata: dict[str, ToolSecurityMetadata] = {}
        self._ingested: set[str] = set()
        self._last_node_event_id: str | None = None
        self.graph_event, _ = self.instrumentation.emit(
            EventType.MODEL_OUTPUT, "langgraph", content={"mode": mode.value}, boundary=TrustBoundary.SYSTEM,
            metadata={"framework_event": "graph_invocation"},
        )

    @property
    def trace(self):
        return self.instrumentation.trace

    def register_tool(self, name: str, metadata: ToolSecurityMetadata) -> ProtectedLangGraphTool:
        try:
            definition = self.tools.get(name)
        except KeyError as exc:
            raise ToolMappingError(f"tool is not registered in runtime: {name}") from exc
        if definition.capability is not metadata.capability:
            raise ToolMappingError(f"capability mapping mismatch for {name}")
        self._metadata[name] = metadata
        return ProtectedLangGraphTool(name, self)

    create_protected_tool = register_tool

    def wrap_tool(
        self,
        name: str,
        handler: Callable[[Mapping[str, Any]], Any],
        metadata: ToolSecurityMetadata,
        *,
        side_effect_level: SideEffectLevel = SideEffectLevel.NONE,
    ) -> ProtectedLangGraphTool:
        self.tools.register(ToolDefinition(name, metadata.capability, side_effect_level, handler))
        return self.register_tool(name, metadata)

    def ingest_state(self, state: Mapping[str, Any]) -> LangGraphStateBridge:
        try:
            bridge = LangGraphStateBridge.from_state(state)
        except (ValueError, TypeError) as exc:
            raise StateBridgeError(str(exc)) from exc
        self.bridge = bridge
        self.context = RunContext(self.context.mode, authorization_grants=bridge.authorization_grants, run_id=self.context.run_id)
        self.instrumentation.context = self.context
        groups = (
            (EventType.USER_INPUT, (bridge.user_instruction,) if bridge.user_instruction else ()),
            (EventType.MODEL_OUTPUT, bridge.system_instructions),
            (EventType.RETRIEVAL, bridge.retrieved_sources),
            (EventType.MEMORY_READ, bridge.memories),
            (EventType.TOOL_RESPONSE, bridge.tool_outputs),
            (EventType.MODEL_OUTPUT, bridge.intermediate_messages),
        )
        for event_type, sources in groups:
            for source in sources:
                key = source.framework_id or f"{event_type.value}:{source.name}:{id(source)}"
                if key in self._ingested:
                    continue
                event, _ = self.instrumentation.emit(
                    event_type, source.name, content=source.content, parent_ids=(self.graph_event.id,),
                    boundary=source.boundary,
                    metadata={"framework_id": source.framework_id or "", "framework_event": "state_value"},
                )
                bridge.event_ids[key] = event.id
                self._ingested.add(key)
        return bridge

    map_context = ingest_state

    def instrument_node(self, name: str, function: Callable[[Mapping[str, Any]], Mapping[str, Any]]):
        def wrapped(state: Mapping[str, Any]) -> Mapping[str, Any]:
            bridge = self.ingest_state(state)
            material = bridge.material_parent_ids()
            parents = tuple(dict.fromkeys((*material, *((self._last_node_event_id,) if self._last_node_event_id else ())))) or (self.graph_event.id,)
            entry, _ = self.instrumentation.emit(
                EventType.MODEL_OUTPUT, f"langgraph.node.{name}", content={"phase": "entry"},
                parent_ids=parents, metadata={"framework_event": "node_entry", "node": name},
            )
            output = function(state)
            output_event, _ = self.instrumentation.emit(
                EventType.MODEL_OUTPUT, f"langgraph.node.{name}", content={"phase": "output"},
                parent_ids=(entry.id,), metadata={"framework_event": "node_output", "node": name},
            )
            self._last_node_event_id = output_event.id
            return output
        return wrapped

    def instrument_node_async(self, name: str, function):
        async def wrapped(state: Mapping[str, Any]) -> Mapping[str, Any]:
            bridge = self.ingest_state(state)
            material = bridge.material_parent_ids()
            parents = tuple(dict.fromkeys((*material, *((self._last_node_event_id,) if self._last_node_event_id else ())))) or (self.graph_event.id,)
            entry, _ = self.instrumentation.emit(
                EventType.MODEL_OUTPUT, f"langgraph.node.{name}", content={"phase": "entry"},
                parent_ids=parents, metadata={"framework_event": "node_entry", "node": name, "async": True},
            )
            output = await function(state)
            output_event, _ = self.instrumentation.emit(
                EventType.MODEL_OUTPUT, f"langgraph.node.{name}", content={"phase": "output"},
                parent_ids=(entry.id,), metadata={"framework_event": "node_output", "node": name, "async": True},
            )
            self._last_node_event_id = output_event.id
            return output
        return wrapped

    async def invoke_tool_async(self, name: str, arguments: Mapping[str, Any], state: Mapping[str, Any]):
        from agentshield.runtime.async_executor import AsyncInstrumentedExecutor
        if name not in self._metadata:
            raise ToolMappingError(f"no security mapping for tool: {name}")
        bridge = self.ingest_state(state)
        parents = ((self._last_node_event_id,) if self._last_node_event_id else bridge.material_parent_ids())
        if not parents:
            raise StateBridgeError("sensitive tool provenance could not be reconstructed")
        before = len(self.trace.events)
        result, response_id = await AsyncInstrumentedExecutor(self.tools, self.instrumentation).execute_async(ToolRequest(name, arguments), parents)
        request = next(event for event in self.trace.events[before:] if event.event_type is EventType.TOOL_REQUEST)
        decision = next(item for item in self.trace.decisions if item.event.id == request.id)
        return FrameworkToolOutcome(result, decision.action, result.status is ToolStatus.SUCCESS, request.id, response_id)

    def invoke_tool(self, name: str, arguments: Mapping[str, Any], state: Mapping[str, Any]) -> FrameworkToolOutcome:
        if name not in self._metadata:
            raise ToolMappingError(f"no security mapping for tool: {name}")
        if not isinstance(arguments, Mapping):
            raise ToolMappingError("tool arguments must be a mapping")
        bridge = self.ingest_state(state)
        parents = ((self._last_node_event_id,) if self._last_node_event_id else bridge.material_parent_ids())
        if not parents:
            raise StateBridgeError("sensitive tool provenance could not be reconstructed")
        before = len(self.trace.events)
        result, response_id = self.executor.execute(ToolRequest(name, arguments), parents)
        new_events = self.trace.events[before:]
        request = next((event for event in new_events if event.event_type is EventType.TOOL_REQUEST), None)
        if request is None:
            raise StateBridgeError("tool request event was not produced")
        decision = next(item for item in self.trace.decisions if item.event.id == request.id)
        return FrameworkToolOutcome(result, decision.action, result.status is ToolStatus.SUCCESS, request.id, response_id)

    invoke_protected = invoke_tool

    def normalized_trace(self):
        from agentshield.integrations.base.traces import FrameworkSecurityTrace
        return FrameworkSecurityTrace.from_execution(self.framework_name, self.trace)

    def compile_graph(self, builder: Callable[[Any, "LangGraphAdapter"], Any]):
        try:
            from langgraph.graph import StateGraph
        except ImportError as exc:
            raise LangGraphUnavailableError('LangGraph is optional; install AgentShield with ".[langgraph]"') from exc
        return builder(StateGraph, self)

    def render_trace(self) -> str:
        return render_langgraph_trace(self.trace)
