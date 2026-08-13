"""Event emission and structured execution traces."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Mapping
from uuid import uuid4

from agentshield.core.capabilities import Capability
from agentshield.core.engine import AgentShield, SecurityDecision
from agentshield.core.events import EventType, SecurityEvent
from agentshield.core.provenance import ProvenanceRecord
from agentshield.runtime.context import ExecutionMode, RunContext, TrustBoundary
from agentshield.runtime.influence import InfluenceKind, InfluenceRecord
from agentshield.runtime.tools import ToolRequest, ToolResult, ToolStatus


@dataclass
class ExecutionTrace:
    run_id: str
    mode: ExecutionMode
    events: list[SecurityEvent] = field(default_factory=list)
    decisions: list[SecurityDecision] = field(default_factory=list)
    tools_requested: list[ToolRequest] = field(default_factory=list)
    tools_executed: list[ToolRequest] = field(default_factory=list)
    tools_blocked: list[ToolRequest] = field(default_factory=list)
    tool_results: list[ToolResult] = field(default_factory=list)
    influences: dict[str, tuple[InfluenceRecord, ...]] = field(default_factory=dict)
    final_result: str = ""

    def influence_set(self, event_id: str) -> tuple[InfluenceRecord, ...]:
        if event_id not in {event.id for event in self.events}:
            raise KeyError(f"event not present in trace: {event_id}")
        return self.influences.get(event_id, ())

    def propagation_chain(self, event_id: str) -> tuple[SecurityEvent, ...]:
        """Reconstruct a causal chain using the events retained by this run."""
        events = {event.id: event for event in self.events}
        if event_id not in events:
            raise KeyError(f"event not present in trace: {event_id}")
        ordered: list[SecurityEvent] = []
        visited: set[str] = set()

        def visit(current_id: str) -> None:
            if current_id in visited:
                return
            event = events[current_id]
            for parent_id in event.parent_ids:
                visit(parent_id)
            visited.add(current_id)
            ordered.append(event)

        visit(event_id)
        return tuple(ordered)

    def render(self) -> str:
        lines = ["AgentShield Execution Trace", "===========================", f"run: {self.run_id}", f"mode: {self.mode.name}", ""]
        decisions = {decision.event.id: decision for decision in self.decisions}
        for index, event in enumerate(self.events, 1):
            lines.extend([
                f"[{index}] {event.event_type.name}",
                f"    source: {event.source}",
                f"    trust: {event.provenance.trust_level.name}",
            ])
            if event.capability:
                lines.append(f"    capability: {event.capability.name}")
            if event.metadata.get("tool"):
                lines.append(f"    tool: {event.metadata['tool']}")
            decision = decisions.get(event.id)
            if decision:
                lines.extend([
                    f"    decision: {decision.action.name}",
                    f"    risk: {decision.risk.severity.name} ({decision.risk.score:.3f})",
                ])
            lines.append("")
        lines.append(f"final: {self.final_result}")
        return "\n".join(lines)


class RuntimeInstrumentation:
    def __init__(self, shield: AgentShield, context: RunContext) -> None:
        self.shield = shield
        self.context = context
        self.trace = ExecutionTrace(context.run_id, context.mode)

    def emit(
        self,
        event_type: EventType,
        source: str,
        *,
        content: str | Mapping[str, Any] | None = None,
        parent_ids: tuple[str, ...] = (),
        boundary: TrustBoundary | None = None,
        capability: Capability | None = None,
        metadata: Mapping[str, Any] | None = None,
        authorized: bool = False,
    ) -> tuple[SecurityEvent, SecurityDecision]:
        event_id = str(uuid4())
        if parent_ids:
            provenance = self.shield.provenance.build_provenance(parent_ids)
        else:
            provenance = ProvenanceRecord(original_source=source)
        if boundary is not None:
            provenance = replace(
                provenance,
                original_source=source if not parent_ids or boundary.is_external_or_untrusted else provenance.original_source,
                trust_level=boundary.trust_level if not parent_ids or boundary.is_external_or_untrusted else provenance.trust_level,
                source_event_id=event_id if not parent_ids or boundary.is_external_or_untrusted else provenance.source_event_id,
                externally_influenced=provenance.externally_influenced or boundary.is_external_or_untrusted,
            )
        event = SecurityEvent(
            event_type,
            source,
            content=content,
            parent_ids=parent_ids,
            provenance=provenance,
            capability=capability,
            metadata=metadata or {},
            id=event_id,
        )
        decision = self.shield.evaluate(event, explicit_authorization=authorized)
        self.trace.events.append(decision.event)
        self.trace.decisions.append(decision)
        inherited: list[InfluenceRecord] = []
        for parent_id in parent_ids:
            for record in self.trace.influences.get(parent_id, ()):
                if record not in inherited:
                    inherited.append(record)
        introduces_source = not parent_ids or (boundary is not None and boundary.is_external_or_untrusted)
        if introduces_source and boundary is not None:
            capabilities = tuple(sorted(
                set(self.context.authorized_capabilities)
                | {grant.capability for grant in self.context.authorization_grants},
                key=lambda item: item.value,
            )) if boundary is TrustBoundary.USER else ()
            kind = (
                InfluenceKind.AUTHORIZATION_BEARING
                if capabilities
                else InfluenceKind.UNTRUSTED
                if boundary.is_external_or_untrusted
                else InfluenceKind.TRUSTED
            )
            inherited.append(InfluenceRecord(event_id, source, boundary.trust_level, kind, capabilities))
        self.trace.influences[event_id] = tuple(inherited)
        return decision.event, decision
