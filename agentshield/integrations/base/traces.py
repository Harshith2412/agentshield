"""Normalized cross-framework security trace semantics."""

from dataclasses import dataclass
from enum import Enum

from agentshield.core.events import EventType
from agentshield.runtime.instrumentation import ExecutionTrace


class NormalizedEventType(str, Enum):
    USER_AUTHORITY = "user_authority"
    UNTRUSTED_SOURCE = "untrusted_source"
    MODEL_DECISION = "model_decision"
    PRIVILEGED_ACTION_REQUEST = "privileged_action_request"
    SECURITY_DECISION = "security_decision"
    ACTION_EXECUTION = "action_execution"
    PROVENANCE_LOSS = "provenance_loss"


@dataclass(frozen=True)
class NormalizedTraceEvent:
    kind: NormalizedEventType
    source_event_id: str
    detail: str


@dataclass(frozen=True)
class FrameworkSecurityTrace:
    framework: str
    run_id: str
    events: tuple[NormalizedTraceEvent, ...]

    @classmethod
    def from_execution(cls, framework: str, trace: ExecutionTrace) -> "FrameworkSecurityTrace":
        events: list[NormalizedTraceEvent] = []
        decisions = {item.event.id: item for item in trace.decisions}
        for event in trace.events:
            if event.event_type is EventType.USER_INPUT:
                events.append(NormalizedTraceEvent(NormalizedEventType.USER_AUTHORITY, event.id, event.source))
            if event.provenance.externally_influenced and event.event_type in {EventType.RETRIEVAL, EventType.MEMORY_READ, EventType.TOOL_RESPONSE}:
                events.append(NormalizedTraceEvent(NormalizedEventType.UNTRUSTED_SOURCE, event.id, event.source))
            if event.event_type is EventType.MODEL_OUTPUT and event.metadata.get("framework_event") in {"model_response", "agent_output", "node_output"}:
                events.append(NormalizedTraceEvent(NormalizedEventType.MODEL_DECISION, event.id, event.source))
            if event.event_type is EventType.TOOL_REQUEST:
                events.append(NormalizedTraceEvent(NormalizedEventType.PRIVILEGED_ACTION_REQUEST, event.id, event.capability.value if event.capability else "unknown"))
                decision = decisions[event.id]
                events.append(NormalizedTraceEvent(NormalizedEventType.SECURITY_DECISION, event.id, decision.action.value))
            if event.event_type is EventType.EXTERNAL_ACTION:
                events.append(NormalizedTraceEvent(NormalizedEventType.ACTION_EXECUTION, event.id, event.source))
            if event.metadata.get("framework_event") == "provenance_loss":
                events.append(NormalizedTraceEvent(NormalizedEventType.PROVENANCE_LOSS, event.id, event.source))
        return cls(framework, trace.run_id, tuple(events))
