"""Typed records for activity inside an agent runtime."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping
from uuid import uuid4

from agentshield.core.capabilities import Capability
from agentshield.core.provenance import ProvenanceRecord


class EventType(str, Enum):
    USER_INPUT = "user_input"
    RETRIEVAL = "retrieval"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    TOOL_REQUEST = "tool_request"
    TOOL_RESPONSE = "tool_response"
    MODEL_OUTPUT = "model_output"
    EXTERNAL_ACTION = "external_action"
    SECURITY_ALERT = "security_alert"
    MODEL_STREAM_START = "model_stream_start"
    MODEL_STREAM_CHUNK = "model_stream_chunk"
    MODEL_STREAM_END = "model_stream_end"
    MODEL_STREAM_CANCELLED = "model_stream_cancelled"
    PERSISTENCE_INTEGRITY_FAILURE = "persistence_integrity_failure"
    WORKFLOW_CHECKPOINT = "workflow_checkpoint"


@dataclass(frozen=True)
class SecurityEvent:
    event_type: EventType
    source: str
    content: str | Mapping[str, Any] | None = None
    parent_ids: tuple[str, ...] = ()
    provenance: ProvenanceRecord = field(default_factory=ProvenanceRecord)
    capability: Capability | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.source.strip():
            raise ValueError("event source must not be empty")
        if self.timestamp.tzinfo is None:
            raise ValueError("event timestamp must be timezone-aware")
        object.__setattr__(self, "parent_ids", tuple(self.parent_ids))
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))
        if isinstance(self.content, Mapping):
            object.__setattr__(self, "content", MappingProxyType(dict(self.content)))
