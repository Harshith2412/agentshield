"""Shared structured context concepts used by framework adapters."""

from dataclasses import dataclass, field
from typing import Any, Mapping

from agentshield.runtime.context import AuthorizationGrant, TrustBoundary


@dataclass(frozen=True)
class FrameworkContextItem:
    name: str
    content: str | Mapping[str, Any]
    boundary: TrustBoundary
    framework_id: str | None = None
    agent_name: str | None = None


@dataclass
class FrameworkContext:
    user_instruction: FrameworkContextItem | None = None
    system_instructions: list[FrameworkContextItem] = field(default_factory=list)
    retrieved_sources: list[FrameworkContextItem] = field(default_factory=list)
    memories: list[FrameworkContextItem] = field(default_factory=list)
    function_outputs: list[FrameworkContextItem] = field(default_factory=list)
    model_outputs: list[FrameworkContextItem] = field(default_factory=list)
    authorization_grants: tuple[AuthorizationGrant, ...] = ()
    event_ids: dict[str, str] = field(default_factory=dict)

    def parent_ids(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(self.event_ids.values()))
