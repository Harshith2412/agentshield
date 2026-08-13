"""Structured bridge between framework state and AgentShield events."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from agentshield.runtime.context import AuthorizationGrant, TrustBoundary


@dataclass(frozen=True)
class FrameworkSource:
    name: str
    content: str | Mapping[str, Any]
    boundary: TrustBoundary
    framework_id: str | None = None


@dataclass
class LangGraphStateBridge:
    user_instruction: FrameworkSource | None = None
    system_instructions: list[FrameworkSource] = field(default_factory=list)
    retrieved_sources: list[FrameworkSource] = field(default_factory=list)
    memories: list[FrameworkSource] = field(default_factory=list)
    tool_outputs: list[FrameworkSource] = field(default_factory=list)
    intermediate_messages: list[FrameworkSource] = field(default_factory=list)
    authorization_grants: tuple[AuthorizationGrant, ...] = ()
    event_ids: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_state(cls, state: Mapping[str, Any]) -> "LangGraphStateBridge":
        bridge = state.get("agentshield_bridge")
        if isinstance(bridge, cls):
            return bridge
        raise ValueError("state must contain an AgentShield LangGraphStateBridge")

    def material_parent_ids(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(self.event_ids.values()))
