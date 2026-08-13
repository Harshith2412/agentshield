"""Microsoft Agent Framework context bridge."""

from dataclasses import dataclass
from typing import Any, Mapping

from agentshield.integrations.base.context import FrameworkContext


@dataclass
class MicrosoftAgentContextBridge(FrameworkContext):
    agent_name: str = "agent"

    @classmethod
    def from_state(cls, state: Mapping[str, Any]) -> "MicrosoftAgentContextBridge":
        bridge = state.get("agentshield_bridge")
        if isinstance(bridge, cls):
            return bridge
        raise ValueError("state must contain a MicrosoftAgentContextBridge")
