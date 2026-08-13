"""Shared protected invocation security records."""

from dataclasses import dataclass

from agentshield.core.capabilities import Capability
from agentshield.core.policies import PolicyAction
from agentshield.runtime.tools import ToolResult


@dataclass(frozen=True)
class ToolSecurityMetadata:
    capability: Capability
    side_effect: bool
    authorization_required: bool = True


@dataclass(frozen=True)
class ProtectedInvocationOutcome:
    result: ToolResult
    decision: PolicyAction
    executed: bool
    request_event_id: str
    response_event_id: str
