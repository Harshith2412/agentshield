"""Optional Microsoft Agent Framework security adapter."""

from agentshield.integrations.microsoft_agent_framework.adapter import MicrosoftAgentFrameworkAdapter, ProtectedMicrosoftFunction
from agentshield.integrations.microsoft_agent_framework.context import MicrosoftAgentContextBridge
from agentshield.integrations.microsoft_agent_framework.errors import MicrosoftAgentFrameworkError, MicrosoftAgentFrameworkUnavailableError
from agentshield.integrations.microsoft_agent_framework.experiments import (
    MicrosoftExperimentResult, run_indirect_injection, run_multi_agent, run_provenance_loss, run_scope_scenario,
)

__all__ = [
    "MicrosoftAgentContextBridge", "MicrosoftAgentFrameworkAdapter", "MicrosoftAgentFrameworkError",
    "MicrosoftAgentFrameworkUnavailableError", "ProtectedMicrosoftFunction",
    "MicrosoftExperimentResult", "run_indirect_injection", "run_multi_agent", "run_provenance_loss", "run_scope_scenario",
]
