"""Framework-neutral integration contracts."""

from agentshield.integrations.base.adapter import FrameworkAdapter
from agentshield.integrations.base.conformance import AdapterConformanceResult, SecurityInvariantResult, run_adapter_conformance
from agentshield.integrations.base.context import FrameworkContext, FrameworkContextItem
from agentshield.integrations.base.errors import ContextMappingError, FrameworkIntegrationError, FrameworkUnavailableError, ProtectedInvocationError
from agentshield.integrations.base.tools import ProtectedInvocationOutcome, ToolSecurityMetadata
from agentshield.integrations.base.traces import FrameworkSecurityTrace, NormalizedEventType, NormalizedTraceEvent

__all__ = [
    "AdapterConformanceResult", "ContextMappingError", "FrameworkAdapter", "FrameworkContext",
    "FrameworkContextItem", "FrameworkIntegrationError", "FrameworkSecurityTrace",
    "FrameworkUnavailableError", "NormalizedEventType", "NormalizedTraceEvent",
    "ProtectedInvocationError", "ProtectedInvocationOutcome", "SecurityInvariantResult",
    "ToolSecurityMetadata", "run_adapter_conformance",
]
