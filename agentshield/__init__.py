"""Stable public API for AgentShield v0.1.

Framework adapters and persistence are intentionally imported from their own
namespaces because those APIs remain experimental in the initial release.
"""

from agentshield._version import __version__

from agentshield.core import (
    AgentShield,
    Capability,
    EventType,
    PolicyAction,
    ProvenanceRecord,
    SecurityDecision,
    SecurityEvent,
    TrustLevel,
)

__all__ = [
    "AgentShield", "Capability", "EventType", "PolicyAction", "ProvenanceRecord",
    "SecurityDecision", "SecurityEvent", "TrustLevel", "__version__",
]
