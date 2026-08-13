"""Explicit framework tool security metadata and invocation results."""

from agentshield.integrations.base.tools import ProtectedInvocationOutcome, ToolSecurityMetadata

FrameworkToolOutcome = ProtectedInvocationOutcome

__all__ = ["FrameworkToolOutcome", "ToolSecurityMetadata"]
