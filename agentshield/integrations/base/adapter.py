"""Minimal framework adapter protocol shared by independent ecosystems."""

from typing import Any, Mapping, Protocol

from agentshield.integrations.base.context import FrameworkContext
from agentshield.integrations.base.tools import ProtectedInvocationOutcome, ToolSecurityMetadata


class FrameworkAdapter(Protocol):
    framework_name: str

    def map_context(self, state: Mapping[str, Any]) -> FrameworkContext: ...
    def create_protected_tool(self, name: str, metadata: ToolSecurityMetadata): ...
    def invoke_protected(self, name: str, arguments: Mapping[str, Any], state: Mapping[str, Any]) -> ProtectedInvocationOutcome: ...
    def render_trace(self) -> str: ...
