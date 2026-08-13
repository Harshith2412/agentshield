"""Optional explicit LangGraph integration."""

from agentshield.integrations.langgraph.adapter import LangGraphAdapter, ProtectedLangGraphTool
from agentshield.integrations.langgraph.context import FrameworkSource, LangGraphStateBridge
from agentshield.integrations.langgraph.errors import LangGraphIntegrationError, LangGraphUnavailableError, StateBridgeError, ToolMappingError
from agentshield.integrations.langgraph.events import render_langgraph_trace
from agentshield.integrations.langgraph.tools import FrameworkToolOutcome, ToolSecurityMetadata
from agentshield.integrations.langgraph.experiments import (
    LangGraphBenchmark, LangGraphExperimentResult, run_indirect_injection, run_langgraph_benchmark,
    run_multinode, run_scope_scenario,
)

__all__ = [
    "FrameworkSource", "FrameworkToolOutcome", "LangGraphAdapter", "LangGraphIntegrationError",
    "LangGraphStateBridge", "LangGraphUnavailableError", "ProtectedLangGraphTool",
    "StateBridgeError", "ToolMappingError", "ToolSecurityMetadata", "render_langgraph_trace",
    "LangGraphBenchmark", "LangGraphExperimentResult", "run_indirect_injection",
    "run_langgraph_benchmark", "run_multinode", "run_scope_scenario",
]
