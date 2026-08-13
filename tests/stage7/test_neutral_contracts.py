from typing import runtime_checkable

import pytest

from agentshield import Capability
from agentshield.integrations.base import (
    FrameworkContext, FrameworkContextItem, FrameworkSecurityTrace, NormalizedEventType,
    ToolSecurityMetadata, run_adapter_conformance,
)
from agentshield.integrations.comparison import conformance_for
from agentshield.integrations.langgraph import LangGraphAdapter
from agentshield.integrations.microsoft_agent_framework import MicrosoftAgentFrameworkAdapter
from agentshield.runtime import TrustBoundary


def test_neutral_context_keeps_distinct_categories() -> None:
    context = FrameworkContext(
        user_instruction=FrameworkContextItem("user", "x", TrustBoundary.USER, "u"),
        retrieved_sources=[FrameworkContextItem("doc", "x", TrustBoundary.LOCAL_UNTRUSTED, "d")],
        memories=[FrameworkContextItem("memory", "x", TrustBoundary.MEMORY, "m")],
    )
    assert context.user_instruction.name == "user"
    assert context.retrieved_sources[0].boundary is TrustBoundary.LOCAL_UNTRUSTED
    assert context.memories[0].name == "memory"


def test_neutral_parent_ids_are_deduplicated() -> None:
    context = FrameworkContext(event_ids={"one": "same", "two": "same", "three": "other"})
    assert context.parent_ids() == ("same", "other")


def test_shared_tool_metadata_works_for_both_adapters() -> None:
    metadata = ToolSecurityMetadata(Capability.EMAIL_SEND, True)
    assert LangGraphAdapter().create_protected_tool("send_email", metadata)
    assert MicrosoftAgentFrameworkAdapter().create_protected_tool("send_email", metadata)


@pytest.mark.parametrize("framework", ["langgraph", "microsoft_agent_framework"])
def test_each_adapter_exposes_framework_name(framework: str) -> None:
    adapter = LangGraphAdapter() if framework == "langgraph" else MicrosoftAgentFrameworkAdapter()
    assert adapter.framework_name == framework


@pytest.mark.parametrize("framework", ["langgraph", "microsoft_agent_framework"])
def test_each_adapter_produces_normalized_trace(framework: str) -> None:
    adapter = LangGraphAdapter() if framework == "langgraph" else MicrosoftAgentFrameworkAdapter()
    normalized = adapter.normalized_trace()
    assert isinstance(normalized, FrameworkSecurityTrace)
    assert normalized.framework == framework


def test_unknown_conformance_framework_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported"):
        conformance_for("unknown")


def test_normalized_event_types_cover_security_boundary() -> None:
    assert {item.value for item in NormalizedEventType} == {
        "user_authority", "untrusted_source", "model_decision", "privileged_action_request",
        "security_decision", "action_execution", "provenance_loss",
    }
