from agentshield import EventType
from agentshield.integrations.base import NormalizedEventType
from agentshield.integrations.microsoft_agent_framework import (
    run_indirect_injection, run_multi_agent, run_provenance_loss, run_scope_scenario,
)
from agentshield.runtime import ExecutionMode


def test_indirect_attack_executes_unprotected() -> None:
    assert run_indirect_injection(ExecutionMode.UNPROTECTED).executed


def test_indirect_attack_blocked_protected() -> None:
    result = run_indirect_injection(ExecutionMode.PROTECTED)
    assert result.blocked and not result.executed


def test_indirect_attack_attribution_names_document() -> None:
    assert run_indirect_injection(ExecutionMode.PROTECTED).attribution.source_name == "quarterly_notes.txt"


def test_scope_exact_recipient_allowed() -> None:
    assert run_scope_scenario("demo@example.test").executed


def test_scope_modified_recipient_blocked() -> None:
    assert run_scope_scenario("other@example.test").blocked


def test_multi_agent_chain_preserves_untrusted_origin() -> None:
    result = run_multi_agent()
    assert result.attribution.source_name == "quarterly_notes.txt"
    assert result.blocked


def test_multi_agent_chain_contains_all_agents() -> None:
    result = run_multi_agent()
    agents = {event.metadata.get("agent") for event in result.adapter.trace.events}
    assert {"research_agent", "summarizer_agent", "action_agent"}.issubset(agents)


def test_agent_to_agent_output_does_not_reset_trust() -> None:
    result = run_multi_agent()
    request = next(event for event in result.adapter.trace.events if event.event_type is EventType.TOOL_REQUEST)
    assert request.provenance.externally_influenced


def test_provenance_loss_emits_normalized_event() -> None:
    adapter = run_provenance_loss()
    normalized = adapter.normalized_trace()
    assert any(event.kind is NormalizedEventType.PROVENANCE_LOSS for event in normalized.events)


def test_provenance_loss_executes_no_function() -> None:
    assert not run_provenance_loss().trace.tools_executed


def test_microsoft_specific_trace_is_readable() -> None:
    rendered = run_multi_agent().adapter.render_trace()
    assert "AgentShield Microsoft Agent Framework Trace" in rendered
    assert "agent: action_agent" in rendered
    assert "decision: BLOCK" in rendered


def test_normalized_trace_contains_request_and_decision() -> None:
    events = run_multi_agent().adapter.normalized_trace().events
    kinds = {event.kind for event in events}
    assert NormalizedEventType.PRIVILEGED_ACTION_REQUEST in kinds
    assert NormalizedEventType.SECURITY_DECISION in kinds
