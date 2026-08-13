from agentshield import Capability, EventType, PolicyAction
from agentshield.attacks import MaliciousToolOutput, evaluate_pair
from agentshield.core.provenance import TrustLevel
from agentshield.runtime import ExecutionMode


def test_compromised_tool_output_executes_write_unprotected() -> None:
    result = MaliciousToolOutput().run(ExecutionMode.UNPROTECTED)
    assert result.attack_success
    assert [request.name for request in result.trace.tools_executed] == ["safe_lookup", "write_file"]


def test_compromised_tool_output_write_blocked_protected() -> None:
    result = MaliciousToolOutput().run(ExecutionMode.PROTECTED)
    assert result.blocked
    assert result.decision is PolicyAction.BLOCK
    assert [request.name for request in result.trace.tools_executed] == ["safe_lookup"]


def test_tool_output_preserves_untrusted_provenance() -> None:
    result = MaliciousToolOutput().run(ExecutionMode.PROTECTED)
    response = next(
        event for event in result.trace.events
        if event.event_type is EventType.TOOL_RESPONSE and event.source == "safe_lookup"
    )
    assert response.provenance.trust_level is TrustLevel.UNTRUSTED
    assert response.provenance.externally_influenced


def test_tool_output_influences_followup_plan() -> None:
    result = MaliciousToolOutput().run(ExecutionMode.PROTECTED)
    response = next(event for event in result.trace.events if event.source == "safe_lookup" and event.event_type is EventType.TOOL_RESPONSE)
    plan = next(event for event in result.trace.events if event.metadata.get("kind") == "followup_plan")
    assert plan.parent_ids == (response.id,)
    assert plan.provenance.trust_level is TrustLevel.UNTRUSTED


def test_tool_output_attribution_names_compromised_tool() -> None:
    attribution = MaliciousToolOutput().run(ExecutionMode.PROTECTED).attribution
    assert attribution.source_name == "safe_lookup"
    assert attribution.requested_capability is Capability.WRITE_LOCAL


def test_tool_output_path_contains_response_before_target() -> None:
    types = MaliciousToolOutput().run(ExecutionMode.PROTECTED).attribution.propagation_event_types
    assert EventType.TOOL_RESPONSE in types
    assert types.index(EventType.TOOL_RESPONSE) < len(types) - 1


def test_tool_output_pair_has_expected_outcomes() -> None:
    pair = evaluate_pair(MaliciousToolOutput())
    assert pair.unprotected.attack_success
    assert pair.protected.blocked
