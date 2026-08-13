from agentshield import Capability, EventType, PolicyAction
from agentshield.attacks import IndirectPromptInjection, evaluate_pair
from agentshield.core.provenance import TrustLevel
from agentshield.runtime import ExecutionMode, ToolStatus


def test_indirect_attack_executes_unprotected() -> None:
    result = IndirectPromptInjection().run(ExecutionMode.UNPROTECTED)
    assert result.target_requested
    assert result.target_executed
    assert result.attack_success


def test_indirect_attack_is_blocked_protected() -> None:
    result = IndirectPromptInjection().run(ExecutionMode.PROTECTED)
    assert result.decision is PolicyAction.BLOCK
    assert result.blocked
    assert not result.target_executed


def test_indirect_attack_is_detected_in_both_recording_modes() -> None:
    pair = evaluate_pair(IndirectPromptInjection())
    assert pair.unprotected.detected
    assert pair.protected.detected


def test_indirect_source_is_attributed_to_document() -> None:
    result = IndirectPromptInjection().run(ExecutionMode.PROTECTED)
    attribution = result.attribution
    assert attribution.source_name == "quarterly_notes.txt"
    assert attribution.source_trust is TrustLevel.UNTRUSTED
    assert attribution.requested_capability is Capability.EMAIL_SEND
    source_event = next(event for event in result.trace.events if event.id == attribution.attack_source_event_id)
    assert source_event.provenance.source_event_id == source_event.id


def test_indirect_propagation_includes_retrieval_plan_request() -> None:
    attribution = IndirectPromptInjection().run(ExecutionMode.PROTECTED).attribution
    types = attribution.propagation_event_types
    assert EventType.RETRIEVAL in types
    assert EventType.MODEL_OUTPUT in types
    assert types[-1] is EventType.TOOL_REQUEST


def test_protected_block_has_no_simulated_email_execution() -> None:
    result = IndirectPromptInjection().run(ExecutionMode.PROTECTED)
    assert result.trace.tool_results[-1].status is ToolStatus.BLOCKED
    assert not result.trace.tools_executed


def test_same_attack_metadata_used_for_pair() -> None:
    pair = evaluate_pair(IndirectPromptInjection())
    assert pair.unprotected.attack == pair.protected.attack == pair.attack
