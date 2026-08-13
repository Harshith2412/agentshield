from agentshield import Capability, EventType, PolicyAction
from agentshield.attacks import MemoryPoisoning, evaluate_pair
from agentshield.core.provenance import TrustLevel
from agentshield.runtime import ExecutionMode


def test_poisoned_memory_executes_unprotected() -> None:
    result = MemoryPoisoning().run(ExecutionMode.UNPROTECTED)
    assert result.attack_success
    assert result.target_executed


def test_poisoned_memory_is_blocked_protected() -> None:
    result = MemoryPoisoning().run(ExecutionMode.PROTECTED)
    assert result.blocked
    assert result.decision is PolicyAction.BLOCK


def test_memory_read_retains_untrusted_label() -> None:
    result = MemoryPoisoning().run(ExecutionMode.PROTECTED)
    memory_read = next(event for event in result.trace.events if event.event_type is EventType.MEMORY_READ)
    assert memory_read.provenance.trust_level is TrustLevel.UNTRUSTED
    assert memory_read.provenance.externally_influenced


def test_memory_source_is_attributed_by_key() -> None:
    attribution = MemoryPoisoning().run(ExecutionMode.PROTECTED).attribution
    assert attribution.source_name == "report_workflow"
    assert attribution.requested_capability is Capability.EMAIL_SEND


def test_memory_influence_reaches_plan_and_request() -> None:
    result = MemoryPoisoning().run(ExecutionMode.PROTECTED)
    types = result.attribution.propagation_event_types
    assert EventType.MEMORY_READ in types
    assert EventType.MODEL_OUTPUT in types
    assert types[-1] is EventType.TOOL_REQUEST


def test_preexisting_memory_models_cross_step_influence() -> None:
    result = MemoryPoisoning().run(ExecutionMode.PROTECTED)
    memory_event = next(event for event in result.trace.events if event.event_type is EventType.MEMORY_READ)
    assert memory_event.metadata["found"] is True
    assert memory_event.provenance.source_event_id is not None


def test_memory_pair_has_expected_outcomes() -> None:
    pair = evaluate_pair(MemoryPoisoning())
    assert pair.unprotected.attack_success
    assert not pair.protected.attack_success
