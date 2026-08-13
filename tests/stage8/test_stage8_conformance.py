import pytest

from agentshield.persistence import run_stage8_conformance


TARGETS = ("native", "langgraph", "microsoft_agent_framework")
INVARIANTS = (
    "async_matches_sync", "incomplete_stream_cannot_execute", "persistence_cannot_elevate_trust",
    "resume_cannot_create_authority", "one_shot_remains_consumed", "tamper_fails_closed",
    "stale_checkpoint_rejected", "untrusted_influence_survives_reload",
)


@pytest.mark.parametrize("target", TARGETS)
def test_stage8_target_passes_all_applicable_invariants(target: str) -> None:
    result = run_stage8_conformance(target)
    assert result.passed == 8
    assert result.failed == 0


@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("invariant", INVARIANTS)
def test_named_stage8_invariant(target: str, invariant: str) -> None:
    result = run_stage8_conformance(target)
    check = next(item for item in result.invariants if item.name == invariant)
    assert check.passed


def test_unknown_stage8_target_rejected() -> None:
    with pytest.raises(ValueError): run_stage8_conformance("unknown")
