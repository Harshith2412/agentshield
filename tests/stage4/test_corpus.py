import pytest

from agentshield.attacks import load_attack_corpus
from agentshield.attacks.base import AttackCategory
from agentshield.attacks.corpus import TransformationCategory
from agentshield.runtime import ExecutionMode, TrustBoundary


ATTACKS = load_attack_corpus()


def test_attack_corpus_has_required_family_counts() -> None:
    assert sum(v.attack_family is AttackCategory.INDIRECT_PROMPT_INJECTION for v in ATTACKS) >= 10
    assert sum(v.attack_family is AttackCategory.MALICIOUS_TOOL_OUTPUT for v in ATTACKS) >= 6
    assert sum(v.attack_family is AttackCategory.MEMORY_POISONING for v in ATTACKS) >= 6


def test_variant_ids_are_unique() -> None:
    assert len({variant.variant_id for variant in ATTACKS}) == len(ATTACKS)


@pytest.mark.parametrize("variant", ATTACKS, ids=lambda item: item.variant_id)
def test_each_variant_has_complete_metadata(variant) -> None:
    assert variant.variant_id
    assert variant.payload_representation
    assert isinstance(variant.transformation, TransformationCategory)
    assert variant.source_type in {TrustBoundary.LOCAL_UNTRUSTED, TrustBoundary.EXTERNAL_UNTRUSTED}
    assert not variant.expected_authorized
    assert variant.expected_protected_outcome == "blocked"


@pytest.mark.parametrize("variant", ATTACKS, ids=lambda item: item.variant_id)
def test_each_variant_executes_unauthorized_target_unprotected(variant) -> None:
    result = variant.run(ExecutionMode.UNPROTECTED)
    assert result.target_requested
    assert result.target_executed
    assert result.attack_success


@pytest.mark.parametrize("variant", ATTACKS, ids=lambda item: item.variant_id)
def test_each_variant_is_mitigated_protected(variant) -> None:
    result = variant.run(ExecutionMode.PROTECTED)
    assert result.detected
    assert result.blocked
    assert not result.target_executed
    assert not result.attack_success
