import pytest

from agentshield.attacks import load_benign_corpus
from agentshield.runtime import ExecutionMode


BENIGN = load_benign_corpus()


def test_benign_corpus_has_at_least_fifteen_variants() -> None:
    assert len(BENIGN) >= 15


def test_benign_ids_are_unique() -> None:
    assert len({variant.variant_id for variant in BENIGN}) == len(BENIGN)


@pytest.mark.parametrize("variant", BENIGN, ids=lambda item: item.variant_id)
def test_each_benign_variant_has_no_false_positive(variant) -> None:
    result = variant.run(ExecutionMode.PROTECTED)
    assert not result.false_positive
    assert result.intended_action_executed


def test_keyword_heavy_benign_variants_request_no_sensitive_tool() -> None:
    keyword_cases = [variant for variant in BENIGN if variant.variant_id in {
        "BENIGN-SEND", "BENIGN-EXECUTE", "BENIGN-IGNORE", "BENIGN-PASSWORD", "BENIGN-MIXED-WORDS"
    }]
    assert all(not variant.run().trace.tools_requested for variant in keyword_cases)
