from dataclasses import FrozenInstanceError

import pytest

from agentshield.experiments.corpus import (
    REAL_MODEL_ATTACK_CORPUS_VERSION,
    REAL_MODEL_BENIGN_CORPUS_VERSION,
    load_real_model_attack_corpus,
    load_real_model_benign_corpus,
    real_model_corpus_hash,
)


def test_attack_corpus_has_natural_language_scale() -> None:
    corpus = load_real_model_attack_corpus()
    assert len(corpus) == 60
    assert all(len(item.content.split()) >= 8 for item in corpus)
    assert all("other@example.test" in item.content for item in corpus)


def test_benign_corpus_has_controls() -> None:
    corpus = load_real_model_benign_corpus()
    assert len(corpus) == 24
    assert sum(item.control_kind == "benign" for item in corpus) == 20
    assert sum(item.control_kind == "authorized" for item in corpus) == 4


@pytest.mark.parametrize(
    "family",
    (
        "indirect_prompt_injection", "authority_impersonation", "role_impersonation",
        "tool_output_injection", "memory_poisoning", "scope_manipulation",
        "delayed_instruction", "hidden_in_prose", "conflicting_instruction",
        "multi_hop_influence", "model_authority_claim", "provenance_manipulation",
    ),
)
def test_required_attack_family_has_five_variants(family: str) -> None:
    assert sum(item.family == family for item in load_real_model_attack_corpus()) == 5


def test_corpus_versions_and_hashes_are_stable() -> None:
    assert REAL_MODEL_ATTACK_CORPUS_VERSION == REAL_MODEL_BENIGN_CORPUS_VERSION == "1.0"
    assert real_model_corpus_hash("attack") == "88ba716b622dabad1548e41af8a56c2877680ab657e3a862f3574b3efa2d055e"
    assert real_model_corpus_hash("benign") == "8f51912a3f727e7f44811e67170a6d2d6f18385fe341a26e9494f18846f937a8"


def test_corpus_records_are_immutable() -> None:
    with pytest.raises(FrozenInstanceError):
        load_real_model_attack_corpus()[0].content = "changed"


def test_invalid_corpus_hash_kind_fails() -> None:
    with pytest.raises(ValueError):
        real_model_corpus_hash("unknown")
