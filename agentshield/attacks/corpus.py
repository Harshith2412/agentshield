"""Local deterministic attack and benign evaluation corpora."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Mapping

from agentshield.core.capabilities import Capability
from agentshield.runtime.context import ExecutionMode, TrustBoundary

from agentshield.attacks.base import AttackCategory
from agentshield.attacks.results import AttackResult

ATTACK_CORPUS_VERSION = "1.0"
BENIGN_CORPUS_VERSION = "1.0"


class TransformationCategory(str, Enum):
    DIRECT = "direct"
    POLITE = "polite"
    ROLE_FRAMED = "role_framed"
    FRAGMENTED = "fragmented"
    REORDERED = "reordered"
    EMBEDDED_PROSE = "embedded_prose"
    STRUCTURED = "structured_metadata"
    MULTI_STEP = "multi_step"
    ENCODED = "encoded"
    CONFLICTING = "conflicting"
    DELAYED = "delayed"
    NESTED = "nested"
    MIXED_FIELDS = "mixed_fields"
    CHAINED = "chained"
    CONDITIONAL = "conditional"
    PERSISTENT = "persistent"
    MULTI_HOP = "multi_hop"


@dataclass(frozen=True)
class AttackVariant:
    variant_id: str
    attack_family: AttackCategory
    source_type: TrustBoundary
    payload_representation: object
    transformation: TransformationCategory
    target_capability: Capability
    expected_propagation: str
    expected_authorized: bool
    expected_protected_outcome: str
    expected_source: str
    _runner: Callable[["AttackVariant", ExecutionMode], AttackResult] = field(repr=False, compare=False)

    def run(self, mode: ExecutionMode) -> AttackResult:
        return self._runner(self, mode)


@dataclass(frozen=True)
class BenignVariant:
    variant_id: str
    description: str
    _runner: Callable[[ExecutionMode], object] = field(repr=False, compare=False)

    def run(self, mode: ExecutionMode = ExecutionMode.PROTECTED):
        return self._runner(mode)


def load_attack_corpus() -> tuple[AttackVariant, ...]:
    from agentshield.attacks.variants.indirect_injection import INDIRECT_VARIANTS
    from agentshield.attacks.variants.memory_poisoning import MEMORY_VARIANTS
    from agentshield.attacks.variants.multihop import MULTIHOP_VARIANTS
    from agentshield.attacks.variants.tool_output import TOOL_OUTPUT_VARIANTS

    return (*INDIRECT_VARIANTS, *TOOL_OUTPUT_VARIANTS, *MEMORY_VARIANTS, *MULTIHOP_VARIANTS)


def load_benign_corpus() -> tuple[BenignVariant, ...]:
    from agentshield.attacks.benign import BENIGN_VARIANTS

    return BENIGN_VARIANTS


def corpus_hash(kind: str) -> str:
    """Return a stable SHA-256 identity for corpus scenario definitions."""
    import hashlib
    import json

    if kind == "attack":
        rows = [
            {
                "id": item.variant_id,
                "family": item.attack_family.value,
                "source": item.source_type.value,
                "transformation": item.transformation.value,
                "capability": item.target_capability.value,
                "expected": item.expected_protected_outcome,
                "origin": item.expected_source,
            }
            for item in load_attack_corpus()
        ]
    elif kind == "benign":
        rows = [{"id": item.variant_id, "description": item.description} for item in load_benign_corpus()]
    else:
        raise ValueError("kind must be 'attack' or 'benign'")
    payload = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


__all__ = [
    "ATTACK_CORPUS_VERSION", "BENIGN_CORPUS_VERSION", "AttackVariant",
    "BenignVariant", "TransformationCategory", "corpus_hash",
    "load_attack_corpus", "load_benign_corpus",
]
