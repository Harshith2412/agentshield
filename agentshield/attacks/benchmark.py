"""Measured deterministic corpus benchmark and transparent failure reporting."""

from __future__ import annotations

from dataclasses import dataclass
from statistics import mean

from agentshield.core.capabilities import Capability
from agentshield.runtime.context import ExecutionMode

from agentshield.attacks.base import AttackCategory
from agentshield.attacks.corpus import AttackVariant, load_attack_corpus, load_benign_corpus
from agentshield.attacks.results import AttackResult, AttributionStatus


@dataclass(frozen=True)
class FamilyMetrics:
    family: AttackCategory
    variants: int
    detected: int
    mitigated: int
    false_negatives: int


@dataclass(frozen=True)
class BenchmarkFailure:
    scenario_id: str
    attack_family: str
    variant_id: str
    expected_outcome: str
    actual_outcome: str
    source: str
    target_capability: Capability | None
    risk_decision: str
    provenance_path: tuple[str, ...]
    influence_set: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class BenchmarkMetrics:
    """Measured corpus metrics.

    Mitigation rate is prevented unauthorized target actions divided by attempted
    unauthorized target actions. Detection rate is non-ALLOW target decisions
    divided by attack variants. Attribution success requires the exact expected
    source and an unambiguous result. A false positive is a benign intended action
    withheld in protected mode; a false negative is an unauthorized target action
    that executes in protected mode.
    """
    total_attack_variants: int
    attacks_successful_unprotected: int
    attacks_successful_protected: int
    attack_mitigation_rate: float
    attack_detection_rate: float
    blocked_unauthorized_actions: int
    false_negatives: int
    benign_scenarios: int
    false_positives: int
    false_positive_rate: float
    attribution_success_rate: float
    average_attribution_path_length: float
    ambiguous_attributions: int
    per_family: tuple[FamilyMetrics, ...]


@dataclass(frozen=True)
class BenchmarkReport:
    metrics: BenchmarkMetrics
    unprotected_results: tuple[AttackResult, ...]
    protected_results: tuple[AttackResult, ...]
    benign_results: tuple[object, ...]
    failures: tuple[BenchmarkFailure, ...]

    def render(self) -> str:
        m = self.metrics
        lines = [
            "AgentShield Controlled Benchmark",
            "================================",
            f"Attack variants:             {m.total_attack_variants}",
            f"Benign variants:             {m.benign_scenarios}",
            "",
            "UNPROTECTED",
            f"Attack successes:            {m.attacks_successful_unprotected}",
            "",
            "PROTECTED",
            f"Attack successes:            {m.attacks_successful_protected}",
            f"Blocked unauthorized actions:{m.blocked_unauthorized_actions:>5}",
            f"False negatives:             {m.false_negatives}",
            f"Detection rate:              {m.attack_detection_rate:.1%}",
            f"Mitigation rate:             {m.attack_mitigation_rate:.1%}",
            f"Attribution success:         {m.attribution_success_rate:.1%}",
            f"Ambiguous attributions:      {m.ambiguous_attributions}",
            "",
            "BENIGN",
            f"Allowed correctly:           {m.benign_scenarios - m.false_positives}",
            f"False positives:             {m.false_positives}",
            f"False-positive rate:         {m.false_positive_rate:.1%}",
            "",
            "By family:",
        ]
        for family in m.per_family:
            lines.append(
                f"{family.family.value:28} variants={family.variants} detected={family.detected} mitigated={family.mitigated}"
            )
        lines.append(f"Failures recorded:           {len(self.failures)}")
        return "\n".join(lines)


def run_benchmark(
    attack_variants: tuple[AttackVariant, ...] | None = None,
    benign_variants=None,
) -> BenchmarkReport:
    attacks = attack_variants if attack_variants is not None else load_attack_corpus()
    benign = benign_variants if benign_variants is not None else load_benign_corpus()
    unprotected = tuple(variant.run(ExecutionMode.UNPROTECTED) for variant in attacks)
    protected = tuple(variant.run(ExecutionMode.PROTECTED) for variant in attacks)
    benign_results = tuple(variant.run(ExecutionMode.PROTECTED) for variant in benign)
    attempted = sum(result.target_requested and not result.user_authorized_target_capability for result in protected)
    mitigated = sum(
        result.target_requested and not result.target_executed and not result.user_authorized_target_capability
        for result in protected
    )
    detected = sum(result.detected for result in protected)
    attribution_successes = sum(
        result.attribution is not None
        and result.attribution.status is AttributionStatus.UNAMBIGUOUS
        and result.attribution.source_name == variant.expected_source
        for variant, result in zip(attacks, protected)
    )
    paths = [len(result.propagation_path) for result in protected if result.attribution]
    false_positives = sum(result.false_positive for result in benign_results)
    family_metrics = tuple(
        FamilyMetrics(
            family,
            sum(variant.attack_family is family for variant in attacks),
            sum(result.detected for variant, result in zip(attacks, protected) if variant.attack_family is family),
            sum(not result.target_executed for variant, result in zip(attacks, protected) if variant.attack_family is family),
            sum(result.attack_success for variant, result in zip(attacks, protected) if variant.attack_family is family),
        )
        for family in AttackCategory
    )
    failures: list[BenchmarkFailure] = []
    for variant, result in zip(attacks, protected):
        if result.attack_success or result.decision is None or not result.blocked:
            failures.append(_attack_failure(variant, result))
    for variant, result in zip(benign, benign_results):
        if result.false_positive:
            failures.append(BenchmarkFailure(
                variant.variant_id, "benign", variant.variant_id, "allow", "withheld",
                "benign", None, "non-allow", (), (), "benign intended behavior was not permitted",
            ))
    metrics = BenchmarkMetrics(
        len(attacks),
        sum(result.attack_success for result in unprotected),
        sum(result.attack_success for result in protected),
        mitigated / attempted if attempted else 0.0,
        detected / len(protected) if protected else 0.0,
        sum(result.blocked for result in protected),
        sum(result.attack_success for result in protected),
        len(benign),
        false_positives,
        false_positives / len(benign) if benign else 0.0,
        attribution_successes / len(protected) if protected else 0.0,
        mean(paths) if paths else 0.0,
        sum(result.attribution is not None and result.attribution.status is AttributionStatus.AMBIGUOUS for result in protected),
        family_metrics,
    )
    return BenchmarkReport(metrics, unprotected, protected, benign_results, tuple(failures))


def _attack_failure(variant: AttackVariant, result: AttackResult) -> BenchmarkFailure:
    target = next((decision.event for decision in result.trace.decisions if decision.event.capability is variant.target_capability), None)
    influences = result.trace.influence_set(target.id) if target else ()
    return BenchmarkFailure(
        variant.variant_id,
        variant.attack_family.value,
        variant.variant_id,
        variant.expected_protected_outcome,
        "executed" if result.target_executed else str(result.decision.value if result.decision else "not requested"),
        result.source,
        result.target_capability,
        result.decision.value if result.decision else "none",
        result.propagation_path,
        tuple(f"{item.source_name}:{item.kind.value}" for item in influences),
        "protected outcome differed from corpus expectation",
    )
