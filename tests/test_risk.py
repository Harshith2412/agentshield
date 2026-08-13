import pytest

from agentshield import Capability, EventType, ProvenanceRecord, SecurityEvent, TrustLevel
from agentshield.core.risk import RiskEngine, RiskSeverity


def event(trust: TrustLevel, capability: Capability | None = None) -> SecurityEvent:
    return SecurityEvent(
        EventType.TOOL_REQUEST,
        "planner",
        capability=capability,
        provenance=ProvenanceRecord(original_source="test", trust_level=trust),
    )


def test_untrusted_source_scores_above_trusted_source() -> None:
    engine = RiskEngine()
    assert engine.assess(event(TrustLevel.UNTRUSTED)).score > engine.assess(
        event(TrustLevel.TRUSTED)
    ).score


def test_sensitive_capability_increases_risk() -> None:
    engine = RiskEngine()
    baseline = engine.assess(event(TrustLevel.TRUSTED)).score
    shell = engine.assess(event(TrustLevel.TRUSTED, Capability.SHELL_EXECUTE)).score
    assert shell > baseline


def test_external_influence_increases_risk() -> None:
    engine = RiskEngine()
    plain = event(TrustLevel.UNKNOWN)
    influenced = SecurityEvent(
        EventType.MODEL_OUTPUT,
        "model",
        provenance=ProvenanceRecord(
            trust_level=TrustLevel.UNKNOWN, externally_influenced=True
        ),
    )
    assert engine.assess(influenced).score > engine.assess(plain).score


def test_propagation_depth_is_capped() -> None:
    assessment = RiskEngine().assess(
        SecurityEvent(
            EventType.MODEL_OUTPUT,
            "model",
            provenance=ProvenanceRecord(propagation_path=tuple(str(i) for i in range(100))),
        )
    )
    depth_reason = next(r for r in assessment.reasons if r.factor == "propagation_depth")
    assert depth_reason.contribution == 0.15


@pytest.mark.parametrize(
    ("score", "severity"),
    [(0.0, RiskSeverity.LOW), (0.25, RiskSeverity.MEDIUM), (0.5, RiskSeverity.HIGH), (0.75, RiskSeverity.CRITICAL)],
)
def test_severity_thresholds(score: float, severity: RiskSeverity) -> None:
    assert RiskEngine.severity_for(score) is severity


def test_invalid_score_is_rejected() -> None:
    with pytest.raises(ValueError):
        RiskEngine.severity_for(1.1)
