"""Deterministic, explainable risk assessment."""

from dataclasses import dataclass
from enum import Enum
from typing import Sequence

from agentshield.core.capabilities import CapabilityImpact, capability_profile
from agentshield.core.events import SecurityEvent
from agentshield.core.policies import PolicyAction, PolicyResult
from agentshield.core.provenance import TrustLevel


class RiskSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class RiskReason:
    factor: str
    contribution: float
    explanation: str


@dataclass(frozen=True)
class RiskAssessment:
    score: float
    severity: RiskSeverity
    reasons: tuple[RiskReason, ...]


class RiskEngine:
    _trust_weights = {
        TrustLevel.TRUSTED: 0.02,
        TrustLevel.SEMI_TRUSTED: 0.10,
        TrustLevel.UNKNOWN: 0.20,
        TrustLevel.UNTRUSTED: 0.32,
    }
    _capability_weights = {
        CapabilityImpact.LOW: 0.02,
        CapabilityImpact.MEDIUM: 0.10,
        CapabilityImpact.HIGH: 0.25,
        CapabilityImpact.CRITICAL: 0.38,
    }
    _policy_weights = {
        PolicyAction.ALLOW: 0.0,
        PolicyAction.SANITIZE: 0.08,
        PolicyAction.REVIEW: 0.12,
        PolicyAction.BLOCK: 0.22,
    }

    def assess(
        self, event: SecurityEvent, policy_results: Sequence[PolicyResult] = ()
    ) -> RiskAssessment:
        reasons: list[RiskReason] = []
        trust_weight = self._trust_weights[event.provenance.trust_level]
        reasons.append(
            RiskReason("provenance_trust", trust_weight, f"source trust is {event.provenance.trust_level.value}")
        )
        if event.capability is not None:
            impact = capability_profile(event.capability).impact
            weight = self._capability_weights[impact]
            reasons.append(
                RiskReason("capability", weight, f"{event.capability.value} has {impact.name.lower()} impact")
            )
        if event.provenance.externally_influenced:
            reasons.append(RiskReason("external_influence", 0.18, "external or untrusted data influenced the event"))
        depth_weight = min(event.provenance.propagation_depth * 0.025, 0.15)
        if depth_weight:
            reasons.append(
                RiskReason("propagation_depth", depth_weight, f"instruction propagated through {event.provenance.propagation_depth} event(s)")
            )
        consequential = [result for result in policy_results if result.action is not PolicyAction.ALLOW]
        if consequential:
            strongest = max(consequential, key=lambda result: self._policy_weights[result.action])
            weight = self._policy_weights[strongest.action]
            reasons.append(RiskReason("policy", weight, f"{strongest.policy}: {strongest.reason}"))
        score = round(min(sum(reason.contribution for reason in reasons), 1.0), 3)
        return RiskAssessment(score, self.severity_for(score), tuple(reasons))

    @staticmethod
    def severity_for(score: float) -> RiskSeverity:
        if not 0.0 <= score <= 1.0:
            raise ValueError("risk score must be between 0.0 and 1.0")
        if score < 0.25:
            return RiskSeverity.LOW
        if score < 0.50:
            return RiskSeverity.MEDIUM
        if score < 0.75:
            return RiskSeverity.HIGH
        return RiskSeverity.CRITICAL
