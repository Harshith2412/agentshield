"""High-level AgentShield decision engine."""

from dataclasses import dataclass

from agentshield.core.events import SecurityEvent
from agentshield.core.policies import PolicyAction, PolicyEngine, PolicyResult, SecurityContext
from agentshield.core.provenance import ProvenanceTracker
from agentshield.core.risk import RiskAssessment, RiskEngine


@dataclass(frozen=True)
class SecurityDecision:
    event: SecurityEvent
    action: PolicyAction
    risk: RiskAssessment
    policy_results: tuple[PolicyResult, ...]

    @property
    def reasons(self) -> tuple[str, ...]:
        policy_reasons = tuple(
            result.reason for result in self.policy_results if result.action is not PolicyAction.ALLOW
        )
        return policy_reasons or tuple(reason.explanation for reason in self.risk.reasons)


class AgentShield:
    def __init__(
        self,
        *,
        provenance_tracker: ProvenanceTracker | None = None,
        risk_engine: RiskEngine | None = None,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        self.provenance = provenance_tracker or ProvenanceTracker()
        self.risk_engine = risk_engine or RiskEngine()
        self.policy_engine = policy_engine or PolicyEngine()

    def evaluate(
        self, event: SecurityEvent, *, explicit_authorization: bool = False
    ) -> SecurityDecision:
        event = self.provenance.with_inferred_provenance(event)
        self.provenance.register(event)
        context = SecurityContext(event, explicit_authorization=explicit_authorization)
        policy_results = self.policy_engine.evaluate(context)
        action = self.policy_engine.final_action(policy_results)
        risk = self.risk_engine.assess(event, policy_results)
        return SecurityDecision(event, action, risk, policy_results)

    async def evaluate_async(
        self, event: SecurityEvent, *, explicit_authorization: bool = False
    ) -> SecurityDecision:
        """Async entry point with identical policy and provenance semantics."""
        return self.evaluate(event, explicit_authorization=explicit_authorization)


SecurityEngine = AgentShield
