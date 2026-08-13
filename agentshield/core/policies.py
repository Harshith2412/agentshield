"""Composable rules for security-sensitive agent activity."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Protocol, Sequence

from agentshield.core.capabilities import Capability, CapabilityImpact, capability_profile
from agentshield.core.events import SecurityEvent
from agentshield.core.provenance import TrustLevel


class PolicyAction(str, Enum):
    ALLOW = "allow"
    SANITIZE = "sanitize"
    REVIEW = "review"
    BLOCK = "block"


class _ActionPriority(IntEnum):
    ALLOW = 0
    SANITIZE = 1
    REVIEW = 2
    BLOCK = 3


@dataclass(frozen=True)
class SecurityContext:
    event: SecurityEvent
    explicit_authorization: bool = False

    @property
    def untrusted_influence(self) -> bool:
        provenance = self.event.provenance
        return provenance.externally_influenced or provenance.trust_level is TrustLevel.UNTRUSTED


@dataclass(frozen=True)
class PolicyResult:
    policy: str
    action: PolicyAction
    reason: str


class Policy(Protocol):
    name: str

    def evaluate(self, context: SecurityContext) -> PolicyResult: ...


class UntrustedSideEffectPolicy:
    name = "untrusted_external_side_effect"

    def evaluate(self, context: SecurityContext) -> PolicyResult:
        capability = context.event.capability
        dangerous = bool(
            capability
            and capability_profile(capability).creates_side_effect
            and capability_profile(capability).impact >= CapabilityImpact.HIGH
        )
        if dangerous and context.untrusted_influence and not context.explicit_authorization:
            return PolicyResult(
                self.name,
                PolicyAction.BLOCK,
                "untrusted content cannot directly cause a high-impact side effect without authorization",
            )
        return PolicyResult(self.name, PolicyAction.ALLOW, "no unauthorized high-impact side effect")


class HighImpactAuthorizationPolicy:
    """Require explicit authority for high-impact side effects from any source."""

    name = "high_impact_authorization"

    def evaluate(self, context: SecurityContext) -> PolicyResult:
        capability = context.event.capability
        requires_authority = bool(
            capability
            and capability is not Capability.SHELL_EXECUTE
            and capability_profile(capability).creates_side_effect
            and capability_profile(capability).impact >= CapabilityImpact.HIGH
        )
        if requires_authority and not context.explicit_authorization:
            return PolicyResult(
                self.name,
                PolicyAction.BLOCK,
                "high-impact side effect lacks explicit capability authority",
            )
        return PolicyResult(self.name, PolicyAction.ALLOW, "capability authority requirement satisfied")


class ShellExecutionPolicy:
    name = "shell_execution"

    def evaluate(self, context: SecurityContext) -> PolicyResult:
        if context.event.capability is not Capability.SHELL_EXECUTE:
            return PolicyResult(self.name, PolicyAction.ALLOW, "shell execution not requested")
        if context.untrusted_influence and not context.explicit_authorization:
            return PolicyResult(self.name, PolicyAction.BLOCK, "untrusted influence on shell execution")
        if not context.explicit_authorization:
            return PolicyResult(self.name, PolicyAction.REVIEW, "shell execution requires human review")
        return PolicyResult(self.name, PolicyAction.ALLOW, "shell execution explicitly authorized")


class CredentialAccessPolicy:
    name = "credential_access"

    def evaluate(self, context: SecurityContext) -> PolicyResult:
        if context.event.capability is not Capability.CREDENTIAL_ACCESS:
            return PolicyResult(self.name, PolicyAction.ALLOW, "credential access not requested")
        if context.untrusted_influence:
            return PolicyResult(self.name, PolicyAction.BLOCK, "credential access has untrusted influence")
        if not context.explicit_authorization:
            return PolicyResult(self.name, PolicyAction.REVIEW, "credential access requires authorization")
        return PolicyResult(self.name, PolicyAction.ALLOW, "credential access explicitly authorized")


class UntrustedMemoryWritePolicy:
    name = "untrusted_memory_write"

    def evaluate(self, context: SecurityContext) -> PolicyResult:
        if context.event.capability is not Capability.MEMORY_WRITE:
            return PolicyResult(self.name, PolicyAction.ALLOW, "memory write not requested")
        if context.untrusted_influence and not context.explicit_authorization:
            return PolicyResult(
                self.name, PolicyAction.SANITIZE, "sanitize untrusted content before persistent memory write"
            )
        return PolicyResult(self.name, PolicyAction.ALLOW, "memory write meets trust requirements")


DEFAULT_POLICIES: tuple[Policy, ...] = (
    UntrustedSideEffectPolicy(),
    HighImpactAuthorizationPolicy(),
    ShellExecutionPolicy(),
    CredentialAccessPolicy(),
    UntrustedMemoryWritePolicy(),
)


class PolicyEngine:
    def __init__(self, policies: Sequence[Policy] | None = None) -> None:
        self.policies = tuple(DEFAULT_POLICIES if policies is None else policies)

    def evaluate(self, context: SecurityContext) -> tuple[PolicyResult, ...]:
        return tuple(policy.evaluate(context) for policy in self.policies)

    @staticmethod
    def final_action(results: Sequence[PolicyResult]) -> PolicyAction:
        if not results:
            return PolicyAction.ALLOW
        return max(results, key=lambda result: _ActionPriority[result.action.name]).action
