from agentshield import (
    Capability,
    EventType,
    PolicyAction,
    ProvenanceRecord,
    SecurityEvent,
    TrustLevel,
)
from agentshield.core.policies import PolicyEngine, SecurityContext


def context(
    capability: Capability,
    *,
    trust: TrustLevel = TrustLevel.TRUSTED,
    influenced: bool = False,
    authorized: bool = False,
) -> SecurityContext:
    event = SecurityEvent(
        EventType.TOOL_REQUEST,
        "planner",
        capability=capability,
        provenance=ProvenanceRecord(
            original_source="fixture", trust_level=trust, externally_influenced=influenced
        ),
    )
    return SecurityContext(event, explicit_authorization=authorized)


def action_for(ctx: SecurityContext) -> PolicyAction:
    engine = PolicyEngine()
    return engine.final_action(engine.evaluate(ctx))


def test_benign_network_read_is_allowed() -> None:
    assert action_for(context(Capability.NETWORK_READ)) is PolicyAction.ALLOW


def test_untrusted_network_write_is_blocked() -> None:
    assert action_for(
        context(Capability.NETWORK_WRITE, trust=TrustLevel.UNTRUSTED)
    ) is PolicyAction.BLOCK


def test_authorization_allows_untrusted_network_write() -> None:
    assert action_for(
        context(Capability.NETWORK_WRITE, trust=TrustLevel.UNTRUSTED, authorized=True)
    ) is PolicyAction.ALLOW


def test_trusted_shell_requires_review_without_authorization() -> None:
    assert action_for(context(Capability.SHELL_EXECUTE)) is PolicyAction.REVIEW


def test_untrusted_shell_is_blocked() -> None:
    assert action_for(
        context(Capability.SHELL_EXECUTE, influenced=True)
    ) is PolicyAction.BLOCK


def test_untrusted_credential_access_is_blocked_even_when_authorized() -> None:
    assert action_for(
        context(Capability.CREDENTIAL_ACCESS, influenced=True, authorized=True)
    ) is PolicyAction.BLOCK


def test_untrusted_memory_write_requires_sanitization() -> None:
    assert action_for(
        context(Capability.MEMORY_WRITE, trust=TrustLevel.UNTRUSTED)
    ) is PolicyAction.SANITIZE


def test_policy_results_explain_decision() -> None:
    results = PolicyEngine().evaluate(context(Capability.SHELL_EXECUTE))
    review = next(result for result in results if result.action is PolicyAction.REVIEW)
    assert "review" in review.reason
