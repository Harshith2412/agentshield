from agentshield import (
    AgentShield,
    Capability,
    EventType,
    PolicyAction,
    ProvenanceRecord,
    SecurityEvent,
    TrustLevel,
)


def test_engine_allows_benign_trusted_event() -> None:
    shield = AgentShield()
    decision = shield.evaluate(
        SecurityEvent(
            EventType.USER_INPUT,
            "user",
            provenance=ProvenanceRecord(trust_level=TrustLevel.TRUSTED),
        )
    )
    assert decision.action is PolicyAction.ALLOW
    assert decision.risk.score < 0.25


def test_engine_blocks_dangerous_propagated_action() -> None:
    shield = AgentShield()
    retrieval = SecurityEvent(
        EventType.RETRIEVAL,
        "retriever",
        provenance=ProvenanceRecord(
            original_source="external_document",
            trust_level=TrustLevel.UNTRUSTED,
            externally_influenced=True,
        ),
    )
    shield.evaluate(retrieval)
    tool_request = SecurityEvent(
        EventType.TOOL_REQUEST,
        "planner",
        parent_ids=(retrieval.id,),
        capability=Capability.EMAIL_SEND,
    )
    decision = shield.evaluate(tool_request)
    assert decision.action is PolicyAction.BLOCK
    assert decision.event.provenance.original_source == "external_document"
    assert decision.risk.score >= 0.75


def test_engine_registers_each_evaluated_event() -> None:
    shield = AgentShield()
    event = SecurityEvent(EventType.USER_INPUT, "user")
    shield.evaluate(event)
    assert len(shield.provenance) == 1


def test_engine_decision_exposes_policy_reason() -> None:
    decision = AgentShield().evaluate(
        SecurityEvent(
            EventType.TOOL_REQUEST,
            "planner",
            capability=Capability.CREDENTIAL_ACCESS,
        )
    )
    assert decision.action is PolicyAction.REVIEW
    assert any("authorization" in reason for reason in decision.reasons)


def test_explicit_authorization_is_passed_to_policies() -> None:
    decision = AgentShield().evaluate(
        SecurityEvent(
            EventType.TOOL_REQUEST,
            "planner",
            capability=Capability.SHELL_EXECUTE,
            provenance=ProvenanceRecord(trust_level=TrustLevel.TRUSTED),
        ),
        explicit_authorization=True,
    )
    assert decision.action is PolicyAction.ALLOW
