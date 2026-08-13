from agentshield import Capability, EventType
from agentshield.attacks import load_attack_corpus
from agentshield.runtime import (
    AgentTask, AuthorizationGrant, DemoAgent, Document, DocumentStore, EmailScope,
    InfluenceKind, TrustBoundary, influence_kind,
)


def test_mixed_context_records_trusted_and_untrusted_influences() -> None:
    agent = DemoAgent(documents=DocumentStore((Document("data.txt", "external", TrustBoundary.LOCAL_UNTRUSTED),)))
    trace = agent.run("Summarize", task=AgentTask(document="data.txt", tool="send_email", tool_arguments={"to": "x.test"}))
    request = next(event for event in trace.events if event.event_type is EventType.TOOL_REQUEST)
    records = trace.influence_set(request.id)
    assert {record.source_name for record in records} == {"user", "data.txt"}
    assert influence_kind(records) is InfluenceKind.MIXED


def test_user_influence_is_non_authority_without_grant() -> None:
    trace = DemoAgent().run("Do nothing")
    record = trace.influence_set(trace.events[0].id)[0]
    assert record.kind is InfluenceKind.TRUSTED
    assert not record.authorized_capabilities


def test_user_influence_bears_only_explicit_capability_authority() -> None:
    trace = DemoAgent().run(
        "Email", task=AgentTask(tool="send_email", tool_arguments={"to": "demo@example.test"}),
        authorization_grants=(AuthorizationGrant(Capability.EMAIL_SEND, EmailScope("demo@example.test")),),
    )
    request = next(event for event in trace.events if event.event_type is EventType.TOOL_REQUEST)
    user = next(record for record in trace.influence_set(request.id) if record.source_name == "user")
    assert user.kind is InfluenceKind.AUTHORIZATION_BEARING
    assert user.authorized_capabilities == (Capability.EMAIL_SEND,)


def test_untrusted_influence_never_bears_authority() -> None:
    variant = load_attack_corpus()[0]
    result = variant.run(mode=__import__("agentshield.runtime", fromlist=["ExecutionMode"]).ExecutionMode.PROTECTED)
    request = next(event for event in result.trace.events if event.event_type is EventType.TOOL_REQUEST)
    untrusted = [record for record in result.trace.influence_set(request.id) if record.trust.value == "untrusted"]
    assert untrusted
    assert all(record.kind is InfluenceKind.UNTRUSTED for record in untrusted)
    assert all(not record.authorized_capabilities for record in untrusted)


def test_influence_set_rejects_unknown_event() -> None:
    trace = DemoAgent().run("No action")
    try:
        trace.influence_set("missing")
    except KeyError as exc:
        assert "not present" in str(exc)
    else:
        raise AssertionError("unknown event accepted")
