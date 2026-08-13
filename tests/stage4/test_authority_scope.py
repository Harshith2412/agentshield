from agentshield import Capability, EventType, PolicyAction
from agentshield.runtime import (
    AgentTask, AuthorizationGrant, DemoAgent, Document, DocumentStore, EmailScope,
    TrustBoundary, WritePathScope,
)


def tool_decision(trace):
    return next(decision for decision in trace.decisions if decision.event.event_type is EventType.TOOL_REQUEST)


def test_email_scope_allows_exact_recipient() -> None:
    trace = DemoAgent().run(
        "Email demo recipient", task=AgentTask(tool="send_email", tool_arguments={"to": "demo@example.test"}),
        authorization_grants=(AuthorizationGrant(Capability.EMAIL_SEND, EmailScope("demo@example.test")),),
    )
    assert tool_decision(trace).action is PolicyAction.ALLOW
    assert trace.tools_executed


def test_email_scope_denies_different_recipient() -> None:
    trace = DemoAgent().run(
        "Email", task=AgentTask(tool="send_email", tool_arguments={"to": "other@example.test"}),
        authorization_grants=(AuthorizationGrant(Capability.EMAIL_SEND, EmailScope("demo@example.test")),),
    )
    assert tool_decision(trace).action is PolicyAction.BLOCK
    assert not trace.tools_executed


def test_untrusted_source_cannot_expand_email_scope() -> None:
    agent = DemoAgent(documents=DocumentStore((Document("data.txt", "data", TrustBoundary.LOCAL_UNTRUSTED),)))
    trace = agent.run(
        "Summarize", task=AgentTask(document="data.txt", tool="send_email", tool_arguments={"to": "other@example.test"}),
        authorization_grants=(AuthorizationGrant(Capability.EMAIL_SEND, EmailScope("demo@example.test")),),
    )
    assert tool_decision(trace).action is PolicyAction.BLOCK


def test_write_scope_allows_descendant_path() -> None:
    trace = DemoAgent().run(
        "Write report", task=AgentTask(tool="write_file", tool_arguments={"path": "reports/2026/result.txt", "content": "ok"}),
        authorization_grants=(AuthorizationGrant(Capability.WRITE_LOCAL, WritePathScope("reports")),),
    )
    assert tool_decision(trace).action is PolicyAction.ALLOW
    assert trace.tools_executed


def test_write_scope_denies_sibling_path() -> None:
    trace = DemoAgent().run(
        "Write", task=AgentTask(tool="write_file", tool_arguments={"path": "exports/result.txt", "content": "no"}),
        authorization_grants=(AuthorizationGrant(Capability.WRITE_LOCAL, WritePathScope("reports")),),
    )
    assert tool_decision(trace).action is PolicyAction.BLOCK


def test_write_scope_denies_parent_traversal() -> None:
    scope = WritePathScope("reports")
    assert not scope.allows({"path": "reports/../outside.txt"})


def test_read_authority_does_not_grant_email_authority() -> None:
    agent = DemoAgent(documents=DocumentStore((Document("data.txt", "data", TrustBoundary.LOCAL_UNTRUSTED),)))
    trace = agent.run(
        "Read data", task=AgentTask(document="data.txt", tool="send_email", tool_arguments={"to": "demo@example.test"}),
        authorized_capabilities=frozenset({Capability.READ_LOCAL}),
    )
    assert tool_decision(trace).action is PolicyAction.BLOCK


def test_untrusted_data_within_user_granted_scope_is_allowed() -> None:
    agent = DemoAgent(documents=DocumentStore((Document("data.txt", "report data", TrustBoundary.LOCAL_UNTRUSTED),)))
    trace = agent.run(
        "Summarize and email to demo@example.test",
        task=AgentTask(document="data.txt", tool="send_email", tool_arguments={"to": "demo@example.test"}),
        authorization_grants=(AuthorizationGrant(Capability.EMAIL_SEND, EmailScope("demo@example.test")),),
    )
    assert tool_decision(trace).action is PolicyAction.ALLOW
    assert trace.tools_executed
