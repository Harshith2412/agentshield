from agentshield import Capability, EventType, PolicyAction
from agentshield.runtime import (
    AgentTask,
    DemoAgent,
    Document,
    DocumentStore,
    ExecutionMode,
    MemoryEntry,
    RuntimeMemory,
    ToolRegistry,
    ToolStatus,
    TrustBoundary,
)


def make_agent(boundary: TrustBoundary = TrustBoundary.LOCAL_TRUSTED) -> DemoAgent:
    return DemoAgent(documents=DocumentStore((Document("notes.txt", "Alpha beta gamma.", boundary),)))


def test_agent_execution_is_behaviorally_deterministic() -> None:
    first = make_agent().run("Summarize", task=AgentTask(document="notes.txt"))
    second = make_agent().run("Summarize", task=AgentTask(document="notes.txt"))
    assert first.final_result == second.final_result
    assert [event.event_type for event in first.events] == [event.event_type for event in second.events]


def test_retrieval_flow_emits_expected_events() -> None:
    trace = make_agent().run("Summarize", task=AgentTask(document="notes.txt"))
    assert [event.event_type for event in trace.events] == [
        EventType.USER_INPUT, EventType.RETRIEVAL, EventType.MODEL_OUTPUT, EventType.MODEL_OUTPUT
    ]


def test_retrieval_is_parent_of_plan() -> None:
    trace = make_agent().run("Summarize", task=AgentTask(document="notes.txt"))
    retrieval = next(event for event in trace.events if event.event_type is EventType.RETRIEVAL)
    plan = next(event for event in trace.events if event.metadata.get("kind") == "plan")
    assert retrieval.id in plan.parent_ids


def test_untrusted_retrieval_propagates_to_plan() -> None:
    trace = make_agent(TrustBoundary.EXTERNAL_UNTRUSTED).run(
        "Summarize", task=AgentTask(document="notes.txt")
    )
    plan = next(event for event in trace.events if event.metadata.get("kind") == "plan")
    assert plan.provenance.externally_influenced
    assert plan.provenance.original_source == "notes.txt"


def test_trusted_retrieval_does_not_mark_external_influence() -> None:
    trace = make_agent().run("Summarize", task=AgentTask(document="notes.txt"))
    retrieval = next(event for event in trace.events if event.event_type is EventType.RETRIEVAL)
    assert not retrieval.provenance.externally_influenced


def test_protected_untrusted_email_is_blocked_and_not_recorded() -> None:
    tools = ToolRegistry()
    agent = DemoAgent(
        documents=DocumentStore((Document("notes.txt", "Routine content", TrustBoundary.LOCAL_UNTRUSTED),)),
        tools=tools,
    )
    trace = agent.run("Process", task=AgentTask(
        document="notes.txt", tool="send_email", tool_arguments={"to": "a@example.test"}
    ))
    assert trace.tool_results[0].status is ToolStatus.BLOCKED
    assert not tools.simulated_emails
    assert trace.tools_blocked


def test_unprotected_mode_executes_despite_block_decision() -> None:
    tools = ToolRegistry()
    agent = DemoAgent(
        documents=DocumentStore((Document("notes.txt", "Routine content", TrustBoundary.LOCAL_UNTRUSTED),)),
        tools=tools,
    )
    trace = agent.run("Process", task=AgentTask(
        document="notes.txt", tool="send_email", tool_arguments={"to": "a@example.test"}
    ), mode=ExecutionMode.UNPROTECTED)
    request_decision = next(d for d in trace.decisions if d.event.event_type is EventType.TOOL_REQUEST)
    assert request_decision.action is PolicyAction.BLOCK
    assert trace.tool_results[0].status is ToolStatus.SUCCESS
    assert len(tools.simulated_emails) == 1


def test_authorized_email_executes_in_protected_mode() -> None:
    tools = ToolRegistry()
    trace = DemoAgent(tools=tools).run(
        "Send approved email",
        task=AgentTask(tool="send_email", tool_arguments={"to": "a@example.test"}),
        authorized_capabilities=frozenset({Capability.EMAIL_SEND}),
    )
    assert trace.tool_results[0].status is ToolStatus.SUCCESS
    assert trace.tools_executed


def test_review_does_not_execute_in_protected_mode() -> None:
    tools = ToolRegistry()
    trace = DemoAgent(tools=tools).run(
        "Maintenance", task=AgentTask(tool="shell_execute", tool_arguments={"command": "check"})
    )
    assert trace.tool_results[0].status is ToolStatus.REVIEW_REQUIRED
    assert not tools.simulated_shell_commands


def test_memory_read_is_instrumented() -> None:
    memory = RuntimeMemory((MemoryEntry("project", "green"),))
    trace = DemoAgent(memory=memory).run("Recall", task=AgentTask(memory_read="project"))
    event = next(event for event in trace.events if event.event_type is EventType.MEMORY_READ)
    assert event.content == "green"
    assert "Memory: green" in trace.final_result


def test_trusted_memory_write_is_instrumented_and_persisted() -> None:
    memory = RuntimeMemory()
    trace = DemoAgent(memory=memory).run("Remember", task=AgentTask(memory_write=("state", "ready")))
    assert any(event.event_type is EventType.MEMORY_WRITE for event in trace.events)
    assert memory.read("state").value == "ready"


def test_untrusted_memory_write_requires_sanitizer_and_is_not_persisted() -> None:
    memory = RuntimeMemory()
    agent = DemoAgent(
        documents=DocumentStore((Document("notes.txt", "External data", TrustBoundary.EXTERNAL_UNTRUSTED),)),
        memory=memory,
    )
    trace = agent.run("Process", task=AgentTask(document="notes.txt", memory_write=("state", "external")))
    decision = next(d for d in trace.decisions if d.event.event_type is EventType.MEMORY_WRITE)
    assert decision.action is PolicyAction.SANITIZE
    assert "state" not in memory


def test_side_effect_execution_emits_external_action() -> None:
    trace = DemoAgent().run(
        "Send approved email",
        task=AgentTask(tool="send_email", tool_arguments={"to": "a@example.test"}),
        authorized_capabilities=frozenset({Capability.EMAIL_SEND}),
    )
    assert any(event.event_type is EventType.EXTERNAL_ACTION for event in trace.events)
