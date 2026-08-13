from agentshield import Capability, EventType
from agentshield.runtime import AgentTask, DemoAgent


def test_trace_contains_required_collections() -> None:
    trace = DemoAgent().run("Nothing")
    assert trace.run_id
    assert trace.events
    assert trace.decisions
    assert isinstance(trace.tools_requested, list)
    assert isinstance(trace.tools_executed, list)
    assert isinstance(trace.tools_blocked, list)


def test_trace_renderer_is_human_readable() -> None:
    rendered = DemoAgent().run("Nothing").render()
    assert "AgentShield Execution Trace" in rendered
    assert "[1] USER_INPUT" in rendered
    assert "decision: ALLOW" in rendered
    assert "final:" in rendered


def test_trace_renderer_includes_tool_and_risk() -> None:
    trace = DemoAgent().run(
        "Send",
        task=AgentTask(tool="send_email", tool_arguments={"to": "a@example.test"}),
        authorized_capabilities=frozenset({Capability.EMAIL_SEND}),
    )
    rendered = trace.render()
    assert "tool: send_email" in rendered
    assert "capability: EMAIL_SEND" in rendered
    assert "risk:" in rendered


def test_full_provenance_chain_reconstructs_runtime_flow() -> None:
    trace = DemoAgent().run(
        "Send",
        task=AgentTask(tool="send_email", tool_arguments={"to": "a@example.test"}),
        authorized_capabilities=frozenset({Capability.EMAIL_SEND}),
    )
    final = trace.events[-1]
    chain = trace.propagation_chain(final.id)
    assert chain[0].event_type is EventType.USER_INPUT
    assert chain[-1] is final
    assert any(event.event_type is EventType.TOOL_REQUEST for event in chain)
    assert any(event.event_type is EventType.EXTERNAL_ACTION for event in chain)
    assert len(chain) >= 5
