from agentshield import Capability, EventType
from agentshield.core.provenance import TrustLevel
from agentshield.integrations.langgraph import (
    FrameworkSource, LangGraphAdapter, LangGraphStateBridge, ToolSecurityMetadata,
    run_multinode,
)
from agentshield.runtime import TrustBoundary


def test_state_bridge_retains_structured_categories() -> None:
    bridge = LangGraphStateBridge(
        user_instruction=FrameworkSource("user", "x", TrustBoundary.USER, "u"),
        retrieved_sources=[FrameworkSource("doc", "x", TrustBoundary.LOCAL_UNTRUSTED, "r")],
        memories=[FrameworkSource("memory", "x", TrustBoundary.MEMORY, "m")],
        tool_outputs=[FrameworkSource("tool", "x", TrustBoundary.TOOL, "t")],
    )
    adapter = LangGraphAdapter(bridge=bridge)
    adapter.ingest_state({"agentshield_bridge": bridge})
    assert len(bridge.event_ids) == 4


def test_framework_ids_are_metadata_not_event_ids() -> None:
    bridge = LangGraphStateBridge(user_instruction=FrameworkSource("user", "x", TrustBoundary.USER, "framework-id"))
    adapter = LangGraphAdapter(bridge=bridge)
    adapter.ingest_state({"agentshield_bridge": bridge})
    event = next(e for e in adapter.trace.events if e.metadata.get("framework_id") == "framework-id")
    assert event.id != "framework-id"


def test_untrusted_retrieval_influence_reaches_tool_request() -> None:
    result = run_multinode()
    target = next(e for e in result.adapter.trace.events if e.event_type is EventType.TOOL_REQUEST)
    assert target.provenance.trust_level is TrustLevel.UNTRUSTED
    assert any(record.source_name == "multihop_report.txt" for record in result.adapter.trace.influence_set(target.id))


def test_node_instrumentation_records_entry_and_output() -> None:
    result = run_multinode()
    framework_events = [e.metadata.get("framework_event") for e in result.adapter.trace.events]
    assert "node_entry" in framework_events and "node_output" in framework_events


def test_multinode_chain_contains_all_nodes() -> None:
    result = run_multinode()
    target = next(e for e in result.adapter.trace.events if e.event_type is EventType.TOOL_REQUEST)
    chain = result.adapter.trace.propagation_chain(target.id)
    nodes = {e.metadata.get("node") for e in chain}
    assert {"retrieval", "summarizer", "memory", "planner"}.issubset(nodes)


def test_multinode_attribution_selects_original_document() -> None:
    result = run_multinode()
    assert result.attribution.source_name == "multihop_report.txt"


def test_repeated_state_ingestion_does_not_duplicate_sources() -> None:
    bridge = LangGraphStateBridge(user_instruction=FrameworkSource("user", "x", TrustBoundary.USER, "u"))
    adapter = LangGraphAdapter(bridge=bridge)
    state = {"agentshield_bridge": bridge}
    adapter.ingest_state(state)
    count = len(adapter.trace.events)
    adapter.ingest_state(state)
    assert len(adapter.trace.events) == count


def test_conditional_route_name_does_not_grant_trust() -> None:
    bridge = LangGraphStateBridge(retrieved_sources=[FrameworkSource("doc", "x", TrustBoundary.LOCAL_UNTRUSTED, "r")])
    adapter = LangGraphAdapter(bridge=bridge)
    adapter.instrument_node("safe", lambda state: state)({"agentshield_bridge": bridge})
    tool = adapter.register_tool("send_email", ToolSecurityMetadata(Capability.EMAIL_SEND, True))
    assert not tool.invoke({"to": "x.test"}, {"agentshield_bridge": bridge}).executed


def test_framework_trace_renderer_contains_nodes_and_decision() -> None:
    rendered = run_multinode().adapter.render_trace()
    assert "AgentShield LangGraph Trace" in rendered
    assert "node: planner" in rendered
    assert "decision: BLOCK" in rendered


def test_node_output_is_causal_parent_of_next_node() -> None:
    result = run_multinode()
    events = result.adapter.trace.events
    summarizer_entry = next(e for e in events if e.metadata.get("node") == "summarizer" and e.metadata.get("framework_event") == "node_entry")
    retrieval_output = next(e for e in events if e.metadata.get("node") == "retrieval" and e.metadata.get("framework_event") == "node_output")
    assert retrieval_output.id in summarizer_entry.parent_ids


def test_tool_request_descends_from_final_planner_output() -> None:
    result = run_multinode()
    events = result.adapter.trace.events
    planner_output = next(e for e in events if e.metadata.get("node") == "planner" and e.metadata.get("framework_event") == "node_output")
    request = next(e for e in events if e.event_type is EventType.TOOL_REQUEST)
    assert request.parent_ids == (planner_output.id,)
