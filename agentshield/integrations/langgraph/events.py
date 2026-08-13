"""Framework-aware trace rendering."""

from agentshield.core.events import EventType
from agentshield.runtime.instrumentation import ExecutionTrace


def render_langgraph_trace(trace: ExecutionTrace) -> str:
    decisions = {decision.event.id: decision for decision in trace.decisions}
    lines = ["AgentShield LangGraph Trace", "===========================", f"Graph run: {trace.run_id}", ""]
    for index, event in enumerate(trace.events, 1):
        framework_kind = event.metadata.get("framework_event")
        label = "NODE" if framework_kind in {"node_entry", "node_output", "graph_invocation"} else event.event_type.name
        lines.extend([f"[{index}] {label}", f"    source: {event.source}", f"    trust: {event.provenance.trust_level.name}"])
        if event.metadata.get("node"):
            lines.append(f"    node: {event.metadata['node']}")
        if event.metadata.get("framework_id"):
            lines.append(f"    framework_id: {event.metadata['framework_id']}")
        if event.capability:
            lines.append(f"    capability: {event.capability.name}")
        if event.metadata.get("tool"):
            lines.append(f"    tool: {event.metadata['tool']}")
        influence = trace.influences.get(event.id, ())
        if influence:
            lines.append("    influence: " + ", ".join(record.source_name for record in influence))
        if event.id in decisions:
            lines.append(f"    decision: {decisions[event.id].action.name}")
        lines.append("")
    lines.append(f"Tools executed: {len(trace.tools_executed)}")
    return "\n".join(lines)
