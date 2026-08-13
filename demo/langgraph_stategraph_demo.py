"""Optional real StateGraph orchestration with AgentShield node wrappers."""

from typing import TypedDict

from agentshield.integrations.langgraph import FrameworkSource, LangGraphAdapter, LangGraphStateBridge, LangGraphUnavailableError
from agentshield.runtime import TrustBoundary


class GraphState(TypedDict):
    agentshield_bridge: LangGraphStateBridge
    summary: str


def main() -> None:
    adapter = LangGraphAdapter(bridge=LangGraphStateBridge(
        user_instruction=FrameworkSource("user", "Summarize project notes.", TrustBoundary.USER, "real-lg-user"),
        retrieved_sources=[FrameworkSource("notes.txt", "Controlled local notes.", TrustBoundary.LOCAL_TRUSTED, "real-lg-doc")],
    ))

    def build(StateGraph, current):
        from langgraph.graph import END, START
        graph = StateGraph(GraphState)
        graph.add_node("retrieve_document", current.instrument_node("retrieve_document", lambda state: state))
        graph.add_node("agent_decision", current.instrument_node("agent_decision", lambda state: {**state, "summary": "Controlled summary."}))
        graph.add_edge(START, "retrieve_document")
        graph.add_edge("retrieve_document", "agent_decision")
        graph.add_edge("agent_decision", END)
        return graph.compile()

    try:
        graph = adapter.compile_graph(build)
    except LangGraphUnavailableError as exc:
        raise SystemExit(str(exc)) from exc
    graph.invoke({"agentshield_bridge": adapter.bridge, "summary": ""})
    print(adapter.render_trace())


if __name__ == "__main__":
    main()
