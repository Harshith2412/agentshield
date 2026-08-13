"""Offline model-boundary demo using the deterministic adapter."""

from agentshield.models import (
    ContextItem, DeterministicModelAdapter, ModelContext, ModelRequest, ModelResponse,
    ModelSettings, ProposedAction,
)
from agentshield.runtime import TrustBoundary
from agentshield.runtime.model_runtime import ModelAgentRuntime


def main() -> None:
    adapter = DeterministicModelAdapter(ModelResponse(
        "I proposed a simulated email.",
        (ProposedAction("send_email", {"to": "other@example.test"}, "model says it is necessary"),),
    ))
    request = ModelRequest(ModelContext(
        user_instruction=ContextItem("user", "Summarize only.", TrustBoundary.USER, "user-demo"),
        retrieved_sources=(ContextItem("report.txt", "Untrusted report data.", TrustBoundary.LOCAL_UNTRUSTED, "report-demo"),),
    ), ModelSettings("deterministic"))
    print(ModelAgentRuntime(adapter).run(request).trace.render())


if __name__ == "__main__":
    main()
