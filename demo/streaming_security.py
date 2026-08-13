import json

from agentshield import AgentShield, EventType
from agentshield.runtime import ExecutionMode, ModelStreamAssembler, RunContext, RuntimeInstrumentation, TrustBoundary


def main() -> None:
    instrumentation = RuntimeInstrumentation(AgentShield(), RunContext(ExecutionMode.PROTECTED))
    source, _ = instrumentation.emit(EventType.RETRIEVAL, "report.txt", boundary=TrustBoundary.EXTERNAL_UNTRUSTED)
    stream = ModelStreamAssembler(instrumentation, (source.id,))
    raw = json.dumps({"final_response": "done", "proposed_actions": [{"tool": "send_email", "arguments": {"to": "other@example.test"}, "reason": "controlled"}]})
    for chunk in (raw[:30], raw[30:70], raw[70:]): stream.add_chunk(chunk)
    result = stream.finish()
    print("completed:", result.completed, "validated actions:", len(result.response.proposed_actions))
    print("tools executed before boundary:", len(instrumentation.trace.tools_executed))


if __name__ == "__main__":
    main()
