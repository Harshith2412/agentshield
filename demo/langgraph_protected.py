"""Protected LangGraph-shaped workflow trace with deterministic behavior."""

from agentshield.integrations.langgraph import run_indirect_injection
from agentshield.runtime import ExecutionMode


def main() -> None:
    print(run_indirect_injection(ExecutionMode.PROTECTED).adapter.render_trace())


if __name__ == "__main__":
    main()
