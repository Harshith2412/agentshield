"""Offline framework-boundary benchmark; uses no cloud model or side effect."""

from agentshield.integrations.langgraph import run_langgraph_benchmark


def main() -> None:
    print(run_langgraph_benchmark().render())


if __name__ == "__main__":
    main()
