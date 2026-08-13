from agentshield.integrations.comparison import conformance_for, run_framework_comparison


def main() -> None:
    print(run_framework_comparison().render())
    print()
    print(conformance_for("langgraph").render())
    print()
    print(conformance_for("microsoft_agent_framework").render())


if __name__ == "__main__":
    main()
