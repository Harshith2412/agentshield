"""Show protected enforcement of an unauthorized simulated shell request."""

from agentshield.runtime import AgentTask, DemoAgent


def main() -> None:
    trace = DemoAgent().run(
        "Perform the maintenance step.",
        task=AgentTask(tool="shell_execute", tool_arguments={"command": "maintenance --check"}),
    )
    print(trace.render())


if __name__ == "__main__":
    main()
