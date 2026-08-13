"""Run an explicitly authorized, simulated email action."""

from agentshield import Capability
from agentshield.runtime import AgentTask, DemoAgent


def main() -> None:
    trace = DemoAgent().run(
        "Send the approved project update by email.",
        task=AgentTask(tool="send_email", tool_arguments={
            "to": "research@example.test",
            "subject": "Project update",
            "body": "The controlled demo completed.",
        }),
        authorized_capabilities=frozenset({Capability.EMAIL_SEND}),
    )
    print(trace.render())


if __name__ == "__main__":
    main()
