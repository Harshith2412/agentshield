"""Run a benign local retrieval through the protected harness."""

from agentshield.runtime import DemoAgent, Document, DocumentStore, TrustBoundary


def main() -> None:
    agent = DemoAgent(documents=DocumentStore((Document(
        "project_notes.txt",
        "AgentShield tracks provenance and evaluates capabilities at runtime boundaries.",
        TrustBoundary.LOCAL_TRUSTED,
    ),)))
    print(agent.run("Read the project notes and summarize them.").render())


if __name__ == "__main__":
    main()
