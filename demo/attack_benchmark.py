"""Run the complete Stage 4 controlled benchmark."""

from agentshield.attacks.benchmark import run_benchmark


def main() -> None:
    print(run_benchmark().render())


if __name__ == "__main__":
    main()
