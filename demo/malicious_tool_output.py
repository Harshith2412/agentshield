"""Compare the controlled compromised-tool-output scenario in both modes."""

from agentshield.attacks import MaliciousToolOutput, evaluate_pair


def main() -> None:
    print(evaluate_pair(MaliciousToolOutput()).render())


if __name__ == "__main__":
    main()
