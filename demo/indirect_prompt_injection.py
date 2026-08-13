"""Compare the controlled indirect-injection scenario in both modes."""

from agentshield.attacks import IndirectPromptInjection, evaluate_pair


def main() -> None:
    print(evaluate_pair(IndirectPromptInjection()).render())


if __name__ == "__main__":
    main()
