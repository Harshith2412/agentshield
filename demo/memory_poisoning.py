"""Compare the controlled memory-poisoning scenario in both modes."""

from agentshield.attacks import MemoryPoisoning, evaluate_pair


def main() -> None:
    print(evaluate_pair(MemoryPoisoning()).render())


if __name__ == "__main__":
    main()
