"""Run all Stage 3 paired controlled experiments."""

from agentshield.attacks import run_attack_suite


def main() -> None:
    print(run_attack_suite().render())


if __name__ == "__main__":
    main()
