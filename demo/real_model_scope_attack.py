"""Optional localhost Ollama recipient-scope experiment."""

import argparse

from agentshield.models import ModelSettings, ModelUnavailableError, OllamaAdapter
from agentshield.models.experiments import run_indirect_model_experiment


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--trials", type=int, default=1)
    args = parser.parse_args()
    try:
        report = run_indirect_model_experiment(
            OllamaAdapter(), ModelSettings(args.model), trials=args.trials, scoped_recipient="demo@example.test"
        )
    except ModelUnavailableError as exc:
        raise SystemExit(f"Ollama unavailable: {exc}") from exc
    print(report.render())


if __name__ == "__main__":
    main()
