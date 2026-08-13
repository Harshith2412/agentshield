"""Optional localhost Ollama indirect-injection experiment."""

import argparse

from agentshield.models import ModelSettings, ModelUnavailableError, OllamaAdapter
from agentshield.models.experiments import run_indirect_model_experiment


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--trials", type=int, default=1)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()
    try:
        report = run_indirect_model_experiment(
            OllamaAdapter(), ModelSettings(args.model, temperature=args.temperature, seed=args.seed), trials=args.trials
        )
    except ModelUnavailableError as exc:
        raise SystemExit(f"Ollama unavailable: {exc}") from exc
    print(report.render())


if __name__ == "__main__":
    main()
