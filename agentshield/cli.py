"""Small, offline-first command line interface for AgentShield."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import platform
import sqlite3
import sys
import tempfile
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Sequence

from agentshield import __version__
from agentshield.attacks.corpus import (
    ATTACK_CORPUS_VERSION,
    BENIGN_CORPUS_VERSION,
    corpus_hash,
)


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def environment_metadata() -> dict[str, Any]:
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
    }


def _dependency_versions() -> dict[str, str | None]:
    names = ("langgraph", "agent-framework-core")
    versions: dict[str, str | None] = {}
    for name in names:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    return versions


def _envelope(name: str, metrics: Any, failures: Any = (), limitations: Sequence[str] = ()) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "agentshield_version": __version__,
        "benchmark": name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": environment_metadata(),
        "dependencies": _dependency_versions(),
        "corpora": {
            "attack": {"version": ATTACK_CORPUS_VERSION, "sha256": corpus_hash("attack")},
            "benign": {"version": BENIGN_CORPUS_VERSION, "sha256": corpus_hash("benign")},
        },
        "configuration": {"seed": None, "network": False, "simulated_side_effects": True},
        "metrics": _jsonable(metrics),
        "failures": _jsonable(failures),
        "limitations": list(limitations),
    }


def run_benchmark_named(name: str) -> dict[str, Any]:
    if name == "deterministic":
        from agentshield.attacks.benchmark import run_benchmark

        result = run_benchmark()
        return _envelope(name, result.metrics, result.failures, (
            "Scripted local corpus; results do not establish universal attack coverage.",
        ))
    if name == "frameworks":
        from agentshield.integrations.comparison import run_framework_comparison

        result = run_framework_comparison()
        return _envelope(name, result, (), (
            "Controlled adapter harness; optional framework packages are not required by this benchmark.",
        ))
    if name == "persistence":
        from agentshield.persistence.scenarios import run_persistence_benchmark

        with tempfile.TemporaryDirectory(prefix="agentshield-benchmark-") as directory:
            result = run_persistence_benchmark(directory)
        return _envelope(name, result, (), (
            "Latency is host-dependent and excluded from deterministic regression checks.",
            "SQLite benchmark uses temporary local files.",
        ))
    raise ValueError(f"unknown benchmark: {name}")


def generate_baseline() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "agentshield_version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "benchmarks": {name: run_benchmark_named(name) for name in ("deterministic", "frameworks", "persistence")},
    }


def _stable_metrics(name: str, metrics: dict[str, Any]) -> dict[str, Any]:
    if name == "persistence":
        return {key: value for key, value in metrics.items() if not key.endswith("_latency_ms")}
    return metrics


def verify_baseline(path: Path) -> tuple[bool, list[str]]:
    expected = json.loads(path.read_text(encoding="utf-8"))
    differences: list[str] = []
    for name in ("deterministic", "frameworks", "persistence"):
        current = run_benchmark_named(name)["metrics"]
        baseline = expected["benchmarks"][name]["metrics"]
        left, right = _stable_metrics(name, baseline), _stable_metrics(name, current)
        if left != right:
            keys = sorted(set(left) | set(right))
            differences.extend(f"{name}.{key}: {left.get(key)!r} -> {right.get(key)!r}" for key in keys if left.get(key) != right.get(key))
    return not differences, differences


def _demo() -> int:
    from agentshield.attacks.corpus import load_attack_corpus
    from agentshield.runtime import ExecutionMode

    scenario = load_attack_corpus()[0]
    unprotected = scenario.run(ExecutionMode.UNPROTECTED)
    protected = scenario.run(ExecutionMode.PROTECTED)
    print("AgentShield Demo\n")
    print("Scenario: Indirect prompt injection")
    print("User authority: no EMAIL_SEND grant")
    print(f"Untrusted source: {scenario.expected_source}")
    print(f"Requested capability: {scenario.target_capability.value}")
    print(f"UNPROTECTED: {'simulated action executed' if unprotected.target_executed else 'not executed'}")
    print(f"PROTECTED: {'BLOCKED' if protected.blocked else 'allowed'}")
    print(f"Attribution: {protected.attribution.source_name if protected.attribution else 'unavailable'}")
    print("\nAll tools and side effects in this demo are simulated.")
    return 0


def _doctor() -> int:
    dependencies = _dependency_versions()
    ollama_status: object = "unavailable"
    ollama_models: object = ()
    experiment_ready = False
    try:
        from agentshield.models.ollama import OllamaAdapter

        info = OllamaAdapter(timeout=0.5).service_info()
        ollama_status = f"reachable ({info.get('version') or 'version unknown'})"
        ollama_models = tuple(item.get("name") for item in info["models"] if item.get("name"))
        experiment_ready = bool(ollama_models)
    except Exception as exc:
        ollama_status = f"unavailable ({type(exc).__name__})"
    checks = {
        "AgentShield": __version__,
        "Python": platform.python_version(),
        "Platform": platform.platform(),
        "LangGraph installed": dependencies["langgraph"] is not None,
        "Microsoft Agent Framework installed": dependencies["agent-framework-core"] is not None,
        "Ollama adapter available": _module_available("agentshield.models.ollama"),
        "Ollama service": ollama_status,
        "Local Ollama models": ollama_models or "none discovered",
        "Real-model experiments ready": experiment_ready,
        "SQLite": sqlite3.sqlite_version,
        "Persistence integrity": "SHA-256 and HMAC-SHA-256",
        "Telemetry": "disabled / none implemented",
    }
    print("AgentShield Doctor")
    for key, value in checks.items():
        print(f"{key}: {value}")
    return 0


def _module_available(name: str) -> bool:
    try:
        __import__(name)
        return True
    except ImportError:
        return False


def _optional_bool(value: str) -> bool | None:
    normalized = value.lower()
    if normalized in {"false", "off", "no", "0"}:
        return False
    if normalized in {"true", "on", "yes", "1"}:
        return True
    if normalized in {"default", "none"}:
        return None
    raise argparse.ArgumentTypeError("expected true, false, or default")


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _benchmark(args: argparse.Namespace) -> int:
    if args.name == "verify":
        path = Path(args.baseline)
        ok, differences = verify_baseline(path)
        print("BASELINE VERIFIED" if ok else "REGRESSION DETECTED")
        for difference in differences:
            print(difference)
        return 0 if ok else 1
    if args.name == "all":
        payload: Any = generate_baseline()
    else:
        payload = run_benchmark_named(args.name)
    if args.manifest:
        _write_json(Path(args.manifest), payload)
    if args.format == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        if args.name == "all":
            for name, result in payload["benchmarks"].items():
                print(f"{name}: {json.dumps(result['metrics'], sort_keys=True)}")
        else:
            print(f"AgentShield {args.name.title()} Benchmark")
            print(json.dumps(payload["metrics"], indent=2, sort_keys=True))
    return 0


def _conformance() -> int:
    from agentshield.integrations.comparison import conformance_for
    from agentshield.persistence.conformance import run_stage8_conformance

    for framework in ("langgraph", "microsoft_agent_framework"):
        report = conformance_for(framework)
        print(f"{framework}: {report.passed}/{len(report.tests)} passed")
    for target in ("native", "langgraph", "microsoft_agent_framework"):
        report = run_stage8_conformance(target)
        print(f"{report.target}: {report.passed}/{len(report.invariants)} persistence invariants passed")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentshield", description="Offline provenance-aware agent security tools")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("version", help="show AgentShield version")
    commands.add_parser("demo", help="run a safe simulated attack demonstration")
    commands.add_parser("doctor", help="inspect the local installation without telemetry")
    commands.add_parser("conformance", help="run framework and persistence conformance checks")
    experiment = commands.add_parser("experiment", help="run an explicit optional research experiment")
    experiment_commands = experiment.add_subparsers(dest="experiment_name", required=True)
    real_model = experiment_commands.add_parser("real-model", help="run paired trials against local Ollama")
    real_model.add_argument("--model", action="append", default=[], help="local Ollama model name; repeat to compare")
    real_model.add_argument("--models", nargs="+", default=[], help="one or more local Ollama model names")
    real_model.add_argument("--trials", type=int, default=5, help="trials per selected variant (default: 5)")
    real_model.add_argument("--temperature", type=float, default=0.0)
    real_model.add_argument("--seed", type=int, default=0)
    real_model.add_argument("--think", type=_optional_bool, default=False, help="true, false, or default (default: false)")
    real_model.add_argument("--max-tokens", type=int, default=256, help="maximum generated tokens (default: 256)")
    real_model.add_argument("--protocol-smoke", action="store_true", help="run only two structured-response protocol checks")
    real_model.add_argument("--families", nargs="*", help="optional attack-family subset")
    real_model.add_argument("--benign-limit", type=int, help="limit benign controls for an intentional short run")
    real_model.add_argument("--authorized-limit", type=int, help="select only this many explicitly authorized controls")
    real_model.add_argument("--format", choices=("text", "json"), default="text")
    real_model.add_argument("--output-dir", default="experiments/stage10", help="artifact directory")
    benchmark = commands.add_parser("benchmark", help="run controlled reproducible benchmarks")
    benchmark.add_argument("name", nargs="?", default="deterministic", choices=("deterministic", "frameworks", "persistence", "all", "verify"))
    benchmark.add_argument("--format", choices=("text", "json"), default="text")
    benchmark.add_argument("--manifest", help="write the complete result manifest as JSON")
    benchmark.add_argument("--baseline", default="benchmarks/baseline-v0.1.0.json")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "version":
        print(__version__)
        return 0
    if args.command == "demo":
        return _demo()
    if args.command == "doctor":
        return _doctor()
    if args.command == "conformance":
        return _conformance()
    if args.command == "experiment":
        return _experiment(args)
    if args.command == "benchmark":
        return _benchmark(args)
    parser.error("unknown command")
    return 2


def _experiment(args: argparse.Namespace) -> int:
    if args.experiment_name != "real-model":
        raise ValueError(f"unknown experiment: {args.experiment_name}")
    models = tuple(dict.fromkeys((*args.model, *args.models)))
    if not models:
        print("real-model experiment requires --model or --models", file=sys.stderr)
        return 2
    from agentshield.experiments.corpus import load_real_model_attack_corpus, load_real_model_benign_corpus
    from agentshield.experiments.real_model import run_protocol_smoke, run_real_model_experiment, write_experiment_artifacts
    from agentshield.models import ModelSettings, ModelUnavailableError, OllamaAdapter

    if args.max_tokens < 1:
        print("--max-tokens must be positive", file=sys.stderr)
        return 2
    attacks = load_real_model_attack_corpus()
    if args.families:
        requested = set(args.families)
        known = {item.family for item in attacks}
        unknown = requested - known
        if unknown:
            print(f"unknown attack families: {', '.join(sorted(unknown))}", file=sys.stderr)
            return 2
        attacks = tuple(item for item in attacks if item.family in requested)
    benign = load_real_model_benign_corpus()
    if args.benign_limit is not None:
        if args.benign_limit < 0:
            print("--benign-limit must be non-negative", file=sys.stderr)
            return 2
        benign = benign[:args.benign_limit]
    if args.authorized_limit is not None:
        if args.authorized_limit < 0:
            print("--authorized-limit must be non-negative", file=sys.stderr)
            return 2
        benign = tuple(item for item in load_real_model_benign_corpus() if item.control_kind == "authorized")[:args.authorized_limit]
        attacks = ()
    adapter = OllamaAdapter()
    try:
        info = adapter.service_info()
    except ModelUnavailableError as exc:
        print(f"Ollama unavailable: {exc}", file=sys.stderr)
        return 2
    discovered = {item.get("name"): item for item in info["models"]}
    experiments = []
    settings_by_model = {
        model: ModelSettings(
            model, temperature=args.temperature, seed=args.seed,
            think=args.think, max_tokens=args.max_tokens,
        )
        for model in models
    }
    if args.protocol_smoke:
        reports = [run_protocol_smoke(adapter, settings_by_model[model]) for model in models]
        if args.format == "json":
            print(json.dumps({"protocol_smoke": [_jsonable(item) for item in reports]}, indent=2, sort_keys=True))
        else:
            print("\n\n".join(item.render() for item in reports))
        return 0 if all(item.compatible for item in reports) else 1
    for model in models:
        detail = discovered.get(model, {})
        try:
            experiments.append(run_real_model_experiment(
                adapter, settings_by_model[model],
                trials_per_variant=args.trials, attacks=attacks, benign=benign,
                model_details={"ollama_version": info.get("version"), "model_digest": detail.get("digest")},
            ))
        except ModelUnavailableError as exc:
            print(f"Ollama experiment failed for {model}: {exc}", file=sys.stderr)
            return 2
    paths = write_experiment_artifacts(experiments, args.output_dir)
    if args.format == "json":
        print(json.dumps({"experiments": [item.to_dict(include_trials=False) for item in experiments], "artifacts": [str(path) for path in paths]}, indent=2, sort_keys=True))
    else:
        for index, experiment in enumerate(experiments):
            if index:
                print()
            print(experiment.render())
        print("\nArtifacts:")
        for path in paths:
            print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
