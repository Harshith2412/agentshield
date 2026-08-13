# Benchmarks and reproducibility

AgentShield has three separate benchmark families:

1. `deterministic`: 27 controlled attack variants and 15 benign scenarios; reports execution, mitigation, detection, false positives, and attribution.
2. `frameworks`: compares the same controlled adapter scenario and scope behavior across LangGraph and Microsoft boundaries.
3. `persistence`: exercises async consistency, concurrency, stream assembly, reload attribution, integrity, replay, and stale checkpoints. Local timings are descriptive, not regression thresholds.

The optional **real-model adversarial experiment** is a fourth, separate research identity. Its outcomes are nondeterministic and never merged into the controlled benchmark headline or used as blocking CI thresholds. See [real-model-evaluation.md](real-model-evaluation.md).

Run `agentshield benchmark all --manifest results.json`. The JSON records version, UTC timestamp, environment, optional dependency versions, corpus versions and hashes, configuration, metrics, failures, and limitations. No network or real side effect is used.

`agentshield benchmark verify` reruns deterministic fields against `benchmarks/baseline-v0.1.0.json`. Host-dependent persistence latency is deliberately excluded. The command never updates the baseline.
