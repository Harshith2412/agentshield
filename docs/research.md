# Research artifact guide

## Question

Can runtime provenance, causal influence, explicit authority, and capability scopes prevent modeled unauthorized agent side effects even when untrusted data influences a proposal?

## Method

The deterministic corpus executes every attack in unprotected and protected modes, then runs benign cases protected. Framework comparison holds the scenario constant across adapter boundaries. Persistence experiments pause, reload, tamper, replay, and resume local traces. All effects are simulated and deterministic except reported local latency.

## Results and interpretation

For corpus version 1.0, 27/27 modeled attacks execute unprotected and 0/27 execute protected; 0/15 benign cases are withheld. Exact unambiguous attribution occurs in 26/27 attacks. These numbers validate implementation behavior for the checked-in corpus, not real-world prevalence or universal robustness.

## Reproduce

Use a clean Python 3.10+ environment, install the package, run `agentshield benchmark all --manifest reproduction.json`, and compare with `agentshield benchmark verify`. Record platform and optional dependencies from the manifest. See [benchmarks.md](benchmarks.md) for metric definitions and [threat-model.md](threat-model.md) for scope.

Local-model behavior is evaluated separately through the optional Stage 10 harness. Its propagation, resistance, and conditional mitigation metrics are not deterministic benchmark results; see [real-model-evaluation.md](real-model-evaluation.md).

## Stage 10 observation

Qwen3 4B and Llama 3.2 3B were evaluated locally with structured output over the 60-variant natural-language adversarial corpus. Model-level resistance was inconsistent: Qwen propagated the target action in 145/300 protected trials, while Llama propagated it in 24/57 valid protected responses. Six Llama generations were malformed and are excluded from resistance and mitigation counts.

AgentShield does not depend on the model recognizing an adversarial instruction. When an unauthorized action reached the instrumented runtime boundary, provenance, authority, and scope determined whether it could execute. AgentShield blocked 145/145 Qwen proposals and 24/24 Llama proposals; neither experiment produced a protected unauthorized execution. These controlled results do not establish universal attack coverage.
