# Changelog

All notable changes are documented here. This project follows semantic versioning after the `0.1.0` release.

## 0.1.0

### Core

- Deterministic provenance, risk, policy, influence, authority, and capability-scope evaluation.
- Stabilized top-level public API and offline standard-library CLI.

### Runtime security

- Protected synchronous, asynchronous, concurrent, and streamed proposal enforcement.
- Scoped, run-bound, checkpoint-bound, one-shot, and expiring authorization grants.

### Attacks and benchmarks

- Versioned controlled indirect-injection, malicious-tool-output, memory-poisoning, multihop, and benign corpora.
- Machine-readable deterministic, framework, and persistence benchmarks with baseline verification.
- Controlled local-model evaluation with Qwen3 4B and Llama 3.2 3B, reporting model resistance separately from runtime mitigation.

### Framework integrations

- Experimental LangGraph and Microsoft Agent Framework adapters with shared conformance invariants.

### Persistence

- Experimental SQLite provenance, SHA-256 or HMAC integrity, redaction, checkpoint lineage, stale-checkpoint protection, and replay resistance.

### Release engineering

- Packaging metadata, CI/release workflows, security tooling, SBOM generation, research documentation, and contributor guidance.
- Optional Stage 10 local-Ollama adversarial experiment infrastructure with versioned natural-language corpora and separate model-resistance/runtime-mitigation metrics.
