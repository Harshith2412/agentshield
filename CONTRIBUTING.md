# Contributing to AgentShield

AgentShield welcomes defensive security research and careful engineering contributions. By participating, follow the [Code of Conduct](CODE_OF_CONDUCT.md) and [responsible-use guidance](docs/responsible-use.md).

## Development setup

```bash
python -m venv .venv
.venv/bin/python -m pip install -e '.[dev,release]'
.venv/bin/python -m pytest -q
```

The architecture flows from neutral core contracts through runtime enforcement; framework and persistence packages sit at experimental boundaries. Read [architecture.md](docs/architecture.md), [security-model.md](docs/security-model.md), and [API stability](docs/api-stability.md) first.

## Changes

- Detectors and policies need focused unit tests for allow, block, provenance loss, and false positives.
- Attack variants must remain controlled, name an expected source/capability/outcome, include a benign counterexample where useful, and never perform real side effects.
- Framework adapters must pass the complete shared conformance suite. A happy-path integration demo is not sufficient.
- Benchmark changes must explain metric semantics and corpus-version impact. Never update a baseline to conceal a regression.
- New authority or provenance assumptions must be documented in the threat and security models.

Prefer clear typed Python, small changes, standard-library solutions where practical, and no unrelated formatting churn. Run tests, Ruff, Bandit, benchmarks, and relevant optional-extra checks before submitting.

## Pull requests

Describe the change, security implications, compatibility, tests, benchmark impact, and documentation. Integration changes must report conformance results. Do not commit credentials, databases, local paths, generated environments, model downloads, or external-service data. Security vulnerabilities belong in private reporting, not a pull request or public issue.
