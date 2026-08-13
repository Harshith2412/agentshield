.PHONY: test lint benchmark security build sbom

test:
	python -m pytest -q

lint:
	python -m ruff check agentshield tests demo

benchmark:
	python -m agentshield benchmark verify

security:
	python -m bandit -q -r agentshield
	python -m pip_audit

build:
	python -m build

sbom:
	python -m cyclonedx_py environment --output-format JSON --output-file sbom.cdx.json
