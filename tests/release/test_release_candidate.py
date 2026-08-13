"""Release-candidate contracts for public API, CLI, docs, and artifacts."""

from __future__ import annotations

import importlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

import agentshield
from agentshield import __version__
from agentshield.attacks.corpus import (
    ATTACK_CORPUS_VERSION,
    BENIGN_CORPUS_VERSION,
    corpus_hash,
)
from agentshield.cli import build_parser, main, run_benchmark_named, verify_baseline

ROOT = Path(__file__).parents[2]


@pytest.mark.parametrize("name", agentshield.__all__)
def test_public_exports_are_present(name):
    assert hasattr(agentshield, name)


@pytest.mark.parametrize(
    "name",
    (
        "AgentTask", "AuthorizationGrant", "ExecutionMode", "RunContext",
        "TrustBoundary", "InstrumentedExecutor", "AsyncInstrumentedExecutor",
        "ToolRegistry", "ToolRequest", "AuthorityLifetime",
    ),
)
def test_documented_runtime_exports_are_present(name):
    runtime = importlib.import_module("agentshield.runtime")
    assert name in runtime.__all__
    assert hasattr(runtime, name)


@pytest.mark.parametrize(
    ("argv", "expected"),
    (
        (("--help",), "Offline provenance-aware"),
        (("version",), "0.1.0"),
        (("demo",), "PROTECTED: BLOCKED"),
        (("doctor",), "Telemetry: disabled"),
        (("benchmark", "deterministic"), "Deterministic Benchmark"),
        (("benchmark", "frameworks"), "Frameworks Benchmark"),
        (("benchmark", "persistence"), "Persistence Benchmark"),
    ),
)
def test_cli_commands(argv, expected, capsys):
    if argv == ("--help",):
        with pytest.raises(SystemExit) as raised:
            main(argv)
        assert raised.value.code == 0
    else:
        assert main(argv) == 0
    assert expected in capsys.readouterr().out


@pytest.mark.parametrize(
    "path",
    (
        "README.md", "CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md",
        "CITATION.cff", "CHANGELOG.md", "docs/architecture.md",
        "docs/threat-model.md", "docs/security-model.md", "docs/quickstart.md",
        "docs/integrations.md", "docs/persistence.md", "docs/benchmarks.md",
        "docs/api-stability.md", "docs/research.md", "docs/responsible-use.md",
        "docs/release-checklist.md", ".github/pull_request_template.md",
    ),
)
def test_release_document_exists_and_is_nonempty(path):
    assert (ROOT / path).stat().st_size > 80


@pytest.mark.parametrize("kind,version", (("attack", "1.0"), ("benign", "1.0")))
def test_corpus_identity_is_stable(kind, version):
    expected = {
        "attack": "eede129d9bbde2ced023cea2be2076b31046ef66ea15b44baf8af279660f18e6",
        "benign": "1d79d95b50bb9731a1f49f4789fa40a3f640b9d7ff60eb654a330c3feb9578c4",
    }
    assert (ATTACK_CORPUS_VERSION if kind == "attack" else BENIGN_CORPUS_VERSION) == version
    assert corpus_hash(kind) == expected[kind]


@pytest.mark.parametrize("name", ("deterministic", "frameworks", "persistence"))
def test_benchmark_json_envelope(name):
    result = run_benchmark_named(name)
    assert result["agentshield_version"] == __version__
    assert result["benchmark"] == name
    assert result["configuration"]["network"] is False
    assert result["configuration"]["simulated_side_effects"] is True
    assert result["metrics"]
    json.dumps(result)


@pytest.mark.parametrize(
    "workflow",
    ("test.yml", "security.yml", "benchmark.yml", "release.yml"),
)
def test_workflow_is_present_and_least_privileged(workflow):
    text = (ROOT / ".github/workflows" / workflow).read_text(encoding="utf-8")
    assert "contents: read" in text
    assert "permissions:" in text


def test_version_has_one_authoritative_python_source():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'attr = "agentshield._version.__version__"' in pyproject
    assert 'version = "0.1.0"' not in pyproject
    assert __version__ == "0.1.0"


def test_distribution_identity_preserves_import_and_cli_names():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["name"] == "agentshield-provenance"
    assert __version__ == "0.1.0"
    assert agentshield.AgentShield
    assert project["scripts"]["agentshield"] == "agentshield.cli:main"


def test_project_urls_are_canonical():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["urls"] == {
        "Homepage": "https://github.com/Harshith2412/agentshield",
        "Repository": "https://github.com/Harshith2412/agentshield",
        "Issues": "https://github.com/Harshith2412/agentshield/issues",
        "Documentation": "https://github.com/Harshith2412/agentshield/tree/main/docs",
    }


def test_python_module_entrypoint_version():
    process = subprocess.run(
        [sys.executable, "-m", "agentshield", "--version"],
        cwd=ROOT, check=True, capture_output=True, text=True,
    )
    assert process.stdout.strip() == __version__


def test_baseline_is_reproducible():
    ok, differences = verify_baseline(ROOT / "benchmarks/baseline-v0.1.0.json")
    assert ok, differences


def test_baseline_sections_remain_separate():
    baseline = json.loads((ROOT / "benchmarks/baseline-v0.1.0.json").read_text(encoding="utf-8"))
    assert set(baseline["benchmarks"]) == {"deterministic", "frameworks", "persistence"}
    deterministic = baseline["benchmarks"]["deterministic"]["metrics"]
    assert deterministic["total_attack_variants"] == 27
    assert deterministic["attacks_successful_unprotected"] == 27
    assert deterministic["attacks_successful_protected"] == 0


def test_readme_quickstart_executes():
    from agentshield import AgentShield, Capability, EventType, SecurityEvent

    decision = AgentShield().evaluate(SecurityEvent(EventType.TOOL_REQUEST, "example", capability=Capability.EMAIL_SEND))
    assert decision.action.value == "block"


def test_markdown_local_links_resolve():
    failures = []
    for document in (ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))):
        for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", document.read_text(encoding="utf-8")):
            if "://" in target or target.startswith("#"):
                continue
            resolved = (document.parent / target.split("#", 1)[0]).resolve()
            if not resolved.exists():
                failures.append(f"{document.relative_to(ROOT)} -> {target}")
    assert not failures


def test_base_package_declares_no_runtime_dependencies():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "dependencies = []" in text


def test_cli_parser_has_expected_commands():
    help_text = build_parser().format_help()
    for command in ("version", "demo", "doctor", "benchmark", "conformance"):
        assert command in help_text


def test_no_developer_absolute_path_in_release_artifacts():
    candidates = [ROOT / "README.md", ROOT / "CITATION.cff", ROOT / "pyproject.toml"]
    candidates += list((ROOT / "docs").glob("*.md"))
    candidates += list((ROOT / "benchmarks").glob("*.json"))
    assert all("/Users/" not in path.read_text(encoding="utf-8") for path in candidates)


def test_final_real_model_publication_artifact_is_consistent():
    artifact = json.loads((ROOT / "benchmarks/real-model-v0.1.0.json").read_text(encoding="utf-8"))
    assert artifact["agentshield_version"] == __version__ == "0.1.0"
    assert artifact["corpora"]["attack"]["variants"] == 60
    models = {item["model"]: item for item in artifact["models"]}
    assert models["qwen3:4b"]["runtime_mitigation"] == {
        "blocked": 145, "rate": 1.0, "unauthorized_proposals": 145,
    }
    assert models["llama3.2:3b"]["runtime_mitigation"] == {
        "blocked": 24, "rate": 1.0, "unauthorized_proposals": 24,
    }
    assert models["qwen3:4b"]["protected"]["attack_successes"] == 0
    assert models["llama3.2:3b"]["protected"]["attack_successes"] == 0


def test_malformed_llama_generations_are_not_counted_as_resistance():
    artifact = json.loads((ROOT / "benchmarks/real-model-v0.1.0.json").read_text(encoding="utf-8"))
    llama = next(item for item in artifact["models"] if item["model"] == "llama3.2:3b")
    assert llama["generations"]["malformed"] == 6
    assert llama["protected"]["valid_attack_responses"] == 57
    assert llama["model_resistance"]["denominator"] == 57
    assert llama["propagation"]["count"] + llama["model_resistance"]["count"] == 57


def test_sdist_manifest_includes_release_research_materials():
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    for item in ("CHANGELOG.md", "CITATION.cff", "CONTRIBUTING.md", "SECURITY.md"):
        assert f"include {item}" in manifest
    assert "recursive-include docs *.md" in manifest
    assert "recursive-include benchmarks *.json" in manifest
    assert "prune experiments" in manifest
