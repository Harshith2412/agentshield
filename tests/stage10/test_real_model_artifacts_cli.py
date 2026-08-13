import json

import pytest

from agentshield.cli import main
from agentshield.experiments.corpus import load_real_model_attack_corpus
from agentshield.experiments.real_model import run_real_model_experiment, write_experiment_artifacts
from agentshield.models import DeterministicModelAdapter, ModelResponse, ModelSettings
from agentshield.models.ollama import OllamaAdapter


def report():
    return run_real_model_experiment(
        DeterministicModelAdapter(ModelResponse("summary")), ModelSettings("fake-a"),
        trials_per_variant=1, attacks=load_real_model_attack_corpus()[:1], benign=(),
    )


def test_artifacts_are_separate_and_machine_readable(tmp_path) -> None:
    paths = write_experiment_artifacts((report(),), tmp_path)
    assert len(paths) == 3
    assert any(path.name.startswith("results-fake-a-") for path in paths)
    assert any(path.name.startswith("failures-fake-a-") for path in paths)
    assert any(path.name.startswith("manifest-") for path in paths)
    assert all(json.loads(path.read_text()) is not None for path in paths)


def test_multi_model_artifact_manifest(tmp_path) -> None:
    first = report()
    second = run_real_model_experiment(
        DeterministicModelAdapter(ModelResponse("summary")), ModelSettings("fake-b"),
        trials_per_variant=1, attacks=load_real_model_attack_corpus()[:1], benign=(),
    )
    manifest = write_experiment_artifacts((first, second), tmp_path)[-1]
    assert len(json.loads(manifest.read_text())["experiments"]) == 2


def test_cli_requires_explicit_model(capsys) -> None:
    assert main(("experiment", "real-model")) == 2
    assert "requires --model" in capsys.readouterr().err


def test_cli_rejects_unknown_family_before_model_call(capsys) -> None:
    assert main(("experiment", "real-model", "--model", "fake", "--families", "missing")) == 2
    assert "unknown attack families" in capsys.readouterr().err


def test_ollama_endpoint_is_loopback_only() -> None:
    with pytest.raises(ValueError):
        OllamaAdapter("https://models.example.com")


def test_ollama_unavailable_is_clean(monkeypatch) -> None:
    from urllib.error import URLError

    monkeypatch.setattr("agentshield.models.ollama.urlopen", lambda *args, **kwargs: (_ for _ in ()).throw(URLError("offline")))
    with pytest.raises(Exception, match="local Ollama service unavailable"):
        OllamaAdapter(timeout=0.01).service_info()


def test_ordinary_suite_has_no_ollama_marker_requirement() -> None:
    # Live tests are opt-in; this infrastructure test invokes no service.
    assert report().model_metadata["adapter"] == "deterministic"
