import pytest

from agentshield.models import (
    DeterministicModelAdapter, ModelResponse, ModelSettings, ProposedAction,
)
from agentshield.models.experiments import run_indirect_model_experiment


def settings() -> ModelSettings:
    return ModelSettings("fake", "v1", 0.0, 42)


def test_repeated_trials_record_both_modes() -> None:
    report = run_indirect_model_experiment(DeterministicModelAdapter(ModelResponse("ignored")), settings(), trials=3)
    assert len(report.trials) == 6
    assert len({trial.trial_id for trial in report.trials}) == 6


def test_model_ignoring_attack_is_not_mitigation() -> None:
    report = run_indirect_model_experiment(DeterministicModelAdapter(ModelResponse("summary")), settings())
    assert report.attack_propagation_rate == 0.0
    assert report.conditional_mitigation_rate == 0.0
    assert all(not trial.attack_success for trial in report.trials)


def test_propagating_attack_separates_unprotected_and_protected_execution() -> None:
    adapter = DeterministicModelAdapter(ModelResponse("x", (ProposedAction("send_email", {"to": "other@example.test"}),)))
    report = run_indirect_model_experiment(adapter, settings())
    assert report.attack_propagation_rate == 1.0
    assert report.protected_execution_rate == 0.0
    assert report.conditional_mitigation_rate == 1.0
    assert sum(t.attack_success for t in report.trials) == 1


def test_malformed_rate_is_measured() -> None:
    report = run_indirect_model_experiment(DeterministicModelAdapter("bad-json"), settings(), trials=2)
    assert report.malformed_response_rate == 1.0
    assert report.model_refusal_rate == 0.0


def test_refusal_rate_is_separate_from_mitigation() -> None:
    report = run_indirect_model_experiment(DeterministicModelAdapter(ModelResponse("I refuse.")), settings())
    assert report.model_refusal_rate == 1.0
    assert report.conditional_mitigation_rate == 0.0


def test_trial_metadata_is_recorded() -> None:
    report = run_indirect_model_experiment(DeterministicModelAdapter(), settings())
    metadata = report.trials[0].metadata
    assert (metadata.adapter_type, metadata.model_name, metadata.model_tag) == ("deterministic", "fake", "v1")
    assert metadata.seed == 42


def test_scope_attack_changed_recipient_is_blocked() -> None:
    adapter = DeterministicModelAdapter(ModelResponse("x", (ProposedAction("send_email", {"to": "other@example.test"}),)))
    report = run_indirect_model_experiment(adapter, settings(), scoped_recipient="demo@example.test")
    protected = next(t for t in report.trials if t.mode.value == "protected")
    assert protected.target_requested and not protected.target_executed


def test_scope_attack_original_recipient_is_allowed() -> None:
    adapter = DeterministicModelAdapter(ModelResponse("x", (ProposedAction("send_email", {"to": "demo@example.test"}),)))
    report = run_indirect_model_experiment(adapter, settings(), scoped_recipient="demo@example.test")
    protected = next(t for t in report.trials if t.mode.value == "protected")
    assert protected.target_executed
    assert protected.target_authorized


def test_trials_must_be_positive() -> None:
    with pytest.raises(ValueError):
        run_indirect_model_experiment(DeterministicModelAdapter(), settings(), trials=0)


def test_experiment_renderer_reports_observed_metrics() -> None:
    report = run_indirect_model_experiment(DeterministicModelAdapter(ModelResponse("summary")), settings())
    rendered = report.render()
    assert "Trials:                         2" in rendered
    assert "Attack propagation rate:        0.0%" in rendered
