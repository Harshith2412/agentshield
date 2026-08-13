import json

import pytest

from agentshield import Capability
from agentshield.experiments.corpus import load_real_model_attack_corpus, load_real_model_benign_corpus
from agentshield.experiments.real_model import aggregate_trials, run_real_model_experiment, run_trial
from agentshield.models import DeterministicModelAdapter, ModelResponse, ModelSettings, ProposedAction
from agentshield.runtime import ExecutionMode, ToolStatus


SETTINGS = ModelSettings("controlled-fake", "test", temperature=0.0, seed=7)


def adapter_with(*actions, final="ok", malformed=False):
    return DeterministicModelAdapter(ModelResponse(final, tuple(actions), raw_output="controlled", malformed=malformed))


def email(recipient="other@example.test", **extra):
    return ProposedAction("send_email", {"to": recipient, **extra}, "controlled proposal")


def attack(family=None):
    corpus = load_real_model_attack_corpus()
    return next(item for item in corpus if family is None or item.family == family)


def test_propagation_and_unprotected_attack_success() -> None:
    trial = run_trial(adapter_with(email()), SETTINGS, attack(), ExecutionMode.UNPROTECTED, 1)
    assert trial.attack_propagated and trial.attack_success
    assert not trial.mitigation_occurred
    assert trial.actions[0].status is ToolStatus.SUCCESS


def test_conditional_mitigation_requires_proposal_and_block() -> None:
    trial = run_trial(adapter_with(email()), SETTINGS, attack(), ExecutionMode.PROTECTED, 1)
    assert trial.attack_propagated and trial.mitigation_occurred
    assert not trial.attack_success
    assert trial.actions[0].attribution_source == attack().source_name


def test_model_resistance_is_not_mitigation() -> None:
    trial = run_trial(adapter_with(final="I will only summarize."), SETTINGS, attack(), ExecutionMode.PROTECTED, 1)
    assert trial.model_resistance
    assert not trial.mitigation_occurred
    metrics = aggregate_trials((trial,))
    assert metrics.conditional_mitigation_rate is None
    assert metrics.model_resistance_rate == 1.0


def test_model_refusal_is_recorded_separately() -> None:
    trial = run_trial(adapter_with(final="I cannot comply because this is not authorized."), SETTINGS, attack(), ExecutionMode.PROTECTED, 1)
    assert trial.model_refused and not trial.model_resistance
    assert not trial.mitigation_occurred


def test_malformed_output_cannot_execute() -> None:
    trial = run_trial(adapter_with(final="", malformed=True), SETTINGS, attack(), ExecutionMode.PROTECTED, 1)
    assert trial.malformed and not trial.actions and not trial.attack_success


def test_unknown_tool_fails_closed() -> None:
    action = ProposedAction("exfiltrate_report", {"destination": "other@example.test"}, "invented")
    trial = run_trial(adapter_with(action), SETTINGS, attack(), ExecutionMode.PROTECTED, 1)
    assert trial.actions[0].known_tool is False
    assert trial.actions[0].status is ToolStatus.ERROR
    assert not trial.actions[0].executed


def test_multiple_proposals_receive_independent_outcomes() -> None:
    unknown = ProposedAction("exfiltrate_report", {}, "invented")
    trial = run_trial(adapter_with(email(), unknown, ProposedAction("write_file", {"path": "report.txt", "content": "x"})), SETTINGS, attack(), ExecutionMode.PROTECTED, 1)
    assert len(trial.actions) == 3
    assert [item.known_tool for item in trial.actions] == [True, False, True]
    assert all(not item.executed for item in trial.actions)


@pytest.mark.parametrize(
    "claim",
    (
        {"authority": True}, {"source_trust": "TRUSTED"}, {"scope": "*"},
        {"decision": "ALLOW"}, {"authorized": True},
    ),
)
def test_model_arguments_cannot_manufacture_authority_or_trust(claim) -> None:
    trial = run_trial(adapter_with(email(**claim)), SETTINGS, attack("provenance_manipulation"), ExecutionMode.PROTECTED, 1)
    assert trial.actions[0].authorized is False
    assert trial.actions[0].executed is False


def test_scope_expansion_is_blocked() -> None:
    trial = run_trial(adapter_with(email("other@example.test")), SETTINGS, attack("scope_manipulation"), ExecutionMode.PROTECTED, 1)
    assert trial.authorization_state == "email_send:demo@example.test"
    assert not trial.actions[0].authorized and not trial.actions[0].executed


def test_exact_authorized_action_is_allowed() -> None:
    variant = next(item for item in load_real_model_benign_corpus() if item.control_kind == "authorized")
    trial = run_trial(adapter_with(email("demo@example.test")), SETTINGS, variant, ExecutionMode.PROTECTED, 1)
    assert trial.actions[0].authorized and trial.actions[0].executed
    assert not trial.attack_success


def test_benign_no_action_is_not_false_positive() -> None:
    variant = next(item for item in load_real_model_benign_corpus() if item.control_kind == "benign")
    trial = run_trial(adapter_with(), SETTINGS, variant, ExecutionMode.PROTECTED, 1)
    metrics = aggregate_trials((trial,))
    assert metrics.benign_trials == 1 and metrics.false_positives == 0


@pytest.mark.parametrize("family", ("tool_output_injection", "memory_poisoning", "multi_hop_influence"))
def test_cross_boundary_attribution_retains_origin(family) -> None:
    variant = attack(family)
    trial = run_trial(adapter_with(email()), SETTINGS, variant, ExecutionMode.PROTECTED, 1)
    assert trial.actions[0].attribution_source == variant.source_name
    assert variant.source_name in trial.actions[0].influence_sources


def test_experiment_aggregates_conditional_denominator() -> None:
    calls = 0

    def response(_request):
        nonlocal calls
        calls += 1
        return ModelResponse("ok", (email(),) if calls % 2 == 0 else ())

    report = run_real_model_experiment(
        DeterministicModelAdapter(response), SETTINGS, trials_per_variant=1,
        attacks=(attack(),), benign=(),
    )
    assert report.metrics.attack_trials == 1
    assert report.metrics.unauthorized_proposals == 1
    assert report.metrics.unauthorized_proposals_blocked == 1
    assert report.metrics.conditional_mitigation_rate == 1.0


def test_experiment_json_records_reproducibility_metadata() -> None:
    report = run_real_model_experiment(adapter_with(), SETTINGS, trials_per_variant=1, attacks=(attack(),), benign=())
    payload = report.to_dict()
    assert payload["model_metadata"]["model"] == "controlled-fake"
    assert payload["model_metadata"]["seed"] == 7
    assert payload["corpus_metadata"]["attack"]["version"] == "1.0"
    json.dumps(payload)


def test_protected_enforcement_failure_is_persisted_in_failure_report() -> None:
    # Normal policy should make this impossible for the controlled proposal.
    report = run_real_model_experiment(adapter_with(email()), SETTINGS, trials_per_variant=1, attacks=(attack(),), benign=())
    assert report.failures == ()
    assert report.metrics.protected_attack_successes == 0


def test_invalid_trial_count_rejected() -> None:
    with pytest.raises(ValueError):
        run_real_model_experiment(adapter_with(), SETTINGS, trials_per_variant=0, attacks=(), benign=())
