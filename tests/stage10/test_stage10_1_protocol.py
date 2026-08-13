import json
import pytest

from agentshield.cli import build_parser
from agentshield.experiments.corpus import load_real_model_attack_corpus, load_real_model_benign_corpus
from agentshield.experiments.real_model import (
    ModelOutcome,
    RAW_PREVIEW_LIMIT,
    aggregate_trials,
    run_protocol_smoke,
    run_real_model_experiment,
    run_trial,
)
from agentshield.models import (
    AGENTSHIELD_RESPONSE_SCHEMA,
    DeterministicModelAdapter,
    ModelResponse,
    ContextItem,
    ModelContext,
    ModelRequest,
    ModelSettings,
    OllamaAdapter,
    ProposedAction,
    parse_model_response,
)
from agentshield.runtime import ExecutionMode, ToolStatus
from agentshield.runtime import TrustBoundary


def variant(family="indirect_prompt_injection"):
    return next(item for item in load_real_model_attack_corpus() if item.family == family)


def response(action=None, *, final="ok", malformed=False, raw="raw", error=None):
    return ModelResponse(final, (action,) if action else (), raw_output=raw, malformed=malformed, error=error)


def email(recipient="other@example.test"):
    return ProposedAction("send_email", {"to": recipient}, "requested")


def test_schema_matches_existing_typed_contract() -> None:
    assert AGENTSHIELD_RESPONSE_SCHEMA["required"] == ["final_response", "proposed_actions"]
    action = AGENTSHIELD_RESPONSE_SCHEMA["properties"]["proposed_actions"]["items"]
    assert action["required"] == ["tool", "arguments", "reason"]
    assert action["properties"]["arguments"]["type"] == "object"
    assert AGENTSHIELD_RESPONSE_SCHEMA["additionalProperties"] is False


def test_ollama_request_uses_schema_think_and_token_limit(monkeypatch) -> None:
    captured = {}

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return None
        def read(self): return b'{"response":"{\\"final_response\\":\\"ok\\",\\"proposed_actions\\":[]}"}'

    def fake_open(request, timeout):
        captured.update(json.loads(request.data))
        return Response()

    monkeypatch.setattr("agentshield.models.ollama.urlopen", fake_open)
    request = ModelRequest(
        ModelContext(user_instruction=ContextItem("user", "hello", TrustBoundary.USER, "u1")),
        ModelSettings("qwen3:4b", temperature=0.1, seed=9, think=False, max_tokens=192),
    )
    assert not OllamaAdapter().generate(request).malformed
    assert captured["format"] == AGENTSHIELD_RESPONSE_SCHEMA
    assert captured["think"] is False
    assert captured["options"] == {"temperature": 0.1, "num_predict": 192, "seed": 9}


def test_model_settings_and_metadata_record_generation_controls() -> None:
    settings = ModelSettings("qwen3:4b", think=False, max_tokens=128)
    metadata = OllamaAdapter().metadata(settings)
    assert metadata.think is False and metadata.max_tokens == 128


def test_model_default_thinking_omits_option(monkeypatch) -> None:
    captured = {}

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return None
        def read(self): return b'{"response":"{\\"final_response\\":\\"ok\\",\\"proposed_actions\\":[]}"}'

    def fake_open(request, timeout):
        captured.update(json.loads(request.data))
        return Response()

    monkeypatch.setattr("agentshield.models.ollama.urlopen", fake_open)
    from agentshield.models import ContextItem, ModelContext, ModelRequest
    from agentshield.runtime import TrustBoundary
    req = ModelRequest(ModelContext(user_instruction=ContextItem("u", "hi", TrustBoundary.USER, "1")), ModelSettings("m", think=None))
    OllamaAdapter().generate(req)
    assert "think" not in captured


def test_empty_response_with_thinking_gets_specific_diagnostic(monkeypatch) -> None:
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return None
        def read(self): return b'{"response":"","thinking":"{\\"final_response\\":\\"HELLO\\",\\"proposed_actions\\":[]}"}'
    monkeypatch.setattr("agentshield.models.ollama.urlopen", lambda *args, **kwargs: Response())
    from agentshield.models import ContextItem, ModelContext, ModelRequest
    from agentshield.runtime import TrustBoundary
    result = OllamaAdapter().generate(ModelRequest(ModelContext(user_instruction=ContextItem("u", "hi", TrustBoundary.USER, "1")), ModelSettings("m")))
    assert result.malformed
    assert "separate thinking" in result.error
    assert result.raw_output == ""


@pytest.mark.parametrize("payload", ({}, {"final_response": "x"}, {"proposed_actions": []}, {"final_response": "x", "proposed_actions": [], "extra": True}))
def test_strict_parser_requires_exact_top_level_fields(payload) -> None:
    assert parse_model_response(json.dumps(payload)).malformed


def test_strict_parser_requires_exact_action_fields() -> None:
    payload = {"final_response": "x", "proposed_actions": [{"tool": "send_email", "arguments": {"to": "x"}, "reason": "x", "authority": True}]}
    assert parse_model_response(json.dumps(payload)).malformed


def test_missing_required_tool_argument_is_malformed_contract() -> None:
    trial = run_trial(DeterministicModelAdapter(response(ProposedAction("send_email", {}, "x"))), ModelSettings("fake"), variant(), ExecutionMode.PROTECTED, 1)
    assert trial.outcome is ModelOutcome.MALFORMED_OUTPUT
    assert trial.actions[0].valid_arguments is False
    assert not trial.actions[0].reached_agentshield
    assert not trial.mitigation_occurred


def test_invalid_action_batch_prevents_later_valid_privileged_action() -> None:
    invalid = ProposedAction("read_document", {"document_path": "report"}, "wrong argument")
    adapter = DeterministicModelAdapter(ModelResponse("x", (invalid, email("demo@example.test")), raw_output="batch"))
    control = next(item for item in load_real_model_benign_corpus() if item.control_kind == "authorized")
    trial = run_trial(adapter, ModelSettings("fake"), control, ExecutionMode.PROTECTED, 1)
    assert trial.outcome is ModelOutcome.MALFORMED_OUTPUT
    assert all(not action.reached_agentshield and not action.executed for action in trial.actions)
    assert not trial.mitigation_occurred


def test_malformed_is_not_resistance_or_mitigation() -> None:
    trial = run_trial(DeterministicModelAdapter(response(malformed=True, error="bad schema")), ModelSettings("fake"), variant(), ExecutionMode.PROTECTED, 1)
    assert trial.outcome is ModelOutcome.MALFORMED_OUTPUT
    assert not trial.model_resistance and not trial.mitigation_occurred


@pytest.mark.parametrize("error", (RuntimeError("generation failed"), TimeoutError("timed out")))
def test_model_failures_have_separate_error_outcome(error) -> None:
    adapter = DeterministicModelAdapter(lambda request: (_ for _ in ()).throw(error))
    trial = run_trial(adapter, ModelSettings("fake"), variant(), ExecutionMode.PROTECTED, 1)
    assert trial.outcome is ModelOutcome.MODEL_ERROR
    assert not trial.malformed and not trial.model_resistance
    assert type(error).__name__.lower().replace("error", "") in (trial.model_error or "").lower() or str(error) in trial.model_error


def test_corrected_evaluable_denominator() -> None:
    valid = run_trial(DeterministicModelAdapter(response()), ModelSettings("fake"), variant(), ExecutionMode.PROTECTED, 1)
    malformed = run_trial(DeterministicModelAdapter(response(malformed=True, error="bad")), ModelSettings("fake"), variant(), ExecutionMode.PROTECTED, 2)
    metrics = aggregate_trials((valid, malformed))
    assert metrics.protected_attack_trials == 2
    assert metrics.valid_protected_attack_responses == 1
    assert metrics.malformed_protected_attack_responses == 1
    assert metrics.model_resistant_trials == 1
    assert metrics.model_resistance_rate == 1.0


def test_zero_conditional_denominator_renders_na() -> None:
    report = run_real_model_experiment(DeterministicModelAdapter(response()), ModelSettings("fake"), trials_per_variant=1, attacks=(variant(),), benign=())
    assert report.metrics.conditional_mitigation_rate is None
    assert "N/A (0 unauthorized proposals reached AgentShield)" in report.render()


def test_authorized_action_proposed_and_allowed() -> None:
    control = next(item for item in load_real_model_benign_corpus() if item.control_kind == "authorized")
    trial = run_trial(DeterministicModelAdapter(response(email("demo@example.test"))), ModelSettings("fake"), control, ExecutionMode.PROTECTED, 1)
    metrics = aggregate_trials((trial,))
    assert metrics.authorized_actions_proposed == metrics.authorized_actions_allowed == 1
    assert metrics.authorized_actions_not_proposed == 0


def test_authorized_action_not_proposed_is_explicit() -> None:
    control = next(item for item in load_real_model_benign_corpus() if item.control_kind == "authorized")
    trial = run_trial(DeterministicModelAdapter(response()), ModelSettings("fake"), control, ExecutionMode.PROTECTED, 1)
    assert aggregate_trials((trial,)).authorized_actions_not_proposed == 1


def test_scope_proposed_and_blocked() -> None:
    trial = run_trial(DeterministicModelAdapter(response(email())), ModelSettings("fake"), variant("scope_manipulation"), ExecutionMode.PROTECTED, 1)
    metrics = aggregate_trials((trial,))
    assert metrics.scope_violations_proposed == metrics.scope_violations_blocked == 1
    assert metrics.scope_violations_executed == 0


def test_scope_not_proposed_is_explicit() -> None:
    trial = run_trial(DeterministicModelAdapter(response()), ModelSettings("fake"), variant("scope_manipulation"), ExecutionMode.PROTECTED, 1)
    assert aggregate_trials((trial,)).scope_violations_not_proposed == 1


def test_attribution_denominator_only_uses_applicable_proposals() -> None:
    trial = run_trial(DeterministicModelAdapter(response(email())), ModelSettings("fake"), variant(), ExecutionMode.PROTECTED, 1)
    metrics = aggregate_trials((trial,))
    assert metrics.attribution_applicable == metrics.attribution_successes == 1


def test_raw_diagnostic_is_bounded_and_length_is_retained() -> None:
    raw = "x" * (RAW_PREVIEW_LIMIT + 500)
    trial = run_trial(DeterministicModelAdapter(response(malformed=True, raw=raw, error="bad")), ModelSettings("fake"), variant(), ExecutionMode.PROTECTED, 1)
    assert len(trial.raw_output_preview) == RAW_PREVIEW_LIMIT
    assert trial.response_length == len(raw)


def test_unknown_tool_remains_rejected_not_remapped() -> None:
    unknown = ProposedAction("exfiltrate_report", {"to": "other@example.test"}, "x")
    trial = run_trial(DeterministicModelAdapter(response(unknown)), ModelSettings("fake"), variant(), ExecutionMode.PROTECTED, 1)
    assert trial.actions[0].known_tool is False
    assert trial.actions[0].status is ToolStatus.ERROR
    assert not trial.actions[0].reached_agentshield and not trial.actions[0].executed


def test_protocol_smoke_valid_cases() -> None:
    def generate(request):
        if "Do not use" in request.context.user_instruction.content:
            return response(final="HELLO")
        return response(email("demo@example.test"))
    report = run_protocol_smoke(DeterministicModelAdapter(generate), ModelSettings("fake", think=False, max_tokens=64))
    assert report.compatible
    assert [case.proposed_actions for case in report.cases] == [0, 1]
    assert "Protocol compatibility: PASS" in report.render()


def test_protocol_smoke_cli_parses_without_contacting_ollama() -> None:
    args = build_parser().parse_args(("experiment", "real-model", "--model", "qwen3:4b", "--protocol-smoke", "--think", "false", "--max-tokens", "256"))
    assert args.protocol_smoke and args.think is False and args.max_tokens == 256


def test_generation_category_counts_explain_pairing() -> None:
    ordinary = next(item for item in load_real_model_benign_corpus() if item.control_kind == "benign")
    authorized = next(item for item in load_real_model_benign_corpus() if item.control_kind == "authorized")
    report = run_real_model_experiment(DeterministicModelAdapter(response()), ModelSettings("fake"), trials_per_variant=1, attacks=(variant(),), benign=(ordinary, authorized))
    metrics = report.metrics
    assert metrics.total_generations == 6
    assert metrics.attack_generations == metrics.benign_generations == metrics.authorized_control_generations == 2


def test_max_tokens_must_be_positive() -> None:
    with pytest.raises(ValueError):
        ModelSettings("fake", max_tokens=0)
