import json

from agentshield.experiments.real_model import run_protocol_smoke
from agentshield.models import ModelSettings, OllamaAdapter


def capture_protocol_payloads(monkeypatch):
    payloads = []

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return None
        def read(self): return b'{"response":"{\\"final_response\\":\\"ok\\",\\"proposed_actions\\":[]}"}'

    def fake_open(request, timeout):
        payloads.append(json.loads(request.data))
        return Response()

    monkeypatch.setattr("agentshield.models.ollama.urlopen", fake_open)
    run_protocol_smoke(OllamaAdapter(), ModelSettings("neutral-model", think=False))
    return payloads


def test_contract_explicitly_permits_empty_actions(monkeypatch) -> None:
    prompts = [item["prompt"] for item in capture_protocol_payloads(monkeypatch)]
    assert all("proposed_actions may be an empty list" in prompt for prompt in prompts)
    assert "empty proposed_actions list is the correct and valid result" in prompts[0]


def test_contract_says_tools_are_optional_not_mandatory(monkeypatch) -> None:
    prompts = [item["prompt"] for item in capture_protocol_payloads(monkeypatch)]
    assert all("optional, never mandatory" in prompt for prompt in prompts)
    assert all("Do not invent tool calls" in prompt for prompt in prompts)


def test_no_action_prompt_has_no_tool_call_priming(monkeypatch) -> None:
    prompt = capture_protocol_payloads(monkeypatch)[0]["prompt"]
    assert "Available tool: send_email" not in prompt
    assert "send_email" not in prompt
    assert "demo@example.test" not in prompt


def test_action_prompt_documents_existing_argument_contract(monkeypatch) -> None:
    prompt = capture_protocol_payloads(monkeypatch)[1]["prompt"]
    assert "send_email" in prompt
    assert '{"to": "recipient address"}' in prompt
    assert "demo@example.test" in prompt


def test_protocol_prompts_do_not_contain_attack_corpus_or_prior_state(monkeypatch) -> None:
    prompts = [item["prompt"] for item in capture_protocol_payloads(monkeypatch)]
    forbidden = (
        "quarterly", "other@example.test", "authority impersonation",
        "scope_manipulation", "retrieved", "memory", "tool_output",
    )
    assert all(not any(value.lower() in prompt.lower() for value in forbidden) for prompt in prompts)
    assert all(prompt.count("[USER source=user]") == 1 for prompt in prompts)


def test_protocol_prompt_has_no_model_specific_branches(monkeypatch) -> None:
    prompts = [item["prompt"] for item in capture_protocol_payloads(monkeypatch)]
    assert all("qwen" not in prompt.lower() and "llama" not in prompt.lower() for prompt in prompts)


def test_schema_still_allows_zero_items(monkeypatch) -> None:
    schema = capture_protocol_payloads(monkeypatch)[0]["format"]
    actions = schema["properties"]["proposed_actions"]
    assert actions["type"] == "array"
    assert "minItems" not in actions


def test_protocol_cases_have_isolated_contexts(monkeypatch) -> None:
    prompts = [item["prompt"] for item in capture_protocol_payloads(monkeypatch)]
    assert "Reply with HELLO" in prompts[0] and "Reply with HELLO" not in prompts[1]
    assert "Send a simulated email" in prompts[1] and "Send a simulated email" not in prompts[0]
