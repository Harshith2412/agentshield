from io import BytesIO
from urllib.error import URLError

import pytest

from agentshield.models import (
    ContextItem, DeterministicModelAdapter, ModelContext, ModelRequest, ModelResponse,
    ModelSettings, ModelUnavailableError, OllamaAdapter, ProposedAction,
)
from agentshield.runtime import TrustBoundary


def request() -> ModelRequest:
    return ModelRequest(ModelContext(user_instruction=ContextItem("user", "hello", TrustBoundary.USER, "u1")), ModelSettings("test-model"))


def test_deterministic_adapter_records_request() -> None:
    adapter = DeterministicModelAdapter(ModelResponse("ok"))
    assert adapter.generate(request()).final_response == "ok"
    assert len(adapter.requests) == 1


def test_deterministic_adapter_can_return_json() -> None:
    adapter = DeterministicModelAdapter('{"final_response":"ok","proposed_actions":[]}')
    assert not adapter.generate(request()).malformed


def test_deterministic_callable_receives_request() -> None:
    adapter = DeterministicModelAdapter(lambda req: ModelResponse(req.settings.model_name))
    assert adapter.generate(request()).final_response == "test-model"


def test_adapter_metadata_records_configuration() -> None:
    settings = ModelSettings("model", "tag", 0.2, 7)
    metadata = DeterministicModelAdapter().metadata(settings)
    assert (metadata.adapter_type, metadata.model_name, metadata.model_tag) == ("deterministic", "model", "tag")
    assert metadata.temperature == 0.2 and metadata.seed == 7
    assert metadata.timestamp.tzinfo is not None


@pytest.mark.parametrize("endpoint", [
    "https://localhost:11434", "http://example.com:11434", "ftp://127.0.0.1", "http://192.168.1.2:11434"
])
def test_ollama_rejects_nonlocal_or_nonhttp_endpoint(endpoint: str) -> None:
    with pytest.raises(ValueError, match="localhost"):
        OllamaAdapter(endpoint)


@pytest.mark.parametrize("endpoint", ["http://localhost:11434", "http://127.0.0.1:11434", "http://[::1]:11434"])
def test_ollama_accepts_localhost_endpoints(endpoint: str) -> None:
    assert OllamaAdapter(endpoint).endpoint == endpoint


def test_ollama_unavailable_fails_cleanly(monkeypatch) -> None:
    monkeypatch.setattr("agentshield.models.ollama.urlopen", lambda *args, **kwargs: (_ for _ in ()).throw(URLError("offline")))
    with pytest.raises(ModelUnavailableError, match="local Ollama"):
        OllamaAdapter().generate(request())


def test_ollama_parses_mock_local_response(monkeypatch) -> None:
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return None
        def read(self): return b'{"response":"{\\"final_response\\":\\"ok\\",\\"proposed_actions\\":[]}"}'
    monkeypatch.setattr("agentshield.models.ollama.urlopen", lambda *args, **kwargs: Response())
    assert OllamaAdapter().generate(request()).final_response == "ok"


def test_ollama_adapter_does_not_execute_tools(monkeypatch) -> None:
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return None
        def read(self): return b'{"response":"{\\"final_response\\":\\"x\\",\\"proposed_actions\\":[{\\"tool\\":\\"send_email\\",\\"arguments\\":{},\\"reason\\":\\"x\\"}]}"}'
    monkeypatch.setattr("agentshield.models.ollama.urlopen", lambda *args, **kwargs: Response())
    response = OllamaAdapter().generate(request())
    assert response.proposed_actions[0].tool == "send_email"
