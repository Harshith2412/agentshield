"""Optional localhost-only Ollama adapter using the Python standard library."""

from __future__ import annotations

import json
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from agentshield.models.base import (
    ModelMetadata, ModelRequest, ModelResponse, ModelSettings, ModelUnavailableError,
)
from agentshield.models.parsing import parse_model_response


AGENTSHIELD_RESPONSE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["final_response", "proposed_actions"],
    "properties": {
        "final_response": {"type": "string"},
        "proposed_actions": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["tool", "arguments", "reason"],
                "properties": {
                    "tool": {"type": "string"},
                    "arguments": {"type": "object"},
                    "reason": {"type": "string"},
                },
            },
        },
    },
}


class OllamaAdapter:
    adapter_type = "ollama"

    def __init__(self, endpoint: str = "http://127.0.0.1:11434", *, timeout: float = 30.0) -> None:
        parsed = urlparse(endpoint)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("Ollama endpoint must use HTTP on localhost")
        self.endpoint = endpoint.rstrip("/")
        self.timeout = timeout

    def generate(self, request: ModelRequest) -> ModelResponse:
        schema_instruction = (
            "Return only one JSON object matching the supplied schema. "
            "proposed_actions may be an empty list. Proposing a tool is optional, never mandatory, "
            "and appropriate only when the user explicitly requests that side effect. "
            "Do not invent tool calls. Each proposed action has tool, arguments, and reason."
        )
        payload = {
            "model": request.settings.model_name,
            "prompt": f"{schema_instruction}\n\n{request.context.render_for_model()}",
            "stream": False,
            "format": AGENTSHIELD_RESPONSE_SCHEMA,
            "options": {
                "temperature": request.settings.temperature,
                "num_predict": request.settings.max_tokens,
            },
        }
        if request.settings.think is not None:
            payload["think"] = request.settings.think
        if request.settings.seed is not None:
            payload["options"]["seed"] = request.settings.seed
        http_request = Request(
            f"{self.endpoint}/api/generate",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            # Endpoint validation in __init__ restricts this to HTTP loopback.
            with urlopen(http_request, timeout=self.timeout) as response:  # nosec B310
                envelope = json.loads(response.read().decode("utf-8"))
        except (URLError, OSError, TimeoutError, json.JSONDecodeError) as exc:
            raise ModelUnavailableError(f"local Ollama service unavailable at {self.endpoint}: {exc}") from exc
        raw = envelope.get("response") if isinstance(envelope, dict) else None
        if not isinstance(raw, str):
            return ModelResponse("", raw_output=str(envelope), malformed=True, error="Ollama response missing text")
        response = parse_model_response(raw)
        if response.malformed and not raw and envelope.get("thinking"):
            return ModelResponse(
                "", raw_output=raw, malformed=True,
                error="empty Ollama response; model returned separate thinking content",
            )
        return response

    def metadata(self, settings: ModelSettings) -> ModelMetadata:
        return ModelMetadata(
            self.adapter_type, settings.model_name, settings.model_tag, "localhost",
            settings.temperature, settings.seed, think=settings.think,
            max_tokens=settings.max_tokens,
        )

    def service_info(self) -> dict[str, object]:
        """Discover local service/model metadata without downloading anything."""
        version = self._get_json("/api/version")
        tags = self._get_json("/api/tags")
        models = []
        for item in tags.get("models", []) if isinstance(tags, dict) else []:
            if isinstance(item, dict):
                models.append({
                    "name": item.get("name") or item.get("model"),
                    "digest": item.get("digest"),
                    "modified_at": item.get("modified_at"),
                })
        return {
            "reachable": True,
            "version": version.get("version") if isinstance(version, dict) else None,
            "models": tuple(models),
        }

    def _get_json(self, path: str) -> dict[str, object]:
        request = Request(f"{self.endpoint}{path}", method="GET")
        try:
            # Constructor validation restricts the endpoint to HTTP loopback.
            with urlopen(request, timeout=self.timeout) as response:  # nosec B310
                data = json.loads(response.read().decode("utf-8"))
        except (URLError, OSError, TimeoutError, json.JSONDecodeError) as exc:
            raise ModelUnavailableError(f"local Ollama service unavailable at {self.endpoint}: {exc}") from exc
        if not isinstance(data, dict):
            raise ModelUnavailableError("local Ollama service returned invalid metadata")
        return data
