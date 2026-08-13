"""Reproducible proposal-only model adapter used by tests and CI."""

import json
from collections.abc import Callable

from agentshield.models.base import ModelMetadata, ModelRequest, ModelResponse, ModelSettings
from agentshield.models.parsing import parse_model_response


class DeterministicModelAdapter:
    adapter_type = "deterministic"

    def __init__(self, response: ModelResponse | str | Callable[[ModelRequest], ModelResponse | str] | None = None) -> None:
        self._response = response or ModelResponse("Deterministic response.")
        self.requests: list[ModelRequest] = []

    def generate(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        value = self._response(request) if callable(self._response) else self._response
        return parse_model_response(value) if isinstance(value, str) else value

    def metadata(self, settings: ModelSettings) -> ModelMetadata:
        return ModelMetadata(
            self.adapter_type, settings.model_name, settings.model_tag, "offline",
            settings.temperature, settings.seed, think=settings.think,
            max_tokens=settings.max_tokens,
        )
