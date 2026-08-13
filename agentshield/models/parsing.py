"""Strict JSON parsing for model action proposals."""

import json
from collections.abc import Mapping

from agentshield.models.base import ModelResponse, ProposedAction


def parse_model_response(raw: str) -> ModelResponse:
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        return ModelResponse("", raw_output=raw, malformed=True, error=f"invalid JSON: {exc}")
    if not isinstance(data, Mapping):
        return ModelResponse("", raw_output=raw, malformed=True, error="response must be a JSON object")
    if set(data) != {"final_response", "proposed_actions"}:
        return ModelResponse("", raw_output=raw, malformed=True, error="response must contain exactly final_response and proposed_actions")
    final = data["final_response"]
    actions = data["proposed_actions"]
    if not isinstance(final, str) or not isinstance(actions, list):
        return ModelResponse("", raw_output=raw, malformed=True, error="invalid response field types")
    parsed: list[ProposedAction] = []
    for index, action in enumerate(actions):
        if not isinstance(action, Mapping):
            return ModelResponse(final, raw_output=raw, malformed=True, error=f"action {index} must be an object")
        if set(action) != {"tool", "arguments", "reason"}:
            return ModelResponse(final, raw_output=raw, malformed=True, error=f"action {index} must contain exactly tool, arguments, and reason")
        tool, arguments, reason = action["tool"], action["arguments"], action["reason"]
        if not isinstance(tool, str) or not tool or not isinstance(arguments, Mapping) or not isinstance(reason, str):
            return ModelResponse(final, raw_output=raw, malformed=True, error=f"action {index} has invalid fields")
        parsed.append(ProposedAction(tool, dict(arguments), reason))
    return ModelResponse(final, tuple(parsed), raw_output=raw)
