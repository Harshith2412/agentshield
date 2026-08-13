"""Optional, proposal-only language model adapters."""

from agentshield.models.base import (
    ContextItem, ModelAdapter, ModelAdapterError, ModelContext, ModelMetadata, ModelRequest,
    ModelResponse, ModelSettings, ModelUnavailableError, ProposedAction,
)
from agentshield.models.deterministic import DeterministicModelAdapter
from agentshield.models.ollama import AGENTSHIELD_RESPONSE_SCHEMA, OllamaAdapter
from agentshield.models.parsing import parse_model_response

__all__ = [
    "ContextItem", "DeterministicModelAdapter", "ModelAdapter", "ModelAdapterError",
    "ModelContext", "ModelMetadata", "ModelRequest", "ModelResponse", "ModelSettings",
    "ModelUnavailableError", "OllamaAdapter", "ProposedAction",
    "AGENTSHIELD_RESPONSE_SCHEMA", "parse_model_response",
]
