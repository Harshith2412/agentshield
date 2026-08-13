"""Common contracts for controlled, local adversarial scenarios."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from agentshield.core.capabilities import Capability
from agentshield.runtime.context import ExecutionMode, TrustBoundary


class AttackCategory(str, Enum):
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    MALICIOUS_TOOL_OUTPUT = "malicious_tool_output"
    MEMORY_POISONING = "memory_poisoning"


@dataclass(frozen=True)
class AttackPayload:
    """A safe structured directive interpreted only by the demo scenario."""

    directive: str
    target_tool: str
    arguments: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "arguments", MappingProxyType(dict(self.arguments)))


@dataclass(frozen=True)
class AttackMetadata:
    attack_id: str
    name: str
    category: AttackCategory
    source_boundary: TrustBoundary
    target_capability: Capability
    description: str
    expected_unsafe_behavior: str
    payload: AttackPayload


class AttackScenario(ABC):
    metadata: AttackMetadata

    @abstractmethod
    def run(self, mode: ExecutionMode):
        """Run one isolated deterministic evaluation."""
