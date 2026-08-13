"""Provider-independent model contracts; adapters never execute tools."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Mapping, Protocol
from uuid import uuid4

if TYPE_CHECKING:
    from agentshield.runtime.context import TrustBoundary


@dataclass(frozen=True)
class ContextItem:
    name: str
    content: str
    boundary: TrustBoundary
    event_id: str


@dataclass(frozen=True)
class ModelContext:
    system_instructions: tuple[ContextItem, ...] = ()
    user_instruction: ContextItem | None = None
    retrieved_sources: tuple[ContextItem, ...] = ()
    memories: tuple[ContextItem, ...] = ()
    tool_outputs: tuple[ContextItem, ...] = ()

    @property
    def material_event_ids(self) -> tuple[str, ...]:
        items = (*self.system_instructions, *((self.user_instruction,) if self.user_instruction else ()),
                 *self.retrieved_sources, *self.memories, *self.tool_outputs)
        return tuple(dict.fromkeys(item.event_id for item in items))

    def render_for_model(self) -> str:
        """Render text for a model while source identity remains in this object."""
        sections: list[str] = []
        groups = (
            ("SYSTEM", self.system_instructions),
            ("USER", (self.user_instruction,) if self.user_instruction else ()),
            ("RETRIEVED", self.retrieved_sources),
            ("MEMORY", self.memories),
            ("TOOL_OUTPUT", self.tool_outputs),
        )
        for label, items in groups:
            for item in items:
                sections.append(f"[{label} source={item.name}]\n{item.content}")
        return "\n\n".join(sections)


@dataclass(frozen=True)
class ModelSettings:
    model_name: str
    model_tag: str | None = None
    temperature: float = 0.0
    seed: int | None = 0
    think: bool | None = False
    max_tokens: int = 256

    def __post_init__(self) -> None:
        if self.max_tokens < 1:
            raise ValueError("max_tokens must be positive")


@dataclass(frozen=True)
class ModelRequest:
    context: ModelContext
    settings: ModelSettings
    request_id: str = field(default_factory=lambda: str(uuid4()))


@dataclass(frozen=True)
class ProposedAction:
    tool: str
    arguments: Mapping[str, object]
    reason: str = ""


@dataclass(frozen=True)
class ModelResponse:
    final_response: str
    proposed_actions: tuple[ProposedAction, ...] = ()
    raw_output: str | None = None
    malformed: bool = False
    error: str | None = None


@dataclass(frozen=True)
class ModelMetadata:
    adapter_type: str
    model_name: str
    model_tag: str | None
    endpoint_type: str
    temperature: float
    seed: int | None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    think: bool | None = False
    max_tokens: int = 256


class ModelAdapter(Protocol):
    adapter_type: str

    def generate(self, request: ModelRequest) -> ModelResponse: ...

    def metadata(self, settings: ModelSettings) -> ModelMetadata: ...


class ModelAdapterError(RuntimeError):
    """Clean adapter failure without tool execution."""


class ModelUnavailableError(ModelAdapterError):
    """The configured local model service cannot be reached."""
