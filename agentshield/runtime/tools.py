"""Safe simulated tools for reproducible runtime experiments."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from tempfile import TemporaryDirectory
from types import MappingProxyType
from typing import Any, Callable, Mapping
import inspect

from agentshield.core.capabilities import Capability
from agentshield.runtime.context import TrustBoundary


class SideEffectLevel(str, Enum):
    NONE = "none"
    LOCAL = "local"
    EXTERNAL_SIMULATED = "external_simulated"


class ToolStatus(str, Enum):
    SUCCESS = "success"
    BLOCKED = "blocked"
    REVIEW_REQUIRED = "review_required"
    SANITIZATION_REQUIRED = "sanitization_required"
    ERROR = "error"


@dataclass(frozen=True)
class ToolRequest:
    name: str
    arguments: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "arguments", MappingProxyType(dict(self.arguments)))


@dataclass(frozen=True)
class ToolResult:
    tool_name: str
    status: ToolStatus
    output: str | Mapping[str, Any] | None = None
    side_effect_level: SideEffectLevel = SideEffectLevel.NONE


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    capability: Capability
    side_effect_level: SideEffectLevel
    handler: Callable[[Mapping[str, Any]], str | Mapping[str, Any]] = field(repr=False)
    output_boundary: TrustBoundary = TrustBoundary.TOOL


class ToolRegistry:
    """Registry whose sensitive built-ins are simulations, not real integrations."""

    def __init__(self, documents: Mapping[str, str] | None = None) -> None:
        self._sandbox = TemporaryDirectory(prefix="agentshield-")
        self.sandbox_path = Path(self._sandbox.name).resolve()
        self.documents = dict(documents or {})
        self.simulated_emails: list[Mapping[str, Any]] = []
        self.simulated_network_requests: list[Mapping[str, Any]] = []
        self.simulated_shell_commands: list[str] = []
        self._tools: dict[str, ToolDefinition] = {}
        self._register_builtins()

    def register(self, definition: ToolDefinition) -> None:
        if definition.name in self._tools:
            raise ValueError(f"tool already registered: {definition.name}")
        self._tools[definition.name] = definition

    def get(self, name: str) -> ToolDefinition:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise KeyError(f"unknown tool: {name}") from exc

    def validate_request(self, request: ToolRequest) -> ToolDefinition:
        """Validate the controlled tool name and its minimum typed contract."""
        definition = self.get(request.name)
        required = {
            "read_document": ("name",),
            "write_file": ("path",),
            "send_email": ("to",),
            "network_request": ("url",),
            "shell_execute": ("command",),
        }.get(request.name, ())
        for key in required:
            value = request.arguments.get(key)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{request.name} requires non-empty string argument: {key}")
        return definition

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    def execute(self, request: ToolRequest) -> ToolResult:
        definition = self.get(request.name)
        try:
            output = definition.handler(request.arguments)
        except (KeyError, TypeError, ValueError) as exc:
            return ToolResult(request.name, ToolStatus.ERROR, str(exc), definition.side_effect_level)
        return ToolResult(request.name, ToolStatus.SUCCESS, output, definition.side_effect_level)

    async def execute_async(self, request: ToolRequest) -> ToolResult:
        definition = self.get(request.name)
        try:
            output = definition.handler(request.arguments)
            if inspect.isawaitable(output):
                output = await output
        except (KeyError, TypeError, ValueError) as exc:
            return ToolResult(request.name, ToolStatus.ERROR, str(exc), definition.side_effect_level)
        return ToolResult(request.name, ToolStatus.SUCCESS, output, definition.side_effect_level)

    def close(self) -> None:
        self._sandbox.cleanup()

    def _register_builtins(self) -> None:
        self.register(ToolDefinition("read_document", Capability.READ_LOCAL, SideEffectLevel.NONE, self._read_document))
        self.register(ToolDefinition("write_file", Capability.WRITE_LOCAL, SideEffectLevel.LOCAL, self._write_file))
        self.register(ToolDefinition("send_email", Capability.EMAIL_SEND, SideEffectLevel.EXTERNAL_SIMULATED, self._send_email))
        self.register(ToolDefinition("network_request", Capability.NETWORK_READ, SideEffectLevel.EXTERNAL_SIMULATED, self._network_request))
        self.register(ToolDefinition("shell_execute", Capability.SHELL_EXECUTE, SideEffectLevel.EXTERNAL_SIMULATED, self._shell_execute))

    def _read_document(self, arguments: Mapping[str, Any]) -> str:
        return self.documents[str(arguments["name"])]

    def _write_file(self, arguments: Mapping[str, Any]) -> Mapping[str, str]:
        relative = Path(str(arguments["path"]))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("write path must remain inside the tool sandbox")
        target = (self.sandbox_path / relative).resolve()
        if not target.is_relative_to(self.sandbox_path):
            raise ValueError("write path escapes the tool sandbox")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(arguments.get("content", "")), encoding="utf-8")
        return {"sandbox_relative_path": str(relative), "bytes_written": str(target.stat().st_size)}

    def _send_email(self, arguments: Mapping[str, Any]) -> Mapping[str, str]:
        record = MappingProxyType({
            "to": str(arguments["to"]),
            "subject": str(arguments.get("subject", "")),
            "body": str(arguments.get("body", "")),
        })
        self.simulated_emails.append(record)
        return {"simulation": "email recorded", "recipient": record["to"]}

    def _network_request(self, arguments: Mapping[str, Any]) -> Mapping[str, str]:
        record = MappingProxyType({"url": str(arguments["url"]), "method": str(arguments.get("method", "GET"))})
        self.simulated_network_requests.append(record)
        return {"simulation": "network request recorded", "status": "not_sent"}

    def _shell_execute(self, arguments: Mapping[str, Any]) -> Mapping[str, str]:
        command = str(arguments["command"])
        self.simulated_shell_commands.append(command)
        return {"simulation": "shell command recorded", "status": "not_executed"}
