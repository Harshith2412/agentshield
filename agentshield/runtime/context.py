"""Runtime execution modes, trust boundaries, and run context."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Mapping
from uuid import uuid4

from agentshield.core.capabilities import Capability
from agentshield.core.provenance import TrustLevel
from agentshield.runtime.authority import AuthorityLedger, AuthorityLifetime


class ExecutionMode(str, Enum):
    UNPROTECTED = "unprotected"
    PROTECTED = "protected"


@dataclass(frozen=True)
class EmailScope:
    allowed_recipient: str

    def allows(self, arguments: Mapping[str, Any]) -> bool:
        return str(arguments.get("to", "")) == self.allowed_recipient


@dataclass(frozen=True)
class WritePathScope:
    allowed_prefix: str

    def allows(self, arguments: Mapping[str, Any]) -> bool:
        from pathlib import PurePosixPath

        path = PurePosixPath(str(arguments.get("path", "")))
        prefix = PurePosixPath(self.allowed_prefix)
        return not path.is_absolute() and ".." not in path.parts and (path == prefix or prefix in path.parents)


@dataclass(frozen=True)
class AuthorizationGrant:
    capability: Capability
    scope: EmailScope | WritePathScope | None = None
    lifetime: AuthorityLifetime = AuthorityLifetime.RUN_BOUND
    grant_id: str = field(default_factory=lambda: str(uuid4()))
    expires_at: datetime | None = None
    issued_checkpoint_generation: int = 0

    def allows(self, capability: Capability, arguments: Mapping[str, Any]) -> bool:
        return self.capability is capability and (self.scope is None or self.scope.allows(arguments))


class TrustBoundary(str, Enum):
    USER = "user"
    SYSTEM = "system"
    LOCAL_TRUSTED = "local_trusted"
    LOCAL_UNTRUSTED = "local_untrusted"
    EXTERNAL_UNTRUSTED = "external_untrusted"
    MEMORY = "memory"
    TOOL = "tool"

    @property
    def trust_level(self) -> TrustLevel:
        return {
            TrustBoundary.USER: TrustLevel.TRUSTED,
            TrustBoundary.SYSTEM: TrustLevel.TRUSTED,
            TrustBoundary.LOCAL_TRUSTED: TrustLevel.TRUSTED,
            TrustBoundary.LOCAL_UNTRUSTED: TrustLevel.UNTRUSTED,
            TrustBoundary.EXTERNAL_UNTRUSTED: TrustLevel.UNTRUSTED,
            TrustBoundary.MEMORY: TrustLevel.SEMI_TRUSTED,
            TrustBoundary.TOOL: TrustLevel.SEMI_TRUSTED,
        }[self]

    @property
    def is_external_or_untrusted(self) -> bool:
        return self in {TrustBoundary.LOCAL_UNTRUSTED, TrustBoundary.EXTERNAL_UNTRUSTED}


@dataclass(frozen=True)
class AgentTask:
    """Structured intent consumed by the deterministic demo agent."""

    document: str | None = None
    tool: str | None = None
    tool_arguments: Mapping[str, Any] = field(default_factory=dict)
    followup_tool: str | None = None
    followup_tool_arguments: Mapping[str, Any] = field(default_factory=dict)
    memory_read: str | None = None
    memory_write: tuple[str, str] | None = None


@dataclass(frozen=True)
class RunContext:
    mode: ExecutionMode
    authorized_capabilities: frozenset[Capability] = frozenset()
    authorization_grants: tuple[AuthorizationGrant, ...] = ()
    run_id: str = field(default_factory=lambda: str(uuid4()))
    authority_ledger: AuthorityLedger = field(default_factory=AuthorityLedger, compare=False)

    def authorizes(self, capability: Capability, arguments: Mapping[str, Any] | None = None) -> bool:
        if capability in self.authorized_capabilities:
            return True
        return any(
            grant.allows(capability, arguments or {}) and self.authority_ledger.available(grant)
            for grant in self.authorization_grants
        )

    def consume_authority(self, capability: Capability, arguments: Mapping[str, Any] | None = None) -> bool:
        if capability in self.authorized_capabilities:
            return True
        for grant in self.authorization_grants:
            if grant.allows(capability, arguments or {}) and self.authority_ledger.consume(grant):
                return True
        return False
