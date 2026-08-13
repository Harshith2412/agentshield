"""Small authority lifetime and consumption ledger."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import Lock


class AuthorityLifetime(str, Enum):
    RUN_BOUND = "run_bound"
    ONE_SHOT = "one_shot"
    UNTIL_TIMESTAMP = "until_timestamp"
    UNTIL_CHECKPOINT = "until_checkpoint"


@dataclass
class AuthorityLedger:
    consumed_grant_ids: set[str] = field(default_factory=set)
    checkpoint_generation: int = 0
    _lock: Lock = field(default_factory=Lock, repr=False, compare=False)

    def available(self, grant) -> bool:
        if grant.grant_id in self.consumed_grant_ids:
            return False
        if grant.lifetime is AuthorityLifetime.UNTIL_TIMESTAMP:
            return grant.expires_at is not None and datetime.now(timezone.utc) < grant.expires_at
        if grant.lifetime is AuthorityLifetime.UNTIL_CHECKPOINT:
            return grant.issued_checkpoint_generation == self.checkpoint_generation
        return True

    def consume(self, grant) -> bool:
        with self._lock:
            if not self.available(grant):
                return False
            if grant.lifetime is AuthorityLifetime.ONE_SHOT:
                self.consumed_grant_ids.add(grant.grant_id)
            return True

    def revoke(self, grant_id: str) -> None:
        """Atomically make a queued or future use unavailable."""
        with self._lock:
            self.consumed_grant_ids.add(grant_id)
