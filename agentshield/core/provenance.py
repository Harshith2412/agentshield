"""Information origin and propagation tracking."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import TYPE_CHECKING, Iterable

from agentshield.exceptions import DuplicateEventError, UnknownParentError

if TYPE_CHECKING:
    from agentshield.core.events import SecurityEvent


class TrustLevel(str, Enum):
    TRUSTED = "trusted"
    SEMI_TRUSTED = "semi_trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


_TRUST_ORDER = {
    TrustLevel.TRUSTED: 0,
    TrustLevel.SEMI_TRUSTED: 1,
    TrustLevel.UNKNOWN: 2,
    TrustLevel.UNTRUSTED: 3,
}


@dataclass(frozen=True)
class ProvenanceRecord:
    original_source: str = "unknown"
    trust_level: TrustLevel = TrustLevel.UNKNOWN
    source_event_id: str | None = None
    propagation_path: tuple[str, ...] = ()
    externally_influenced: bool = False

    @property
    def propagation_depth(self) -> int:
        return len(self.propagation_path)


class ProvenanceTracker:
    """In-memory event graph for audit and ancestry reconstruction."""

    def __init__(self) -> None:
        self._events: dict[str, SecurityEvent] = {}

    def register(self, event: SecurityEvent) -> None:
        if event.id in self._events:
            raise DuplicateEventError(f"event already registered: {event.id}")
        missing = [parent for parent in event.parent_ids if parent not in self._events]
        if missing:
            raise UnknownParentError(f"unknown parent event(s): {', '.join(missing)}")
        self._events[event.id] = event

    def get(self, event_id: str) -> SecurityEvent:
        try:
            return self._events[event_id]
        except KeyError as exc:
            raise UnknownParentError(f"unknown event: {event_id}") from exc

    def build_provenance(
        self,
        parent_ids: Iterable[str],
        *,
        original_source: str | None = None,
        trust_level: TrustLevel | None = None,
    ) -> ProvenanceRecord:
        parents = [self.get(event_id) for event_id in parent_ids]
        if not parents:
            return ProvenanceRecord(
                original_source=original_source or "unknown",
                trust_level=trust_level or TrustLevel.UNKNOWN,
            )
        least_trusted = max(
            (parent.provenance.trust_level for parent in parents), key=_TRUST_ORDER.__getitem__
        )
        primary = max(parents, key=lambda item: _TRUST_ORDER[item.provenance.trust_level])
        path: list[str] = []
        for parent in parents:
            for event_id in (*parent.provenance.propagation_path, parent.id):
                if event_id not in path:
                    path.append(event_id)
        return ProvenanceRecord(
            original_source=original_source or primary.provenance.original_source,
            trust_level=trust_level or least_trusted,
            source_event_id=primary.provenance.source_event_id or primary.id,
            propagation_path=tuple(path),
            externally_influenced=any(
                parent.provenance.externally_influenced
                or parent.provenance.trust_level is TrustLevel.UNTRUSTED
                for parent in parents
            ),
        )

    def with_inferred_provenance(self, event: SecurityEvent) -> SecurityEvent:
        """Fill default provenance from parents while preserving explicit records."""
        if not event.parent_ids or event.provenance != ProvenanceRecord():
            return event
        return replace(event, provenance=self.build_provenance(event.parent_ids))

    def propagation_chain(self, event_id: str) -> tuple[SecurityEvent, ...]:
        """Return ancestors in causal order followed by the requested event."""
        ordered: list[SecurityEvent] = []
        visited: set[str] = set()

        def visit(current_id: str) -> None:
            if current_id in visited:
                return
            event = self.get(current_id)
            for parent_id in event.parent_ids:
                visit(parent_id)
            visited.add(current_id)
            ordered.append(event)

        visit(event_id)
        return tuple(ordered)

    def __len__(self) -> int:
        return len(self._events)
