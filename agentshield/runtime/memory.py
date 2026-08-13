"""Small in-memory store used only by the deterministic harness."""

from dataclasses import dataclass

from agentshield.runtime.context import TrustBoundary


@dataclass(frozen=True)
class MemoryEntry:
    key: str
    value: str
    boundary: TrustBoundary = TrustBoundary.MEMORY


class RuntimeMemory:
    def __init__(self, entries: tuple[MemoryEntry, ...] = ()) -> None:
        self._entries = {entry.key: entry for entry in entries}

    def read(self, key: str) -> MemoryEntry | None:
        return self._entries.get(key)

    def write(self, key: str, value: str, boundary: TrustBoundary = TrustBoundary.MEMORY) -> None:
        self._entries[key] = MemoryEntry(key, value, boundary)

    def __contains__(self, key: str) -> bool:
        return key in self._entries
