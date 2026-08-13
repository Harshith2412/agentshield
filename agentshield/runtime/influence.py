"""Explicit material-influence labels layered on causal provenance."""

from dataclasses import dataclass
from enum import Enum

from agentshield.core.capabilities import Capability
from agentshield.core.provenance import TrustLevel


class InfluenceKind(str, Enum):
    TRUSTED = "trusted_influence"
    UNTRUSTED = "untrusted_influence"
    MIXED = "mixed_influence"
    AUTHORIZATION_BEARING = "authorization_bearing"
    NON_AUTHORITATIVE_DATA = "non_authoritative_data"


@dataclass(frozen=True)
class InfluenceRecord:
    source_event_id: str
    source_name: str
    trust: TrustLevel
    kind: InfluenceKind
    authorized_capabilities: tuple[Capability, ...] = ()


def influence_kind(records: tuple[InfluenceRecord, ...]) -> InfluenceKind:
    trusts = {record.trust for record in records}
    if TrustLevel.UNTRUSTED in trusts and TrustLevel.TRUSTED in trusts:
        return InfluenceKind.MIXED
    if TrustLevel.UNTRUSTED in trusts:
        return InfluenceKind.UNTRUSTED
    return InfluenceKind.TRUSTED
