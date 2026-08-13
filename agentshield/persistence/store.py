"""SQLite durable traces, hash-chain integrity, and resumable checkpoints."""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

from agentshield.core.capabilities import Capability
from agentshield.core.engine import SecurityDecision
from agentshield.core.events import EventType, SecurityEvent
from agentshield.core.policies import PolicyAction, PolicyResult
from agentshield.core.provenance import ProvenanceRecord, TrustLevel
from agentshield.core.risk import RiskAssessment, RiskReason, RiskSeverity
from agentshield.runtime.authority import AuthorityLedger, AuthorityLifetime
from agentshield.runtime.context import AuthorizationGrant, EmailScope, ExecutionMode, WritePathScope
from agentshield.runtime.influence import InfluenceKind, InfluenceRecord
from agentshield.runtime.instrumentation import ExecutionTrace


class PersistenceIntegrityError(RuntimeError):
    pass


class StaleCheckpointError(PersistenceIntegrityError):
    pass


class StaleCheckpointPolicy(str, Enum):
    REJECT = "reject"
    READ_ONLY = "read_only"
    APPROVED_ROLLBACK = "approved_rollback"


@dataclass(frozen=True)
class WorkflowCheckpoint:
    checkpoint_id: str
    run_id: str
    generation: int
    parent_checkpoint_id: str | None
    state: Mapping[str, Any]
    grants: tuple[AuthorizationGrant, ...]
    consumed_grant_ids: frozenset[str]
    read_only: bool = False


class SQLiteProvenanceStore:
    def __init__(self, path: str | Path, *, integrity_key: bytes | None = None) -> None:
        self.path = str(path)
        self.integrity_key = integrity_key
        self._connection = sqlite3.connect(self.path)
        self._connection.row_factory = sqlite3.Row
        self._create_schema()

    def _create_schema(self) -> None:
        self._connection.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY, mode TEXT NOT NULL, event_count INTEGER NOT NULL,
                head_hash TEXT NOT NULL, final_result TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                run_id TEXT NOT NULL, sequence INTEGER NOT NULL, event_id TEXT NOT NULL,
                payload TEXT NOT NULL, previous_hash TEXT NOT NULL, chain_hash TEXT NOT NULL,
                PRIMARY KEY (run_id, sequence), UNIQUE (run_id, event_id)
            );
            CREATE TABLE IF NOT EXISTS checkpoints (
                checkpoint_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, generation INTEGER NOT NULL,
                parent_checkpoint_id TEXT, payload TEXT NOT NULL, integrity_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS lineage (
                run_id TEXT PRIMARY KEY, latest_generation INTEGER NOT NULL, latest_checkpoint_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS normalized_traces (
                run_id TEXT PRIMARY KEY, framework TEXT NOT NULL, payload TEXT NOT NULL, integrity_hash TEXT NOT NULL
            );
        """)
        self._connection.commit()

    def _digest(self, data: bytes) -> str:
        if self.integrity_key is not None:
            return hmac.new(self.integrity_key, data, hashlib.sha256).hexdigest()
        return hashlib.sha256(data).hexdigest()

    def persist_trace(self, trace: ExecutionTrace, *, redact_content: bool = True) -> None:
        previous = ""
        rows = []
        decisions = {item.event.id: item for item in trace.decisions}
        for sequence, event in enumerate(trace.events, 1):
            payload = _event_payload(event, decisions.get(event.id), trace.influences.get(event.id, ()), redact_content)
            encoded = _canonical(payload)
            chain_hash = self._digest(previous.encode() + encoded.encode())
            rows.append((trace.run_id, sequence, event.id, encoded, previous, chain_hash))
            previous = chain_hash
        with self._connection:
            self._connection.execute("DELETE FROM events WHERE run_id = ?", (trace.run_id,))
            self._connection.executemany("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?)", rows)
            self._connection.execute(
                "INSERT OR REPLACE INTO runs VALUES (?, ?, ?, ?, ?)",
                (trace.run_id, trace.mode.value, len(rows), previous, trace.final_result),
            )

    def verify_run(self, run_id: str) -> bool:
        run = self._connection.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if run is None:
            raise KeyError(f"unknown persisted run: {run_id}")
        rows = self._connection.execute("SELECT * FROM events WHERE run_id = ? ORDER BY sequence", (run_id,)).fetchall()
        if len(rows) != run["event_count"]:
            raise PersistenceIntegrityError("event count mismatch; event may have been removed")
        previous = ""
        ids: set[str] = set()
        payloads = []
        for expected, row in enumerate(rows, 1):
            if row["sequence"] != expected or row["previous_hash"] != previous:
                raise PersistenceIntegrityError("event order or previous hash is invalid")
            calculated = self._digest(previous.encode() + row["payload"].encode())
            if not hmac.compare_digest(calculated, row["chain_hash"]):
                raise PersistenceIntegrityError("event payload integrity failure")
            payload = json.loads(row["payload"])
            ids.add(payload["event"]["id"])
            payloads.append(payload)
            previous = row["chain_hash"]
        if previous != run["head_hash"]:
            raise PersistenceIntegrityError("run head hash mismatch")
        for payload in payloads:
            if any(parent not in ids for parent in payload["event"]["parent_ids"]):
                raise PersistenceIntegrityError("broken parent reference")
        return True

    def load_trace(self, run_id: str) -> ExecutionTrace:
        self.verify_run(run_id)
        run = self._connection.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        rows = self._connection.execute("SELECT payload FROM events WHERE run_id = ? ORDER BY sequence", (run_id,)).fetchall()
        trace = ExecutionTrace(run_id, ExecutionMode(run["mode"]), final_result=run["final_result"])
        for row in rows:
            payload = json.loads(row["payload"])
            event = _event_from_payload(payload["event"])
            trace.events.append(event)
            if payload.get("decision"):
                trace.decisions.append(_decision_from_payload(event, payload["decision"]))
            trace.influences[event.id] = tuple(_influence_from_payload(item) for item in payload.get("influences", []))
        return trace

    def create_checkpoint(
        self,
        trace: ExecutionTrace,
        *,
        state: Mapping[str, Any],
        grants: tuple[AuthorizationGrant, ...] = (),
        ledger: AuthorityLedger | None = None,
        parent_checkpoint_id: str | None = None,
    ) -> WorkflowCheckpoint:
        self.persist_trace(trace)
        lineage = self._connection.execute("SELECT * FROM lineage WHERE run_id = ?", (trace.run_id,)).fetchone()
        generation = (lineage["latest_generation"] + 1) if lineage else 1
        if parent_checkpoint_id is None and lineage:
            parent_checkpoint_id = lineage["latest_checkpoint_id"]
        checkpoint_id = str(uuid4())
        payload = {
            "state": _json_safe(state),
            "grants": [_grant_payload(grant) for grant in grants],
            "consumed": sorted((ledger or AuthorityLedger()).consumed_grant_ids),
            "event_head": self._connection.execute("SELECT head_hash FROM runs WHERE run_id = ?", (trace.run_id,)).fetchone()[0],
        }
        encoded = _canonical(payload)
        integrity = self._digest(f"{checkpoint_id}|{trace.run_id}|{generation}|{parent_checkpoint_id or ''}|{encoded}".encode())
        with self._connection:
            self._connection.execute(
                "INSERT INTO checkpoints VALUES (?, ?, ?, ?, ?, ?)",
                (checkpoint_id, trace.run_id, generation, parent_checkpoint_id, encoded, integrity),
            )
            self._connection.execute("INSERT OR REPLACE INTO lineage VALUES (?, ?, ?)", (trace.run_id, generation, checkpoint_id))
        return WorkflowCheckpoint(checkpoint_id, trace.run_id, generation, parent_checkpoint_id, payload["state"], grants, frozenset(payload["consumed"]))

    def load_checkpoint(
        self, checkpoint_id: str, *, policy: StaleCheckpointPolicy = StaleCheckpointPolicy.REJECT
    ) -> WorkflowCheckpoint:
        row = self._connection.execute("SELECT * FROM checkpoints WHERE checkpoint_id = ?", (checkpoint_id,)).fetchone()
        if row is None:
            raise KeyError(f"unknown checkpoint: {checkpoint_id}")
        encoded = row["payload"]
        expected = self._digest(f"{row['checkpoint_id']}|{row['run_id']}|{row['generation']}|{row['parent_checkpoint_id'] or ''}|{encoded}".encode())
        if not hmac.compare_digest(expected, row["integrity_hash"]):
            raise PersistenceIntegrityError("checkpoint integrity failure")
        self.verify_run(row["run_id"])
        payload = json.loads(encoded)
        head = self._connection.execute("SELECT head_hash FROM runs WHERE run_id = ?", (row["run_id"],)).fetchone()[0]
        if payload["event_head"] != head:
            raise PersistenceIntegrityError("checkpoint refers to a different event-chain head")
        lineage = self._connection.execute("SELECT latest_generation FROM lineage WHERE run_id = ?", (row["run_id"],)).fetchone()
        stale = bool(lineage and row["generation"] < lineage["latest_generation"])
        if stale and policy is StaleCheckpointPolicy.REJECT:
            raise StaleCheckpointError("checkpoint is older than latest lineage generation")
        grants = tuple(_grant_from_payload(item) for item in payload["grants"])
        return WorkflowCheckpoint(
            row["checkpoint_id"], row["run_id"], row["generation"], row["parent_checkpoint_id"],
            payload["state"], grants, frozenset(payload["consumed"]),
            read_only=stale and policy is StaleCheckpointPolicy.READ_ONLY,
        )

    def restore_ledger(self, checkpoint: WorkflowCheckpoint) -> AuthorityLedger:
        return AuthorityLedger(set(checkpoint.consumed_grant_ids), checkpoint.generation)

    def persist_normalized_trace(self, normalized_trace) -> None:
        payload = _canonical({"events": [
            {"kind": event.kind.value, "source_event_id": event.source_event_id, "detail": event.detail}
            for event in normalized_trace.events
        ]})
        integrity = self._digest(f"{normalized_trace.framework}|{normalized_trace.run_id}|{payload}".encode())
        with self._connection:
            self._connection.execute("INSERT OR REPLACE INTO normalized_traces VALUES (?, ?, ?, ?)", (normalized_trace.run_id, normalized_trace.framework, payload, integrity))

    def load_normalized_trace(self, run_id: str):
        from agentshield.integrations.base.traces import FrameworkSecurityTrace, NormalizedEventType, NormalizedTraceEvent
        row = self._connection.execute("SELECT * FROM normalized_traces WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            raise KeyError(run_id)
        expected = self._digest(f"{row['framework']}|{run_id}|{row['payload']}".encode())
        if not hmac.compare_digest(expected, row["integrity_hash"]):
            raise PersistenceIntegrityError("normalized trace integrity failure")
        payload = json.loads(row["payload"])
        return FrameworkSecurityTrace(row["framework"], run_id, tuple(
            NormalizedTraceEvent(NormalizedEventType(item["kind"]), item["source_event_id"], item["detail"])
            for item in payload["events"]
        ))

    def close(self) -> None:
        self._connection.close()


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(item) for item in value]
    return str(value)


def _event_payload(event, decision, influences, redact):
    return {
        "event": {
            "id": event.id, "type": event.event_type.value, "timestamp": event.timestamp.isoformat(),
            "source": event.source, "content": None if redact else _json_safe(event.content),
            "parent_ids": list(event.parent_ids), "capability": event.capability.value if event.capability else None,
            "metadata": _json_safe(event.metadata),
            "provenance": {
                "original_source": event.provenance.original_source, "trust": event.provenance.trust_level.value,
                "source_event_id": event.provenance.source_event_id, "path": list(event.provenance.propagation_path),
                "external": event.provenance.externally_influenced,
            },
        },
        "decision": None if decision is None else {
            "action": decision.action.value, "score": decision.risk.score, "severity": decision.risk.severity.value,
            "risk_reasons": [_json_safe(reason.__dict__) for reason in decision.risk.reasons],
            "policies": [_json_safe(result.__dict__) for result in decision.policy_results],
        },
        "influences": [{
            "source_event_id": item.source_event_id, "source_name": item.source_name, "trust": item.trust.value,
            "kind": item.kind.value, "capabilities": [cap.value for cap in item.authorized_capabilities],
        } for item in influences],
    }


def _event_from_payload(item):
    provenance = item["provenance"]
    return SecurityEvent(
        EventType(item["type"]), item["source"], content=item["content"], parent_ids=tuple(item["parent_ids"]),
        provenance=ProvenanceRecord(provenance["original_source"], TrustLevel(provenance["trust"]), provenance["source_event_id"], tuple(provenance["path"]), provenance["external"]),
        capability=Capability(item["capability"]) if item["capability"] else None,
        metadata=item["metadata"], id=item["id"], timestamp=datetime.fromisoformat(item["timestamp"]),
    )


def _decision_from_payload(event, item):
    reasons = tuple(RiskReason(reason["factor"], reason["contribution"], reason["explanation"]) for reason in item["risk_reasons"])
    policies = tuple(PolicyResult(result["policy"], PolicyAction(result["action"]), result["reason"]) for result in item["policies"])
    return SecurityDecision(event, PolicyAction(item["action"]), RiskAssessment(item["score"], RiskSeverity(item["severity"]), reasons), policies)


def _influence_from_payload(item):
    return InfluenceRecord(item["source_event_id"], item["source_name"], TrustLevel(item["trust"]), InfluenceKind(item["kind"]), tuple(Capability(cap) for cap in item["capabilities"]))


def _grant_payload(grant):
    scope = None
    if isinstance(grant.scope, EmailScope): scope = {"type": "email", "value": grant.scope.allowed_recipient}
    if isinstance(grant.scope, WritePathScope): scope = {"type": "path", "value": grant.scope.allowed_prefix}
    return {
        "capability": grant.capability.value, "scope": scope, "lifetime": grant.lifetime.value,
        "grant_id": grant.grant_id, "expires_at": grant.expires_at.isoformat() if grant.expires_at else None,
        "issued_checkpoint_generation": grant.issued_checkpoint_generation,
    }


def _grant_from_payload(item):
    scope = None
    if item["scope"] and item["scope"]["type"] == "email": scope = EmailScope(item["scope"]["value"])
    if item["scope"] and item["scope"]["type"] == "path": scope = WritePathScope(item["scope"]["value"])
    return AuthorizationGrant(Capability(item["capability"]), scope, AuthorityLifetime(item["lifetime"]), item["grant_id"], datetime.fromisoformat(item["expires_at"]) if item["expires_at"] else None, item["issued_checkpoint_generation"])
