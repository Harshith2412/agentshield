from datetime import datetime, timedelta, timezone

import pytest

from agentshield import AgentShield, Capability, EventType
from agentshield.persistence import PersistenceIntegrityError, SQLiteProvenanceStore, StaleCheckpointError, StaleCheckpointPolicy
from agentshield.runtime import (
    AuthorizationGrant, AuthorityLedger, AuthorityLifetime, EmailScope, ExecutionMode,
    RunContext, RuntimeInstrumentation, ToolRegistry, ToolRequest, ToolStatus, TrustBoundary,
)
from agentshield.runtime.executor import InstrumentedExecutor


def setup_trace(grants=(), ledger=None):
    context = RunContext(ExecutionMode.PROTECTED, authorization_grants=grants, authority_ledger=ledger or AuthorityLedger())
    instrumentation = RuntimeInstrumentation(AgentShield(), context)
    root = instrumentation.emit(EventType.USER_INPUT, "user", boundary=TrustBoundary.USER)[0]
    return instrumentation, root


def test_checkpoint_round_trip_state(tmp_path) -> None:
    instrumentation, _ = setup_trace(); store = SQLiteProvenanceStore(tmp_path / "x.db")
    checkpoint = store.create_checkpoint(instrumentation.trace, state={"phase": "paused", "count": 2})
    loaded = store.load_checkpoint(checkpoint.checkpoint_id)
    assert loaded.state == {"phase": "paused", "count": 2}


def test_checkpoint_lineage_increments(tmp_path) -> None:
    instrumentation, _ = setup_trace(); store = SQLiteProvenanceStore(tmp_path / "x.db")
    first = store.create_checkpoint(instrumentation.trace, state={}); second = store.create_checkpoint(instrumentation.trace, state={})
    assert second.generation == first.generation + 1
    assert second.parent_checkpoint_id == first.checkpoint_id


def test_stale_checkpoint_rejected_by_default(tmp_path) -> None:
    instrumentation, _ = setup_trace(); store = SQLiteProvenanceStore(tmp_path / "x.db")
    first = store.create_checkpoint(instrumentation.trace, state={}); store.create_checkpoint(instrumentation.trace, state={})
    with pytest.raises(StaleCheckpointError): store.load_checkpoint(first.checkpoint_id)


def test_stale_checkpoint_read_only_inspection(tmp_path) -> None:
    instrumentation, _ = setup_trace(); store = SQLiteProvenanceStore(tmp_path / "x.db")
    first = store.create_checkpoint(instrumentation.trace, state={}); store.create_checkpoint(instrumentation.trace, state={})
    assert store.load_checkpoint(first.checkpoint_id, policy=StaleCheckpointPolicy.READ_ONLY).read_only


def test_explicit_rollback_loads_not_read_only(tmp_path) -> None:
    instrumentation, _ = setup_trace(); store = SQLiteProvenanceStore(tmp_path / "x.db")
    first = store.create_checkpoint(instrumentation.trace, state={}); store.create_checkpoint(instrumentation.trace, state={})
    assert not store.load_checkpoint(first.checkpoint_id, policy=StaleCheckpointPolicy.APPROVED_ROLLBACK).read_only


def test_checkpoint_tamper_detected(tmp_path) -> None:
    instrumentation, _ = setup_trace(); store = SQLiteProvenanceStore(tmp_path / "x.db")
    checkpoint = store.create_checkpoint(instrumentation.trace, state={"authorized_email": False})
    store._connection.execute("UPDATE checkpoints SET payload=? WHERE checkpoint_id=?", ('{"authorized_email":true}', checkpoint.checkpoint_id)); store._connection.commit()
    with pytest.raises(PersistenceIntegrityError): store.load_checkpoint(checkpoint.checkpoint_id)


@pytest.mark.parametrize("lifetime", list(AuthorityLifetime))
def test_authority_lifetime_serialization(lifetime, tmp_path) -> None:
    expires = datetime.now(timezone.utc) + timedelta(hours=1) if lifetime is AuthorityLifetime.UNTIL_TIMESTAMP else None
    grant = AuthorizationGrant(Capability.EMAIL_SEND, EmailScope("demo@example.test"), lifetime, expires_at=expires)
    instrumentation, _ = setup_trace((grant,)); store = SQLiteProvenanceStore(tmp_path / f"{lifetime.value}.db")
    checkpoint = store.create_checkpoint(instrumentation.trace, state={}, grants=(grant,))
    restored = store.load_checkpoint(checkpoint.checkpoint_id).grants[0]
    assert restored.lifetime is lifetime and restored.grant_id == grant.grant_id


def test_expired_timestamp_grant_denied() -> None:
    grant = AuthorizationGrant(Capability.EMAIL_SEND, EmailScope("demo@example.test"), AuthorityLifetime.UNTIL_TIMESTAMP, expires_at=datetime.now(timezone.utc)-timedelta(seconds=1))
    context = RunContext(ExecutionMode.PROTECTED, authorization_grants=(grant,))
    assert not context.authorizes(Capability.EMAIL_SEND, {"to": "demo@example.test"})


def test_future_timestamp_grant_allowed() -> None:
    grant = AuthorizationGrant(Capability.EMAIL_SEND, EmailScope("demo@example.test"), AuthorityLifetime.UNTIL_TIMESTAMP, expires_at=datetime.now(timezone.utc)+timedelta(seconds=10))
    assert RunContext(ExecutionMode.PROTECTED, authorization_grants=(grant,)).authorizes(Capability.EMAIL_SEND, {"to": "demo@example.test"})


def test_until_checkpoint_expires_after_generation() -> None:
    grant = AuthorizationGrant(Capability.EMAIL_SEND, lifetime=AuthorityLifetime.UNTIL_CHECKPOINT, issued_checkpoint_generation=0)
    ledger = AuthorityLedger(checkpoint_generation=1)
    assert not RunContext(ExecutionMode.PROTECTED, authorization_grants=(grant,), authority_ledger=ledger).authorizes(Capability.EMAIL_SEND)


def test_one_shot_first_allowed_second_blocked() -> None:
    grant = AuthorizationGrant(Capability.EMAIL_SEND, EmailScope("demo@example.test"), AuthorityLifetime.ONE_SHOT)
    instrumentation, root = setup_trace((grant,)); executor = InstrumentedExecutor(ToolRegistry(), instrumentation)
    first, _ = executor.execute(ToolRequest("send_email", {"to": "demo@example.test"}), (root.id,))
    second, _ = executor.execute(ToolRequest("send_email", {"to": "demo@example.test"}), (root.id,))
    assert first.status is ToolStatus.SUCCESS and second.status is ToolStatus.BLOCKED


def test_consumed_one_shot_stays_consumed_after_restart(tmp_path) -> None:
    grant = AuthorizationGrant(Capability.EMAIL_SEND, EmailScope("demo@example.test"), AuthorityLifetime.ONE_SHOT)
    instrumentation, root = setup_trace((grant,)); InstrumentedExecutor(ToolRegistry(), instrumentation).execute(ToolRequest("send_email", {"to": "demo@example.test"}), (root.id,))
    store = SQLiteProvenanceStore(tmp_path / "x.db"); checkpoint = store.create_checkpoint(instrumentation.trace, state={}, grants=(grant,), ledger=instrumentation.context.authority_ledger)
    restored = store.load_checkpoint(checkpoint.checkpoint_id); ledger = store.restore_ledger(restored)
    assert not RunContext(ExecutionMode.PROTECTED, authorization_grants=restored.grants, authority_ledger=ledger).authorizes(Capability.EMAIL_SEND, {"to": "demo@example.test"})


def test_consumption_tampering_detected(tmp_path) -> None:
    grant = AuthorizationGrant(Capability.EMAIL_SEND, lifetime=AuthorityLifetime.ONE_SHOT); ledger = AuthorityLedger({grant.grant_id})
    instrumentation, _ = setup_trace((grant,), ledger); store = SQLiteProvenanceStore(tmp_path / "x.db", integrity_key=b"external-test-key")
    checkpoint = store.create_checkpoint(instrumentation.trace, state={}, grants=(grant,), ledger=ledger)
    row = store._connection.execute("SELECT payload FROM checkpoints WHERE checkpoint_id=?", (checkpoint.checkpoint_id,)).fetchone()[0]
    store._connection.execute("UPDATE checkpoints SET payload=? WHERE checkpoint_id=?", (row.replace(grant.grant_id, "removed"), checkpoint.checkpoint_id)); store._connection.commit()
    with pytest.raises(PersistenceIntegrityError): store.load_checkpoint(checkpoint.checkpoint_id)


def test_revoked_queued_authority_is_denied() -> None:
    grant = AuthorizationGrant(Capability.EMAIL_SEND)
    ledger = AuthorityLedger(); context = RunContext(ExecutionMode.PROTECTED, authorization_grants=(grant,), authority_ledger=ledger)
    assert context.authorizes(Capability.EMAIL_SEND)
    ledger.revoke(grant.grant_id)
    assert not context.authorizes(Capability.EMAIL_SEND)
