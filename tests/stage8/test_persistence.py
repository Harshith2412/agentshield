import sqlite3

import pytest

from agentshield import Capability, EventType
from agentshield.persistence import PersistenceIntegrityError, SQLiteProvenanceStore
from agentshield.runtime import AgentTask, DemoAgent, Document, DocumentStore, TrustBoundary


def trace():
    return DemoAgent(documents=DocumentStore((Document("notes.txt", "safe", TrustBoundary.LOCAL_UNTRUSTED),))).run("Summarize", task=AgentTask(document="notes.txt"))


def test_sqlite_store_creates_schema(tmp_path) -> None:
    path = tmp_path / "store.db"; store = SQLiteProvenanceStore(path); store.close()
    connection = sqlite3.connect(path)
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"runs", "events", "checkpoints", "lineage", "normalized_traces"}.issubset(tables)


@pytest.mark.parametrize("with_key", [False, True])
def test_trace_round_trip_preserves_events(with_key: bool, tmp_path) -> None:
    original = trace(); store = SQLiteProvenanceStore(tmp_path / "x.db", integrity_key=b"test-key" if with_key else None)
    store.persist_trace(original); loaded = store.load_trace(original.run_id)
    assert [e.id for e in loaded.events] == [e.id for e in original.events]
    assert [e.parent_ids for e in loaded.events] == [e.parent_ids for e in original.events]


def test_trace_round_trip_preserves_decisions(tmp_path) -> None:
    original = trace(); store = SQLiteProvenanceStore(tmp_path / "x.db"); store.persist_trace(original); loaded = store.load_trace(original.run_id)
    assert [(d.action, d.risk.score) for d in loaded.decisions] == [(d.action, d.risk.score) for d in original.decisions]


def test_trace_round_trip_preserves_influences(tmp_path) -> None:
    original = trace(); store = SQLiteProvenanceStore(tmp_path / "x.db"); store.persist_trace(original); loaded = store.load_trace(original.run_id)
    assert loaded.influences == original.influences


def test_default_persistence_redacts_content(tmp_path) -> None:
    original = trace(); store = SQLiteProvenanceStore(tmp_path / "x.db"); store.persist_trace(original); loaded = store.load_trace(original.run_id)
    assert all(event.content is None for event in loaded.events)


def test_content_can_be_explicitly_persisted(tmp_path) -> None:
    original = trace(); store = SQLiteProvenanceStore(tmp_path / "x.db"); store.persist_trace(original, redact_content=False); loaded = store.load_trace(original.run_id)
    assert any(event.content is not None for event in loaded.events)


def mutate(store, sql, args):
    store._connection.execute(sql, args); store._connection.commit()


@pytest.mark.parametrize("column,value", [("payload", "{}"), ("previous_hash", "bad"), ("chain_hash", "bad")])
def test_modified_event_detected(column, value, tmp_path) -> None:
    original = trace(); store = SQLiteProvenanceStore(tmp_path / "x.db"); store.persist_trace(original)
    mutate(store, f"UPDATE events SET {column}=? WHERE run_id=? AND sequence=2", (value, original.run_id))
    with pytest.raises(PersistenceIntegrityError): store.verify_run(original.run_id)


def test_removed_event_detected(tmp_path) -> None:
    original = trace(); store = SQLiteProvenanceStore(tmp_path / "x.db"); store.persist_trace(original)
    mutate(store, "DELETE FROM events WHERE run_id=? AND sequence=2", (original.run_id,))
    with pytest.raises(PersistenceIntegrityError, match="count"): store.verify_run(original.run_id)


def test_reordered_event_detected(tmp_path) -> None:
    original = trace(); store = SQLiteProvenanceStore(tmp_path / "x.db"); store.persist_trace(original)
    mutate(store, "UPDATE events SET sequence=99 WHERE run_id=? AND sequence=2", (original.run_id,))
    with pytest.raises(PersistenceIntegrityError): store.verify_run(original.run_id)


def test_broken_parent_detected_even_with_recomputed_chain(tmp_path) -> None:
    original = trace(); store = SQLiteProvenanceStore(tmp_path / "x.db"); store.persist_trace(original, redact_content=False)
    # Payload modification itself is sufficient to fail before an invalid parent can be trusted.
    row = store._connection.execute("SELECT payload FROM events WHERE run_id=? AND sequence=2", (original.run_id,)).fetchone()[0]
    mutate(store, "UPDATE events SET payload=? WHERE run_id=? AND sequence=2", (row.replace(original.events[0].id, "missing-parent"), original.run_id))
    with pytest.raises(PersistenceIntegrityError): store.verify_run(original.run_id)


def test_wrong_hmac_key_rejects_database(tmp_path) -> None:
    original = trace(); path = tmp_path / "x.db"; first = SQLiteProvenanceStore(path, integrity_key=b"one"); first.persist_trace(original); first.close()
    second = SQLiteProvenanceStore(path, integrity_key=b"two")
    with pytest.raises(PersistenceIntegrityError): second.verify_run(original.run_id)


def test_unknown_run_rejected(tmp_path) -> None:
    with pytest.raises(KeyError): SQLiteProvenanceStore(tmp_path / "x.db").load_trace("missing")


def test_final_result_round_trip(tmp_path) -> None:
    original = trace(); store = SQLiteProvenanceStore(tmp_path / "x.db"); store.persist_trace(original)
    assert store.load_trace(original.run_id).final_result == original.final_result
