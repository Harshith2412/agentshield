import pytest

from agentshield.integrations.microsoft_agent_framework import run_multi_agent
from agentshield.persistence import PersistenceIntegrityError, SQLiteProvenanceStore


def test_normalized_trace_round_trip(tmp_path) -> None:
    normalized = run_multi_agent().adapter.normalized_trace(); store = SQLiteProvenanceStore(tmp_path / "trace.db")
    store.persist_normalized_trace(normalized); loaded = store.load_normalized_trace(normalized.run_id)
    assert loaded == normalized


def test_normalized_trace_tamper_detected(tmp_path) -> None:
    normalized = run_multi_agent().adapter.normalized_trace(); store = SQLiteProvenanceStore(tmp_path / "trace.db", integrity_key=b"key")
    store.persist_normalized_trace(normalized)
    store._connection.execute("UPDATE normalized_traces SET payload='{}' WHERE run_id=?", (normalized.run_id,)); store._connection.commit()
    with pytest.raises(PersistenceIntegrityError): store.load_normalized_trace(normalized.run_id)


def test_unknown_normalized_trace_rejected(tmp_path) -> None:
    with pytest.raises(KeyError): SQLiteProvenanceStore(tmp_path / "trace.db").load_normalized_trace("missing")
