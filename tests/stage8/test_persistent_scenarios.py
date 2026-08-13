from agentshield.persistence import (
    run_pause_resume_attack, run_persisted_memory_poisoning, run_persistence_benchmark, run_tamper_detection,
)


def test_pause_resume_attack_blocked(tmp_path) -> None:
    result = run_pause_resume_attack(tmp_path / "pause.db")
    assert result.blocked and not result.executed


def test_pause_resume_preserves_original_attribution(tmp_path) -> None:
    result = run_pause_resume_attack(tmp_path / "pause.db")
    assert result.attribution.source_name == "persisted_report.txt"
    assert result.provenance_preserved and result.untrusted_influence_preserved


def test_persisted_memory_poisoning_blocked(tmp_path) -> None:
    result = run_persisted_memory_poisoning(tmp_path / "memory.db")
    assert result.blocked and not result.executed


def test_persisted_memory_attribution_survives_reload(tmp_path) -> None:
    result = run_persisted_memory_poisoning(tmp_path / "memory.db")
    assert result.attribution.source_name == "poisoned_memory"


def test_controlled_tamper_detected(tmp_path) -> None:
    assert run_tamper_detection(tmp_path / "tamper.db")


def test_persistence_benchmark_is_measured(tmp_path) -> None:
    benchmark = run_persistence_benchmark(tmp_path)
    assert benchmark.persisted_attack_attempts == 2
    assert benchmark.persisted_unauthorized_executions == 0
    assert benchmark.attributions_after_reload == 2
    assert benchmark.integrity_failures_detected == 1


def test_persistence_benchmark_records_local_timings(tmp_path) -> None:
    benchmark = run_persistence_benchmark(tmp_path)
    assert benchmark.persistence_latency_ms >= 0
    assert benchmark.checkpoint_latency_ms >= 0
    assert benchmark.reload_latency_ms >= 0


def test_persistence_benchmark_renderer(tmp_path) -> None:
    rendered = run_persistence_benchmark(tmp_path).render()
    assert "AgentShield Stage 8 Persistence Benchmark" in rendered
    assert "Persisted unauthorized executions: 0" in rendered
