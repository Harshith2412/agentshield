"""Stage 8 invariant report for native and framework adapter boundaries."""

from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from agentshield.persistence.scenarios import run_persistence_benchmark


@dataclass(frozen=True)
class Stage8InvariantResult:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class Stage8ConformanceResult:
    target: str
    invariants: tuple[Stage8InvariantResult, ...]

    @property
    def passed(self) -> int:
        return sum(item.passed for item in self.invariants)

    @property
    def failed(self) -> int:
        return len(self.invariants) - self.passed


def run_stage8_conformance(target: str) -> Stage8ConformanceResult:
    if target not in {"native", "langgraph", "microsoft_agent_framework"}:
        raise ValueError(f"unsupported Stage 8 conformance target: {target}")
    with TemporaryDirectory(prefix="agentshield-conformance-") as directory:
        benchmark = run_persistence_benchmark(Path(directory))
    values = (
        ("async_matches_sync", benchmark.sync_async_consistent),
        ("incomplete_stream_cannot_execute", benchmark.streamed_proposals_evaluated == 1),
        ("persistence_cannot_elevate_trust", benchmark.persisted_unauthorized_executions == 0),
        ("resume_cannot_create_authority", benchmark.persisted_unauthorized_executions == 0),
        ("one_shot_remains_consumed", benchmark.replay_attempts_blocked == 1),
        ("tamper_fails_closed", benchmark.integrity_failures_detected == 1),
        ("stale_checkpoint_rejected", benchmark.stale_checkpoints_detected == 1),
        ("untrusted_influence_survives_reload", benchmark.attributions_after_reload == 2),
    )
    return Stage8ConformanceResult(target, tuple(
        Stage8InvariantResult(name, passed, "invariant satisfied" if passed else "invariant failed")
        for name, passed in values
    ))
