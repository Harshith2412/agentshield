"""Reusable adapter security invariant runner."""

from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityInvariantResult:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class AdapterConformanceResult:
    framework: str
    tests: tuple[SecurityInvariantResult, ...]
    provenance_preserved: bool
    authority_preserved: bool
    scope_enforced: bool

    @property
    def passed(self) -> int:
        return sum(item.passed for item in self.tests)

    @property
    def failed(self) -> int:
        return len(self.tests) - self.passed

    def render(self) -> str:
        return "\n".join([
            f"AgentShield Adapter Conformance: {self.framework}",
            f"Passed: {self.passed}", f"Failed: {self.failed}",
            *[f"{'PASS' if item.passed else 'FAIL'} {item.name}: {item.detail}" for item in self.tests],
        ])


def run_adapter_conformance(harness) -> AdapterConformanceResult:
    checks = (
        ("untrusted_cannot_authorize", harness.untrusted_cannot_authorize),
        ("model_cannot_authorize", harness.model_cannot_authorize),
        ("function_output_cannot_authorize", harness.function_output_cannot_authorize),
        ("protected_blocks_unauthorized", harness.protected_blocks_unauthorized),
        ("valid_authority_allows", harness.valid_authority_allows),
        ("scope_cannot_expand", harness.scope_cannot_expand),
        ("provenance_loss_fails_closed", harness.provenance_loss_fails_closed),
        ("metadata_cannot_authorize", harness.metadata_cannot_authorize),
    )
    results: list[SecurityInvariantResult] = []
    for name, check in checks:
        try:
            passed = bool(check())
            detail = "invariant satisfied" if passed else "invariant failed"
        except Exception as exc:
            passed, detail = False, f"integration error: {exc}"
        results.append(SecurityInvariantResult(name, passed, detail))
    return AdapterConformanceResult(
        harness.framework_name, tuple(results),
        results[0].passed and results[6].passed,
        all(results[i].passed for i in (0, 1, 2, 3, 4, 7)),
        results[5].passed,
    )
