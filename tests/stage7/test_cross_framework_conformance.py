import pytest

from agentshield.integrations.comparison import conformance_for


FRAMEWORKS = ("langgraph", "microsoft_agent_framework")
INVARIANTS = (
    "untrusted_cannot_authorize", "model_cannot_authorize", "function_output_cannot_authorize",
    "protected_blocks_unauthorized", "valid_authority_allows", "scope_cannot_expand",
    "provenance_loss_fails_closed", "metadata_cannot_authorize",
)


@pytest.mark.parametrize("framework", FRAMEWORKS)
def test_adapter_conformance_passes_all_invariants(framework: str) -> None:
    result = conformance_for(framework)
    assert result.passed == 8
    assert result.failed == 0


@pytest.mark.parametrize("framework", FRAMEWORKS)
@pytest.mark.parametrize("invariant", INVARIANTS)
def test_named_security_invariant_passes(framework: str, invariant: str) -> None:
    result = conformance_for(framework)
    check = next(item for item in result.tests if item.name == invariant)
    assert check.passed, check.detail


@pytest.mark.parametrize("framework", FRAMEWORKS)
def test_conformance_reports_preservation_flags(framework: str) -> None:
    result = conformance_for(framework)
    assert result.provenance_preserved
    assert result.authority_preserved
    assert result.scope_enforced


def test_conformance_renderer_is_machine_result_driven() -> None:
    rendered = conformance_for("microsoft_agent_framework").render()
    assert "Passed: 8" in rendered and "Failed: 0" in rendered
