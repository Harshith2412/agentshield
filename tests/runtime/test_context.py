from agentshield import Capability
from agentshield.core.provenance import TrustLevel
from agentshield.runtime import ExecutionMode, RunContext, TrustBoundary


def test_all_trust_boundaries_map_to_stage1_trust() -> None:
    assert TrustBoundary.USER.trust_level is TrustLevel.TRUSTED
    assert TrustBoundary.SYSTEM.trust_level is TrustLevel.TRUSTED
    assert TrustBoundary.LOCAL_TRUSTED.trust_level is TrustLevel.TRUSTED
    assert TrustBoundary.LOCAL_UNTRUSTED.trust_level is TrustLevel.UNTRUSTED
    assert TrustBoundary.EXTERNAL_UNTRUSTED.trust_level is TrustLevel.UNTRUSTED
    assert TrustBoundary.MEMORY.trust_level is TrustLevel.SEMI_TRUSTED
    assert TrustBoundary.TOOL.trust_level is TrustLevel.SEMI_TRUSTED


def test_run_context_tracks_authorized_capability() -> None:
    context = RunContext(ExecutionMode.PROTECTED, frozenset({Capability.EMAIL_SEND}))
    assert context.authorizes(Capability.EMAIL_SEND)
    assert not context.authorizes(Capability.SHELL_EXECUTE)


def test_run_ids_are_unique() -> None:
    assert RunContext(ExecutionMode.PROTECTED).run_id != RunContext(ExecutionMode.PROTECTED).run_id
