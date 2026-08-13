import pytest

from agentshield import EventType, ProvenanceRecord, SecurityEvent, TrustLevel
from agentshield.core.provenance import ProvenanceTracker
from agentshield.exceptions import DuplicateEventError, UnknownParentError


def source_event(trust: TrustLevel = TrustLevel.UNTRUSTED) -> SecurityEvent:
    return SecurityEvent(
        EventType.RETRIEVAL,
        "retriever",
        provenance=ProvenanceRecord(
            original_source="malicious_document",
            trust_level=trust,
            externally_influenced=True,
        ),
    )


def test_build_provenance_inherits_untrusted_source() -> None:
    tracker = ProvenanceTracker()
    parent = source_event()
    tracker.register(parent)
    provenance = tracker.build_provenance((parent.id,))
    assert provenance.trust_level is TrustLevel.UNTRUSTED
    assert provenance.original_source == "malicious_document"
    assert provenance.externally_influenced


def test_propagation_path_grows_across_events() -> None:
    tracker = ProvenanceTracker()
    root = source_event()
    tracker.register(root)
    child = SecurityEvent(
        EventType.MODEL_OUTPUT,
        "model_context",
        parent_ids=(root.id,),
        provenance=tracker.build_provenance((root.id,)),
    )
    tracker.register(child)
    grandchild = tracker.build_provenance((child.id,))
    assert grandchild.propagation_path == (root.id, child.id)


def test_chain_reconstruction_is_causal() -> None:
    tracker = ProvenanceTracker()
    root = source_event()
    tracker.register(root)
    child = SecurityEvent(EventType.MODEL_OUTPUT, "model", parent_ids=(root.id,))
    tracker.register(child)
    leaf = SecurityEvent(EventType.TOOL_REQUEST, "planner", parent_ids=(child.id,))
    tracker.register(leaf)
    assert [event.id for event in tracker.propagation_chain(leaf.id)] == [
        root.id,
        child.id,
        leaf.id,
    ]


def test_multiple_parents_use_least_trusted_level() -> None:
    tracker = ProvenanceTracker()
    trusted = source_event(TrustLevel.TRUSTED)
    untrusted = source_event(TrustLevel.UNTRUSTED)
    tracker.register(trusted)
    tracker.register(untrusted)
    result = tracker.build_provenance((trusted.id, untrusted.id))
    assert result.trust_level is TrustLevel.UNTRUSTED


def test_unknown_parent_is_rejected() -> None:
    tracker = ProvenanceTracker()
    child = SecurityEvent(EventType.MODEL_OUTPUT, "model", parent_ids=("missing",))
    with pytest.raises(UnknownParentError):
        tracker.register(child)


def test_duplicate_event_is_rejected() -> None:
    tracker = ProvenanceTracker()
    event = source_event()
    tracker.register(event)
    with pytest.raises(DuplicateEventError):
        tracker.register(event)
