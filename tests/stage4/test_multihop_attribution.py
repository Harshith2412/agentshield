from agentshield import EventType
from agentshield.attacks import AttributionStatus, load_attack_corpus
from agentshield.runtime import ExecutionMode


def multihop(variant_id: str):
    return next(variant for variant in load_attack_corpus() if variant.variant_id == variant_id)


def test_document_multihop_preserves_original_source() -> None:
    result = multihop("HOP-DOCUMENT").run(ExecutionMode.PROTECTED)
    assert result.attribution.source_name == "multihop_document.txt"
    assert result.attribution.status is AttributionStatus.UNAMBIGUOUS


def test_tool_multihop_preserves_original_source() -> None:
    result = multihop("HOP-TOOL").run(ExecutionMode.PROTECTED)
    assert result.attribution.source_name == "compromised_lookup"


def test_multihop_path_crosses_memory_boundaries() -> None:
    types = multihop("HOP-DOCUMENT").run(ExecutionMode.PROTECTED).attribution.propagation_event_types
    assert EventType.MEMORY_WRITE in types
    assert EventType.MEMORY_READ in types
    assert types[-1] is EventType.TOOL_REQUEST


def test_multihop_models_earlier_and_later_phases() -> None:
    result = multihop("HOP-DOCUMENT").run(ExecutionMode.PROTECTED)
    phases = {event.metadata.get("phase") for event in result.trace.events}
    assert {"earlier_run", "later_run"}.issubset(phases)


def test_multiple_origins_return_ambiguous_attribution() -> None:
    attribution = multihop("HOP-AMBIGUOUS").run(ExecutionMode.PROTECTED).attribution
    assert attribution.status is AttributionStatus.AMBIGUOUS
    assert set(attribution.candidates) == {"primary_memory", "secondary_untrusted.txt"}
    assert attribution.confidence < 1.0


def test_ambiguous_attribution_does_not_fabricate_certainty() -> None:
    attribution = multihop("HOP-AMBIGUOUS").run(ExecutionMode.PROTECTED).attribution
    assert any("multiple distinct" in reason for reason in attribution.reasons)
