from agentshield.models import ContextItem, ModelContext
from agentshield.runtime import TrustBoundary


def item(name: str, boundary: TrustBoundary, event_id: str) -> ContextItem:
    return ContextItem(name, f"content-{name}", boundary, event_id)


def test_context_keeps_source_categories_separate() -> None:
    context = ModelContext(
        system_instructions=(item("system", TrustBoundary.SYSTEM, "s"),),
        user_instruction=item("user", TrustBoundary.USER, "u"),
        retrieved_sources=(item("doc", TrustBoundary.LOCAL_UNTRUSTED, "r"),),
        memories=(item("memory", TrustBoundary.MEMORY, "m"),),
        tool_outputs=(item("tool", TrustBoundary.TOOL, "t"),),
    )
    assert context.material_event_ids == ("s", "u", "r", "m", "t")


def test_context_deduplicates_material_event_ids() -> None:
    context = ModelContext(retrieved_sources=(item("a", TrustBoundary.LOCAL_TRUSTED, "same"), item("b", TrustBoundary.LOCAL_TRUSTED, "same")))
    assert context.material_event_ids == ("same",)


def test_render_marks_sources() -> None:
    context = ModelContext(user_instruction=item("alice", TrustBoundary.USER, "u"), retrieved_sources=(item("report", TrustBoundary.LOCAL_UNTRUSTED, "r"),))
    rendered = context.render_for_model()
    assert "[USER source=alice]" in rendered
    assert "[RETRIEVED source=report]" in rendered
