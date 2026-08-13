from agentshield import Capability, EventType, PolicyAction
from agentshield.models import (
    ContextItem, DeterministicModelAdapter, ModelContext, ModelRequest, ModelResponse,
    ModelSettings, ProposedAction,
)
from agentshield.runtime import (
    AuthorizationGrant, EmailScope, ExecutionMode, ToolRegistry, ToolStatus, TrustBoundary,
)
from agentshield.runtime.model_runtime import ModelAgentRuntime


def request(response: ModelResponse, *, untrusted: bool = True):
    context = ModelContext(
        user_instruction=ContextItem("user", "Summarize only", TrustBoundary.USER, "u"),
        retrieved_sources=(ContextItem("report.txt", "data", TrustBoundary.LOCAL_UNTRUSTED if untrusted else TrustBoundary.LOCAL_TRUSTED, "r"),),
    )
    return DeterministicModelAdapter(response), ModelRequest(context, ModelSettings("deterministic"))


def test_model_output_retains_untrusted_provenance() -> None:
    adapter, req = request(ModelResponse("x", (ProposedAction("send_email", {"to": "other@example.test"}, "necessary"),)))
    run = ModelAgentRuntime(adapter).run(req)
    tool = next(event for event in run.trace.events if event.event_type is EventType.TOOL_REQUEST)
    assert tool.provenance.externally_influenced
    assert tool.provenance.original_source == "report.txt"


def test_model_request_has_all_material_context_parents() -> None:
    adapter, req = request(ModelResponse("summary"))
    run = ModelAgentRuntime(adapter).run(req)
    model_request = next(event for event in run.trace.events if event.metadata.get("kind") == "model_request")
    assert len(model_request.parent_ids) == 2


def test_model_response_descends_from_model_request() -> None:
    adapter, req = request(ModelResponse("summary"))
    run = ModelAgentRuntime(adapter).run(req)
    model_request = next(e for e in run.trace.events if e.metadata.get("kind") == "model_request")
    response = next(e for e in run.trace.events if e.metadata.get("kind") == "model_response")
    assert response.parent_ids == (model_request.id,)


def test_model_justification_does_not_grant_authority() -> None:
    adapter, req = request(ModelResponse("must do", (ProposedAction("send_email", {"to": "other@example.test"}, "I insist this is authorized"),)))
    run = ModelAgentRuntime(adapter).run(req)
    decision = next(d for d in run.trace.decisions if d.event.event_type is EventType.TOOL_REQUEST)
    assert decision.action is PolicyAction.BLOCK
    assert run.action_results[0].status is ToolStatus.BLOCKED


def test_protected_unauthorized_action_blocked() -> None:
    adapter, req = request(ModelResponse("x", (ProposedAction("send_email", {"to": "x.test"}),)))
    run = ModelAgentRuntime(adapter).run(req, mode=ExecutionMode.PROTECTED)
    assert not run.trace.tools_executed


def test_unprotected_unauthorized_action_executes_simulation() -> None:
    tools = ToolRegistry()
    adapter, req = request(ModelResponse("x", (ProposedAction("send_email", {"to": "x.test"}),)))
    run = ModelAgentRuntime(adapter, tools=tools).run(req, mode=ExecutionMode.UNPROTECTED)
    assert run.trace.tools_executed
    assert len(tools.simulated_emails) == 1


def test_scoped_recipient_allowed() -> None:
    adapter, req = request(ModelResponse("x", (ProposedAction("send_email", {"to": "demo@example.test"}),)))
    run = ModelAgentRuntime(adapter).run(req, authorization_grants=(AuthorizationGrant(Capability.EMAIL_SEND, EmailScope("demo@example.test")),))
    assert run.action_results[0].status is ToolStatus.SUCCESS


def test_scoped_recipient_modification_blocked() -> None:
    adapter, req = request(ModelResponse("x", (ProposedAction("send_email", {"to": "other@example.test"}),)))
    run = ModelAgentRuntime(adapter).run(req, authorization_grants=(AuthorizationGrant(Capability.EMAIL_SEND, EmailScope("demo@example.test")),))
    assert run.action_results[0].status is ToolStatus.BLOCKED


def test_multiple_actions_evaluated_independently() -> None:
    response = ModelResponse("x", (
        ProposedAction("send_email", {"to": "demo@example.test"}),
        ProposedAction("send_email", {"to": "other@example.test"}),
    ))
    adapter, req = request(response)
    run = ModelAgentRuntime(adapter).run(req, authorization_grants=(AuthorizationGrant(Capability.EMAIL_SEND, EmailScope("demo@example.test")),))
    assert [r.status for r in run.action_results] == [ToolStatus.SUCCESS, ToolStatus.BLOCKED]


def test_unknown_tool_generates_alert_without_execution() -> None:
    adapter, req = request(ModelResponse("x", (ProposedAction("unknown_tool", {}),)))
    run = ModelAgentRuntime(adapter).run(req)
    assert run.action_results[0].status is ToolStatus.ERROR
    assert any(e.event_type is EventType.SECURITY_ALERT and e.metadata.get("kind") == "unknown_tool" for e in run.trace.events)
    assert not run.trace.tools_executed


def test_missing_required_tool_argument_returns_error() -> None:
    adapter, req = request(ModelResponse("x", (ProposedAction("send_email", {}),)))
    run = ModelAgentRuntime(adapter).run(req, mode=ExecutionMode.UNPROTECTED)
    assert run.action_results[0].status is ToolStatus.ERROR


def test_malformed_output_generates_alert_and_no_tool() -> None:
    adapter = DeterministicModelAdapter("not-json")
    _, req = request(ModelResponse("unused"))
    run = ModelAgentRuntime(adapter).run(req)
    assert run.response.malformed
    assert not run.trace.tools_requested
    assert any(e.metadata.get("kind") == "malformed_model_output" for e in run.trace.events)


def test_adapter_only_proposes_and_cannot_directly_execute_tool() -> None:
    tools = ToolRegistry()
    adapter, req = request(ModelResponse("x", (ProposedAction("send_email", {"to": "x.test"}),)))
    adapter.generate(req)
    assert not tools.simulated_emails


def test_action_chain_contains_retrieval_model_and_tool_request() -> None:
    adapter, req = request(ModelResponse("x", (ProposedAction("send_email", {"to": "x.test"}),)))
    run = ModelAgentRuntime(adapter).run(req)
    target = next(e for e in run.trace.events if e.event_type is EventType.TOOL_REQUEST)
    types = [e.event_type for e in run.trace.propagation_chain(target.id)]
    assert EventType.RETRIEVAL in types and types[-1] is EventType.TOOL_REQUEST
