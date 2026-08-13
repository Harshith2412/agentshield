import asyncio

import pytest

from agentshield import AgentShield, Capability, EventType, PolicyAction, ProvenanceRecord, SecurityEvent, TrustLevel
from agentshield.runtime import (
    AsyncInstrumentedExecutor, AuthorizationGrant, AuthorityLifetime, EmailScope, ExecutionMode,
    RunContext, RuntimeInstrumentation, ToolDefinition, ToolRegistry, ToolRequest, ToolStatus, TrustBoundary,
)
from agentshield.runtime.tools import SideEffectLevel


def root(instrumentation):
    return instrumentation.emit(EventType.USER_INPUT, "user", boundary=TrustBoundary.USER)[0]


def test_evaluate_async_matches_sync_decision() -> None:
    event1 = SecurityEvent(EventType.TOOL_REQUEST, "planner", capability=Capability.EMAIL_SEND, provenance=ProvenanceRecord(trust_level=TrustLevel.UNTRUSTED, externally_influenced=True))
    event2 = SecurityEvent(EventType.TOOL_REQUEST, "planner", capability=Capability.EMAIL_SEND, provenance=ProvenanceRecord(trust_level=TrustLevel.UNTRUSTED, externally_influenced=True))
    sync = AgentShield().evaluate(event1)
    async_result = asyncio.run(AgentShield().evaluate_async(event2))
    assert (sync.action, sync.risk.score, sync.reasons) == (async_result.action, async_result.risk.score, async_result.reasons)


def test_async_block_happens_before_handler_starts() -> None:
    calls = []
    async def handler(arguments): calls.append("started"); return "done"
    tools = ToolRegistry()
    tools.register(ToolDefinition("async_email", Capability.EMAIL_SEND, SideEffectLevel.EXTERNAL_SIMULATED, handler))
    instrumentation = RuntimeInstrumentation(AgentShield(), RunContext(ExecutionMode.PROTECTED))
    parent = root(instrumentation)
    result, _ = asyncio.run(AsyncInstrumentedExecutor(tools, instrumentation).execute_async(ToolRequest("async_email", {}), (parent.id,)))
    assert result.status is ToolStatus.BLOCKED
    assert calls == []


def test_async_authorized_handler_executes() -> None:
    calls = []
    async def handler(arguments): calls.append(arguments["to"]); return "done"
    tools = ToolRegistry()
    tools.register(ToolDefinition("async_email", Capability.EMAIL_SEND, SideEffectLevel.EXTERNAL_SIMULATED, handler))
    grant = AuthorizationGrant(Capability.EMAIL_SEND, EmailScope("demo@example.test"))
    instrumentation = RuntimeInstrumentation(AgentShield(), RunContext(ExecutionMode.PROTECTED, authorization_grants=(grant,)))
    parent = root(instrumentation)
    result, _ = asyncio.run(AsyncInstrumentedExecutor(tools, instrumentation).execute_async(ToolRequest("async_email", {"to": "demo@example.test"}), (parent.id,)))
    assert result.status is ToolStatus.SUCCESS and calls == ["demo@example.test"]


def test_concurrent_actions_keep_independent_authority() -> None:
    grant = AuthorizationGrant(Capability.WRITE_LOCAL)
    instrumentation = RuntimeInstrumentation(AgentShield(), RunContext(ExecutionMode.PROTECTED, authorization_grants=(grant,)))
    parent = root(instrumentation)
    requests = (
        ToolRequest("read_document", {"name": "notes"}),
        ToolRequest("send_email", {"to": "x.test"}),
        ToolRequest("write_file", {"path": "reports/x", "content": "ok"}),
    )
    tools = ToolRegistry({"notes": "safe"})
    results = asyncio.run(AsyncInstrumentedExecutor(tools, instrumentation).execute_many(requests, (parent.id,)))
    assert [item[0].status for item in results] == [ToolStatus.SUCCESS, ToolStatus.BLOCKED, ToolStatus.SUCCESS]


def test_concurrent_one_shot_grant_allows_only_one() -> None:
    grant = AuthorizationGrant(Capability.EMAIL_SEND, EmailScope("demo@example.test"), AuthorityLifetime.ONE_SHOT)
    instrumentation = RuntimeInstrumentation(AgentShield(), RunContext(ExecutionMode.PROTECTED, authorization_grants=(grant,)))
    parent = root(instrumentation)
    requests = tuple(ToolRequest("send_email", {"to": "demo@example.test"}) for _ in range(2))
    results = asyncio.run(AsyncInstrumentedExecutor(ToolRegistry(), instrumentation).execute_many(requests, (parent.id,)))
    assert sorted(item[0].status.value for item in results) == ["blocked", "success"]


@pytest.mark.parametrize("count", [1, 2, 4, 8])
def test_concurrent_untrusted_retrievals_remain_separate(count: int) -> None:
    instrumentation = RuntimeInstrumentation(AgentShield(), RunContext(ExecutionMode.PROTECTED))
    parent = root(instrumentation)
    events = [instrumentation.emit(EventType.RETRIEVAL, f"doc-{i}", parent_ids=(parent.id,), boundary=TrustBoundary.EXTERNAL_UNTRUSTED)[0] for i in range(count)]
    assert len({event.id for event in events}) == count
    assert all(event.provenance.externally_influenced for event in events)


def test_incomplete_provenance_async_fails_before_execution() -> None:
    instrumentation = RuntimeInstrumentation(AgentShield(), RunContext(ExecutionMode.PROTECTED))
    with pytest.raises(Exception):
        asyncio.run(AsyncInstrumentedExecutor(ToolRegistry(), instrumentation).execute_async(ToolRequest("send_email", {"to": "x"}), ("missing",)))
    assert not instrumentation.trace.tools_executed


def test_async_tool_error_recorded() -> None:
    async def handler(arguments): raise ValueError("controlled error")
    tools = ToolRegistry(); tools.register(ToolDefinition("async_read", Capability.NETWORK_READ, SideEffectLevel.NONE, handler))
    instrumentation = RuntimeInstrumentation(AgentShield(), RunContext(ExecutionMode.PROTECTED)); parent = root(instrumentation)
    result, _ = asyncio.run(AsyncInstrumentedExecutor(tools, instrumentation).execute_async(ToolRequest("async_read", {}), (parent.id,)))
    assert result.status is ToolStatus.ERROR


def test_two_requests_share_run_but_not_decision() -> None:
    instrumentation = RuntimeInstrumentation(AgentShield(), RunContext(ExecutionMode.PROTECTED)); parent = root(instrumentation)
    executor = AsyncInstrumentedExecutor(ToolRegistry({"n": "x"}), instrumentation)
    results = asyncio.run(executor.execute_many((ToolRequest("read_document", {"name": "n"}), ToolRequest("send_email", {"to": "x"})), (parent.id,)))
    assert results[0][0].status is ToolStatus.SUCCESS and results[1][0].status is ToolStatus.BLOCKED


@pytest.mark.parametrize("capability,expected", [(Capability.NETWORK_READ, PolicyAction.ALLOW), (Capability.EMAIL_SEND, PolicyAction.BLOCK), (Capability.SHELL_EXECUTE, PolicyAction.REVIEW)])
def test_async_policy_equivalence_by_capability(capability, expected) -> None:
    event = SecurityEvent(EventType.TOOL_REQUEST, "async", capability=capability, provenance=ProvenanceRecord(trust_level=TrustLevel.TRUSTED))
    assert asyncio.run(AgentShield().evaluate_async(event)).action is expected
