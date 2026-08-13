import asyncio
from types import SimpleNamespace

import pytest

from agentshield import Capability, PolicyAction
from agentshield.integrations.base import FrameworkContextItem, ToolSecurityMetadata
from agentshield.integrations.microsoft_agent_framework import (
    MicrosoftAgentContextBridge, MicrosoftAgentFrameworkAdapter, MicrosoftAgentFrameworkError,
    MicrosoftAgentFrameworkUnavailableError,
)
from agentshield.runtime import AuthorizationGrant, EmailScope, ExecutionMode, TrustBoundary


def bridge(grants=()) -> MicrosoftAgentContextBridge:
    return MicrosoftAgentContextBridge(
        user_instruction=FrameworkContextItem("user", "summary", TrustBoundary.USER, "u"),
        retrieved_sources=[FrameworkContextItem("doc", "data", TrustBoundary.LOCAL_UNTRUSTED, "d")],
        authorization_grants=grants,
        agent_name="report_agent",
    )


def test_microsoft_adapter_initializes_without_dependency() -> None:
    adapter = MicrosoftAgentFrameworkAdapter(bridge=bridge())
    assert adapter.trace.events


def test_dependency_absence_fails_cleanly(monkeypatch) -> None:
    import builtins
    original = builtins.__import__
    monkeypatch.setattr(builtins, "__import__", lambda name, *a, **k: (_ for _ in ()).throw(ImportError()) if name == "agent_framework" else original(name, *a, **k))
    with pytest.raises(MicrosoftAgentFrameworkUnavailableError):
        MicrosoftAgentFrameworkAdapter().ensure_dependency()


def test_unknown_function_mapping_rejected() -> None:
    with pytest.raises(MicrosoftAgentFrameworkError, match="not registered"):
        MicrosoftAgentFrameworkAdapter().create_protected_tool("missing", ToolSecurityMetadata(Capability.EMAIL_SEND, True))


def test_capability_mapping_mismatch_rejected() -> None:
    with pytest.raises(MicrosoftAgentFrameworkError, match="mismatch"):
        MicrosoftAgentFrameworkAdapter().create_protected_tool("send_email", ToolSecurityMetadata(Capability.WRITE_LOCAL, True))


def test_protected_function_blocks_unauthorized_call() -> None:
    state_bridge = bridge()
    adapter = MicrosoftAgentFrameworkAdapter(bridge=state_bridge)
    function = adapter.create_protected_tool("send_email", ToolSecurityMetadata(Capability.EMAIL_SEND, True))
    outcome = function.invoke({"to": "x.test"}, {"agentshield_bridge": state_bridge})
    assert outcome.decision is PolicyAction.BLOCK and not outcome.executed


def test_protected_function_allows_scoped_call() -> None:
    grant = AuthorizationGrant(Capability.EMAIL_SEND, EmailScope("demo@example.test"))
    state_bridge = bridge((grant,))
    adapter = MicrosoftAgentFrameworkAdapter(bridge=state_bridge)
    outcome = adapter.create_protected_tool("send_email", ToolSecurityMetadata(Capability.EMAIL_SEND, True)).invoke(
        {"to": "demo@example.test"}, {"agentshield_bridge": state_bridge}
    )
    assert outcome.executed


def test_malformed_arguments_rejected() -> None:
    state_bridge = bridge()
    adapter = MicrosoftAgentFrameworkAdapter(bridge=state_bridge)
    adapter.create_protected_tool("send_email", ToolSecurityMetadata(Capability.EMAIL_SEND, True))
    with pytest.raises(MicrosoftAgentFrameworkError, match="mapping"):
        adapter.invoke_protected("send_email", [], {"agentshield_bridge": state_bridge})  # type: ignore[arg-type]


def test_context_missing_bridge_rejected() -> None:
    with pytest.raises(MicrosoftAgentFrameworkError):
        MicrosoftAgentFrameworkAdapter().map_context({})


def test_agent_middleware_calls_next() -> None:
    state_bridge = bridge()
    adapter = MicrosoftAgentFrameworkAdapter(bridge=state_bridge)
    async def call_next(context): return "next-result"
    result = asyncio.run(adapter.agent_middleware()(SimpleNamespace(state={"agentshield_bridge": state_bridge}), call_next))
    assert result == "next-result"


def test_function_middleware_withholds_blocked_call() -> None:
    state_bridge = bridge()
    adapter = MicrosoftAgentFrameworkAdapter(bridge=state_bridge)
    adapter.create_protected_tool("send_email", ToolSecurityMetadata(Capability.EMAIL_SEND, True))
    called = []
    async def call_next(context): called.append(True); return "executed"
    context = SimpleNamespace(function_name="send_email", arguments={"to": "x.test"}, state={"agentshield_bridge": state_bridge})
    result = asyncio.run(adapter.function_middleware()(context, call_next))
    assert not result.executed and called == []


def test_function_middleware_calls_next_when_allowed() -> None:
    grant = AuthorizationGrant(Capability.EMAIL_SEND, EmailScope("demo@example.test"))
    state_bridge = bridge((grant,))
    adapter = MicrosoftAgentFrameworkAdapter(bridge=state_bridge)
    adapter.create_protected_tool("send_email", ToolSecurityMetadata(Capability.EMAIL_SEND, True))
    async def call_next(context): return "framework-result"
    context = SimpleNamespace(function_name="send_email", arguments={"to": "demo@example.test"}, state={"agentshield_bridge": state_bridge})
    assert asyncio.run(adapter.function_middleware()(context, call_next)) == "framework-result"


@pytest.mark.parametrize("context", [SimpleNamespace(), SimpleNamespace(function_name="send_email"), SimpleNamespace(function_name="send_email", arguments={})])
def test_malformed_middleware_context_fails_closed(context) -> None:
    async def next_call(value): return value
    with pytest.raises(MicrosoftAgentFrameworkError):
        asyncio.run(MicrosoftAgentFrameworkAdapter().function_middleware()(context, next_call))
