import pytest

from agentshield import Capability
from agentshield.integrations.langgraph import (
    FrameworkSource, LangGraphAdapter, LangGraphStateBridge, LangGraphUnavailableError,
    StateBridgeError, ToolMappingError, ToolSecurityMetadata,
)
from agentshield.runtime import ExecutionMode, TrustBoundary


def bridge() -> LangGraphStateBridge:
    return LangGraphStateBridge(user_instruction=FrameworkSource("user", "summarize", TrustBoundary.USER, "fw-u"))


def test_adapter_initialization_is_framework_independent() -> None:
    adapter = LangGraphAdapter(bridge=bridge())
    assert adapter.context.mode is ExecutionMode.PROTECTED
    assert adapter.trace.events[0].metadata["framework_event"] == "graph_invocation"


def test_missing_optional_dependency_fails_cleanly(monkeypatch) -> None:
    import builtins
    original_import = builtins.__import__
    def blocked_import(name, *args, **kwargs):
        if name == "langgraph.graph":
            raise ImportError("simulated absent dependency")
        return original_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", blocked_import)
    adapter = LangGraphAdapter()
    with pytest.raises(LangGraphUnavailableError, match="optional"):
        adapter.compile_graph(lambda state_graph, current: None)


def test_builtin_tool_can_be_registered_with_metadata() -> None:
    adapter = LangGraphAdapter()
    wrapped = adapter.register_tool("send_email", ToolSecurityMetadata(Capability.EMAIL_SEND, True))
    assert wrapped.name == "send_email"


def test_unknown_runtime_tool_mapping_rejected() -> None:
    with pytest.raises(ToolMappingError, match="not registered"):
        LangGraphAdapter().register_tool("missing", ToolSecurityMetadata(Capability.EMAIL_SEND, True))


def test_capability_mapping_mismatch_rejected() -> None:
    with pytest.raises(ToolMappingError, match="mismatch"):
        LangGraphAdapter().register_tool("send_email", ToolSecurityMetadata(Capability.WRITE_LOCAL, True))


def test_unmapped_tool_cannot_be_invoked() -> None:
    adapter = LangGraphAdapter(bridge=bridge())
    with pytest.raises(ToolMappingError, match="no security mapping"):
        adapter.invoke_tool("send_email", {}, {"agentshield_bridge": bridge()})


def test_malformed_arguments_rejected() -> None:
    adapter = LangGraphAdapter(bridge=bridge())
    adapter.register_tool("send_email", ToolSecurityMetadata(Capability.EMAIL_SEND, True))
    with pytest.raises(ToolMappingError, match="mapping"):
        adapter.invoke_tool("send_email", [] , {"agentshield_bridge": bridge()})  # type: ignore[arg-type]


def test_missing_state_bridge_fails_closed() -> None:
    adapter = LangGraphAdapter()
    adapter.register_tool("send_email", ToolSecurityMetadata(Capability.EMAIL_SEND, True))
    with pytest.raises(StateBridgeError):
        adapter.invoke_tool("send_email", {"to": "x.test"}, {})


def test_wrapper_direct_call_cannot_bypass_state() -> None:
    wrapped = LangGraphAdapter().register_tool("send_email", ToolSecurityMetadata(Capability.EMAIL_SEND, True))
    with pytest.raises(StateBridgeError, match="explicit graph state"):
        wrapped(to="x.test")


def test_custom_simulated_tool_wrapping() -> None:
    adapter = LangGraphAdapter(bridge=bridge())
    wrapped = adapter.wrap_tool("safe_custom", lambda args: {"ok": True}, ToolSecurityMetadata(Capability.NETWORK_READ, False))
    outcome = wrapped.invoke({}, {"agentshield_bridge": bridge()})
    assert outcome.executed


def test_wrapped_handler_not_called_when_policy_blocks() -> None:
    calls = []
    state_bridge = bridge()
    adapter = LangGraphAdapter(bridge=state_bridge)
    tool = adapter.wrap_tool(
        "dangerous_simulation", lambda args: calls.append(dict(args)) or "done",
        ToolSecurityMetadata(Capability.EMAIL_SEND, True),
    )
    outcome = tool.invoke({"to": "x.test"}, {"agentshield_bridge": state_bridge})
    assert not outcome.executed
    assert calls == []
