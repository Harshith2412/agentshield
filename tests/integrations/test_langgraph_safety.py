from pathlib import Path

from agentshield import Capability
from agentshield.integrations.langgraph import FrameworkSource, LangGraphAdapter, LangGraphStateBridge, ToolSecurityMetadata
from agentshield.runtime import ExecutionMode, ToolRegistry, TrustBoundary


def test_blocked_email_never_records_simulation() -> None:
    tools = ToolRegistry()
    bridge = LangGraphStateBridge(user_instruction=FrameworkSource("user", "summary", TrustBoundary.USER, "u"))
    adapter = LangGraphAdapter(tools=tools, bridge=bridge)
    tool = adapter.register_tool("send_email", ToolSecurityMetadata(Capability.EMAIL_SEND, True))
    outcome = tool.invoke({"to": "x.test"}, {"agentshield_bridge": bridge})
    assert not outcome.executed and not tools.simulated_emails


def test_unprotected_email_remains_simulated() -> None:
    tools = ToolRegistry()
    bridge = LangGraphStateBridge(user_instruction=FrameworkSource("user", "summary", TrustBoundary.USER, "u"))
    adapter = LangGraphAdapter(mode=ExecutionMode.UNPROTECTED, tools=tools, bridge=bridge)
    tool = adapter.register_tool("send_email", ToolSecurityMetadata(Capability.EMAIL_SEND, True))
    tool.invoke({"to": "x.test"}, {"agentshield_bridge": bridge})
    assert len(tools.simulated_emails) == 1


def test_framework_never_uses_state_tool_callable() -> None:
    called = False
    def bypass():
        nonlocal called
        called = True
    bridge = LangGraphStateBridge(user_instruction=FrameworkSource("user", "x", TrustBoundary.USER, "u"))
    adapter = LangGraphAdapter(bridge=bridge)
    adapter.register_tool("send_email", ToolSecurityMetadata(Capability.EMAIL_SEND, True)).invoke(
        {"to": "x.test"}, {"agentshield_bridge": bridge, "tool_callable": bypass}
    )
    assert not called


def test_no_global_langgraph_monkeypatch_attribute() -> None:
    import agentshield.integrations.langgraph.adapter as module
    assert not hasattr(module, "monkeypatch")


def test_tool_error_is_recorded_not_raised_unprotected() -> None:
    bridge = LangGraphStateBridge(user_instruction=FrameworkSource("user", "x", TrustBoundary.USER, "u"))
    adapter = LangGraphAdapter(mode=ExecutionMode.UNPROTECTED, bridge=bridge)
    tool = adapter.register_tool("send_email", ToolSecurityMetadata(Capability.EMAIL_SEND, True))
    outcome = tool.invoke({}, {"agentshield_bridge": bridge})
    assert outcome.result.status.value == "error"


def test_framework_adapter_has_no_network_or_shell_tool_path() -> None:
    bridge = LangGraphStateBridge(user_instruction=FrameworkSource("user", "x", TrustBoundary.USER, "u"))
    adapter = LangGraphAdapter(bridge=bridge)
    assert set(adapter.tools.names) == {"network_request", "read_document", "send_email", "shell_execute", "write_file"}
    # All are the Stage 2 simulations; the integration adds no framework-specific executor.
