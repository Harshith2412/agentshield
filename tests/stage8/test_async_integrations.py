import asyncio

from agentshield import Capability, EventType
from agentshield.integrations.base import FrameworkContextItem, ToolSecurityMetadata
from agentshield.integrations.langgraph import FrameworkSource, LangGraphAdapter, LangGraphStateBridge
from agentshield.integrations.microsoft_agent_framework import MicrosoftAgentContextBridge, MicrosoftAgentFrameworkAdapter
from agentshield.runtime import AuthorizationGrant, EmailScope, TrustBoundary


def test_async_langgraph_node_preserves_provenance() -> None:
    bridge = LangGraphStateBridge(retrieved_sources=[FrameworkSource("doc", "x", TrustBoundary.LOCAL_UNTRUSTED, "r")])
    adapter = LangGraphAdapter(bridge=bridge)
    async def node(state): return state
    asyncio.run(adapter.instrument_node_async("async_node", node)({"agentshield_bridge": bridge}))
    output = next(e for e in adapter.trace.events if e.metadata.get("node") == "async_node" and e.metadata.get("framework_event") == "node_output")
    assert output.provenance.externally_influenced


def test_async_langgraph_blocked_tool_not_executed() -> None:
    bridge = LangGraphStateBridge(user_instruction=FrameworkSource("user", "x", TrustBoundary.USER, "u"))
    adapter = LangGraphAdapter(bridge=bridge); adapter.create_protected_tool("send_email", ToolSecurityMetadata(Capability.EMAIL_SEND, True))
    outcome = asyncio.run(adapter.invoke_tool_async("send_email", {"to": "x"}, {"agentshield_bridge": bridge}))
    assert not outcome.executed


def test_async_langgraph_scoped_tool_allowed() -> None:
    grant = AuthorizationGrant(Capability.EMAIL_SEND, EmailScope("demo@example.test"))
    bridge = LangGraphStateBridge(user_instruction=FrameworkSource("user", "x", TrustBoundary.USER, "u"), authorization_grants=(grant,))
    adapter = LangGraphAdapter(bridge=bridge); adapter.create_protected_tool("send_email", ToolSecurityMetadata(Capability.EMAIL_SEND, True))
    assert asyncio.run(adapter.invoke_tool_async("send_email", {"to": "demo@example.test"}, {"agentshield_bridge": bridge})).executed


def test_async_microsoft_agent_preserves_provenance() -> None:
    bridge = MicrosoftAgentContextBridge(retrieved_sources=[FrameworkContextItem("doc", "x", TrustBoundary.LOCAL_UNTRUSTED, "r")])
    adapter = MicrosoftAgentFrameworkAdapter(bridge=bridge)
    async def agent(state): return state
    asyncio.run(adapter.instrument_agent_async("async_agent", agent)({"agentshield_bridge": bridge}))
    output = next(e for e in adapter.trace.events if e.metadata.get("agent") == "async_agent" and e.metadata.get("framework_event") == "agent_output")
    assert output.provenance.externally_influenced


def test_async_microsoft_blocked_function_not_executed() -> None:
    bridge = MicrosoftAgentContextBridge(user_instruction=FrameworkContextItem("user", "x", TrustBoundary.USER, "u"))
    adapter = MicrosoftAgentFrameworkAdapter(bridge=bridge); adapter.create_protected_tool("send_email", ToolSecurityMetadata(Capability.EMAIL_SEND, True))
    outcome = asyncio.run(adapter.invoke_protected_async("send_email", {"to": "x"}, {"agentshield_bridge": bridge}))
    assert not outcome.executed


def test_async_microsoft_scoped_function_allowed() -> None:
    grant = AuthorizationGrant(Capability.EMAIL_SEND, EmailScope("demo@example.test"))
    bridge = MicrosoftAgentContextBridge(user_instruction=FrameworkContextItem("user", "x", TrustBoundary.USER, "u"), authorization_grants=(grant,))
    adapter = MicrosoftAgentFrameworkAdapter(bridge=bridge); adapter.create_protected_tool("send_email", ToolSecurityMetadata(Capability.EMAIL_SEND, True))
    assert asyncio.run(adapter.invoke_protected_async("send_email", {"to": "demo@example.test"}, {"agentshield_bridge": bridge})).executed


def test_async_framework_requests_are_marked_async() -> None:
    bridge = MicrosoftAgentContextBridge(user_instruction=FrameworkContextItem("user", "x", TrustBoundary.USER, "u"))
    adapter = MicrosoftAgentFrameworkAdapter(bridge=bridge); adapter.create_protected_tool("send_email", ToolSecurityMetadata(Capability.EMAIL_SEND, True))
    asyncio.run(adapter.invoke_protected_async("send_email", {"to": "x"}, {"agentshield_bridge": bridge}))
    request = next(e for e in adapter.trace.events if e.event_type is EventType.TOOL_REQUEST)
    assert request.metadata["async"] is True
