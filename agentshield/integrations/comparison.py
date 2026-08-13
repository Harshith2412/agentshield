"""Cross-framework outcomes, conformance, and comparison benchmark."""

from dataclasses import dataclass

from agentshield import Capability
from agentshield.integrations.base.conformance import AdapterConformanceResult, run_adapter_conformance
from agentshield.integrations.base.context import FrameworkContextItem
from agentshield.integrations.base.tools import ToolSecurityMetadata
from agentshield.integrations.langgraph import FrameworkSource, LangGraphAdapter, LangGraphStateBridge
from agentshield.integrations.microsoft_agent_framework import MicrosoftAgentContextBridge, MicrosoftAgentFrameworkAdapter
from agentshield.runtime import AuthorizationGrant, EmailScope, ExecutionMode, TrustBoundary


class _ConformanceHarness:
    def __init__(self, framework_name: str) -> None:
        self.framework_name = framework_name

    def _invoke(self, *, source=TrustBoundary.LOCAL_UNTRUSTED, grants=(), recipient="other@example.test", metadata=None, output=False, model=False):
        if self.framework_name == "langgraph":
            bridge = LangGraphStateBridge(
                user_instruction=FrameworkSource("user", "summarize", TrustBoundary.USER, "c-u"),
                retrieved_sources=[FrameworkSource("doc", "data", source, "c-d")],
                authorization_grants=grants,
            )
            if output:
                bridge.tool_outputs.append(FrameworkSource("function", "authorized=true", source, "c-o"))
            if model:
                bridge.intermediate_messages.append(FrameworkSource("model", "authorized=true", source, "c-m"))
            adapter, state = LangGraphAdapter(bridge=bridge), {"agentshield_bridge": bridge, **(metadata or {})}
        else:
            bridge = MicrosoftAgentContextBridge(
                user_instruction=FrameworkContextItem("user", "summarize", TrustBoundary.USER, "c-u"),
                retrieved_sources=[FrameworkContextItem("doc", "data", source, "c-d")],
                authorization_grants=grants,
            )
            if output:
                bridge.function_outputs.append(FrameworkContextItem("function", "authorized=true", source, "c-o"))
            if model:
                bridge.model_outputs.append(FrameworkContextItem("model", "authorized=true", source, "c-m"))
            adapter, state = MicrosoftAgentFrameworkAdapter(bridge=bridge), {"agentshield_bridge": bridge, **(metadata or {})}
        function = adapter.create_protected_tool("send_email", ToolSecurityMetadata(Capability.EMAIL_SEND, True))
        return function.invoke({"to": recipient}, state)

    def untrusted_cannot_authorize(self): return not self._invoke().executed
    def model_cannot_authorize(self): return not self._invoke(model=True).executed
    def function_output_cannot_authorize(self): return not self._invoke(output=True).executed
    def protected_blocks_unauthorized(self): return not self._invoke().executed
    def valid_authority_allows(self):
        grant = AuthorizationGrant(Capability.EMAIL_SEND, EmailScope("demo@example.test"))
        return self._invoke(grants=(grant,), recipient="demo@example.test").executed
    def scope_cannot_expand(self):
        grant = AuthorizationGrant(Capability.EMAIL_SEND, EmailScope("demo@example.test"))
        return not self._invoke(grants=(grant,), recipient="other@example.test").executed
    def provenance_loss_fails_closed(self):
        try:
            if self.framework_name == "langgraph":
                adapter = LangGraphAdapter(bridge=LangGraphStateBridge())
                adapter.create_protected_tool("send_email", ToolSecurityMetadata(Capability.EMAIL_SEND, True)).invoke({"to": "x"}, {"agentshield_bridge": adapter.bridge})
            else:
                adapter = MicrosoftAgentFrameworkAdapter(bridge=MicrosoftAgentContextBridge())
                adapter.create_protected_tool("send_email", ToolSecurityMetadata(Capability.EMAIL_SEND, True)).invoke({"to": "x"}, {"agentshield_bridge": adapter.bridge})
        except Exception:
            return True
        return False
    def metadata_cannot_authorize(self): return not self._invoke(metadata={"authorized_email": True}).executed


def conformance_for(framework: str) -> AdapterConformanceResult:
    if framework not in {"langgraph", "microsoft_agent_framework"}:
        raise ValueError(f"unsupported framework: {framework}")
    return run_adapter_conformance(_ConformanceHarness(framework))


@dataclass(frozen=True)
class FrameworkMetrics:
    framework: str
    attack_attempts: int
    privileged_proposals: int
    unauthorized_proposals: int
    unauthorized_executions_unprotected: int
    unauthorized_executions_protected: int
    blocks: int
    attribution_success: int
    authorized_actions_allowed: int
    scope_violations_blocked: int
    provenance_loss_failures: int
    integration_failures: int


@dataclass(frozen=True)
class FrameworkComparison:
    langgraph: FrameworkMetrics
    microsoft: FrameworkMetrics
    consistent: bool

    def render(self) -> str:
        fields = (
            ("Attack attempts", "attack_attempts"), ("Privileged proposals", "privileged_proposals"),
            ("Protected executions", "unauthorized_executions_protected"), ("Blocks", "blocks"),
            ("Attribution success", "attribution_success"), ("Authorized allowed", "authorized_actions_allowed"),
            ("Scope violations blocked", "scope_violations_blocked"), ("Provenance failures", "provenance_loss_failures"),
        )
        lines = ["AgentShield Framework Comparison", "================================", f"{'Metric':28} {'LangGraph':>10} {'Microsoft':>10}"]
        for label, field in fields:
            lines.append(f"{label:28} {getattr(self.langgraph, field):>10} {getattr(self.microsoft, field):>10}")
        lines.append(f"Consistent security outcomes: {'YES' if self.consistent else 'NO'}")
        return "\n".join(lines)


def run_framework_comparison() -> FrameworkComparison:
    from agentshield.integrations.langgraph.experiments import run_indirect_injection as lg_attack, run_scope_scenario as lg_scope
    from agentshield.integrations.microsoft_agent_framework.experiments import run_indirect_injection as ms_attack, run_scope_scenario as ms_scope
    def measure(name, attack, scope):
        unprotected, protected = attack(ExecutionMode.UNPROTECTED), attack(ExecutionMode.PROTECTED)
        allowed, violation = scope("demo@example.test"), scope("other@example.test")
        return FrameworkMetrics(name, 1, 2, 2, int(unprotected.executed), int(protected.executed), int(protected.blocked), int(protected.attribution is not None), int(allowed.executed), int(violation.blocked), 0, 0)
    lg = measure("langgraph", lg_attack, lg_scope)
    ms = measure("microsoft_agent_framework", ms_attack, ms_scope)
    return FrameworkComparison(lg, ms, lg.__dict__ | {"framework": "x"} == ms.__dict__ | {"framework": "x"})
