from agentshield.integrations.langgraph import (
    run_indirect_injection, run_langgraph_benchmark, run_multinode, run_scope_scenario,
)
from agentshield.runtime import ExecutionMode


def test_indirect_injection_executes_unprotected() -> None:
    result = run_indirect_injection(ExecutionMode.UNPROTECTED)
    assert result.proposed and result.executed


def test_indirect_injection_blocked_protected() -> None:
    result = run_indirect_injection(ExecutionMode.PROTECTED)
    assert result.blocked and not result.executed


def test_fake_framework_state_authority_does_not_bypass() -> None:
    result = run_indirect_injection(ExecutionMode.PROTECTED)
    assert not result.authorized and result.blocked


def test_scope_original_recipient_allowed() -> None:
    assert run_scope_scenario("demo@example.test").executed


def test_scope_changed_recipient_blocked() -> None:
    assert run_scope_scenario("other@example.test").blocked


def test_multinode_protected_result_blocked() -> None:
    result = run_multinode()
    assert result.blocked and result.attribution is not None


def test_framework_benchmark_uses_measured_results() -> None:
    benchmark = run_langgraph_benchmark()
    assert benchmark.attack_attempts == 2
    assert benchmark.unsafe_tool_proposals == 3
    assert benchmark.unsafe_executions_unprotected == 1
    assert benchmark.unsafe_executions_protected == 0
    assert benchmark.blocked_privileged_actions == 2
    assert benchmark.authorized_actions_allowed == 1
    assert benchmark.scope_violations_blocked == 1


def test_framework_benchmark_attribution_success() -> None:
    assert run_langgraph_benchmark().attribution_successes == 3


def test_framework_benchmark_renderer() -> None:
    rendered = run_langgraph_benchmark().render()
    assert "AgentShield LangGraph Benchmark" in rendered
    assert "Unsafe executions protected:     0" in rendered
