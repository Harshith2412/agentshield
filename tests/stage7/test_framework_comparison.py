from agentshield.integrations.comparison import run_framework_comparison


def test_cross_framework_outcomes_are_consistent() -> None:
    assert run_framework_comparison().consistent


def test_both_frameworks_block_protected_execution() -> None:
    comparison = run_framework_comparison()
    assert comparison.langgraph.unauthorized_executions_protected == 0
    assert comparison.microsoft.unauthorized_executions_protected == 0


def test_both_frameworks_allow_authorized_action() -> None:
    comparison = run_framework_comparison()
    assert comparison.langgraph.authorized_actions_allowed == 1
    assert comparison.microsoft.authorized_actions_allowed == 1


def test_both_frameworks_block_scope_violation() -> None:
    comparison = run_framework_comparison()
    assert comparison.langgraph.scope_violations_blocked == 1
    assert comparison.microsoft.scope_violations_blocked == 1


def test_both_frameworks_attribute_attack_source() -> None:
    comparison = run_framework_comparison()
    assert comparison.langgraph.attribution_success == 1
    assert comparison.microsoft.attribution_success == 1


def test_comparison_keeps_framework_metrics_separate() -> None:
    comparison = run_framework_comparison()
    assert comparison.langgraph.framework == "langgraph"
    assert comparison.microsoft.framework == "microsoft_agent_framework"


def test_comparison_renderer_has_both_columns() -> None:
    rendered = run_framework_comparison().render()
    assert "LangGraph" in rendered and "Microsoft" in rendered
    assert "Consistent security outcomes: YES" in rendered
