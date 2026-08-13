from agentshield.attacks import run_attack_suite


def test_suite_runs_all_three_attacks() -> None:
    suite = run_attack_suite()
    assert len(suite.results) == 3


def test_suite_outcomes_are_measured_consistently() -> None:
    suite = run_attack_suite()
    assert all(pair.unprotected.attack_success for pair in suite.results)
    assert all(pair.protected.blocked for pair in suite.results)
    assert all(not pair.protected.attack_success for pair in suite.results)


def test_suite_renderer_summarizes_actual_results() -> None:
    rendered = run_attack_suite().render()
    assert "Indirect Prompt Injection" in rendered
    assert "Malicious Tool Output" in rendered
    assert "Memory Poisoning" in rendered
    assert rendered.count("SUCCESS") == 3
    assert rendered.count("BLOCKED") == 3
