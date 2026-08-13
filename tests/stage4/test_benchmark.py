from dataclasses import replace

from agentshield.attacks import load_attack_corpus, run_benchmark
from agentshield.runtime import ExecutionMode


def test_benchmark_counts_actual_corpora() -> None:
    metrics = run_benchmark().metrics
    assert metrics.total_attack_variants == 27
    assert metrics.benign_scenarios == 15


def test_benchmark_separates_detection_and_mitigation() -> None:
    metrics = run_benchmark().metrics
    assert metrics.attack_detection_rate == 1.0
    assert metrics.attack_mitigation_rate == 1.0


def test_benchmark_reports_no_false_negatives() -> None:
    report = run_benchmark()
    assert report.metrics.false_negatives == 0
    assert report.metrics.attacks_successful_protected == 0


def test_benchmark_reports_no_false_positives() -> None:
    metrics = run_benchmark().metrics
    assert metrics.false_positives == 0
    assert metrics.false_positive_rate == 0.0


def test_attribution_rate_excludes_ambiguous_case() -> None:
    metrics = run_benchmark().metrics
    assert metrics.ambiguous_attributions == 1
    assert metrics.attribution_success_rate == 26 / 27


def test_average_path_length_is_measured() -> None:
    metrics = run_benchmark().metrics
    assert metrics.average_attribution_path_length > 3


def test_per_family_metrics_cover_every_variant() -> None:
    metrics = run_benchmark().metrics
    assert sum(family.variants for family in metrics.per_family) == metrics.total_attack_variants
    assert all(family.false_negatives == 0 for family in metrics.per_family)


def test_benchmark_has_no_hidden_failures() -> None:
    assert run_benchmark().failures == ()


def test_failure_analysis_records_deliberate_false_negative() -> None:
    original = load_attack_corpus()[0]
    broken = replace(original, _runner=lambda variant, mode: original.run(ExecutionMode.UNPROTECTED))
    report = run_benchmark((broken,), ())
    assert report.metrics.false_negatives == 1
    assert len(report.failures) == 1
    failure = report.failures[0]
    assert failure.variant_id == original.variant_id
    assert failure.target_capability == original.target_capability
    assert failure.provenance_path
    assert failure.influence_set


def test_benchmark_renderer_uses_computed_values() -> None:
    rendered = run_benchmark().render()
    assert "Attack variants:             27" in rendered
    assert "False positives:             0" in rendered
    assert "Attribution success:         96.3%" in rendered
