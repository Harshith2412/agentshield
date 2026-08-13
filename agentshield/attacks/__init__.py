"""Controlled adversarial evaluations for the deterministic demo runtime."""

from agentshield.attacks.base import AttackCategory, AttackMetadata, AttackPayload, AttackScenario
from agentshield.attacks.evaluation import evaluate_pair, measure_attack
from agentshield.attacks.indirect_prompt_injection import IndirectPromptInjection
from agentshield.attacks.malicious_tool_output import MaliciousToolOutput
from agentshield.attacks.memory_poisoning import MemoryPoisoning
from agentshield.attacks.results import AttackResult, AttributionResult, AttributionStatus, PairedAttackResult
from agentshield.attacks.suite import ExperimentSuiteResult, run_attack_suite
from agentshield.attacks.benchmark import BenchmarkFailure, BenchmarkMetrics, BenchmarkReport, run_benchmark
from agentshield.attacks.corpus import AttackVariant, BenignVariant, load_attack_corpus, load_benign_corpus

__all__ = [
    "AttackCategory", "AttackMetadata", "AttackPayload", "AttackResult", "AttackScenario",
    "AttributionResult", "AttributionStatus", "ExperimentSuiteResult", "IndirectPromptInjection",
    "MaliciousToolOutput", "MemoryPoisoning", "PairedAttackResult", "evaluate_pair",
    "measure_attack", "run_attack_suite",
    "AttackVariant", "BenignVariant", "BenchmarkFailure", "BenchmarkMetrics", "BenchmarkReport",
    "load_attack_corpus", "load_benign_corpus", "run_benchmark",
]
