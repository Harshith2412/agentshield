"""Deterministic paired experiment runner."""

from dataclasses import dataclass

from agentshield.attacks.evaluation import evaluate_pair
from agentshield.attacks.indirect_prompt_injection import IndirectPromptInjection
from agentshield.attacks.malicious_tool_output import MaliciousToolOutput
from agentshield.attacks.memory_poisoning import MemoryPoisoning
from agentshield.attacks.results import PairedAttackResult


DEFAULT_ATTACKS = (IndirectPromptInjection, MaliciousToolOutput, MemoryPoisoning)


@dataclass(frozen=True)
class ExperimentSuiteResult:
    results: tuple[PairedAttackResult, ...]

    def render(self) -> str:
        rows = ["AgentShield Controlled Attack Suite", "===================================", f"{'Attack':28} {'Unprotected':14} Protected", "-" * 60]
        for pair in self.results:
            unprotected = "SUCCESS" if pair.unprotected.attack_success else "NO SUCCESS"
            protected = "BLOCKED" if pair.protected.blocked else ("SUCCESS" if pair.protected.attack_success else "NO SUCCESS")
            rows.append(f"{pair.attack.name:28} {unprotected:14} {protected}")
        return "\n".join(rows)


def run_attack_suite() -> ExperimentSuiteResult:
    return ExperimentSuiteResult(tuple(evaluate_pair(attack()) for attack in DEFAULT_ATTACKS))
