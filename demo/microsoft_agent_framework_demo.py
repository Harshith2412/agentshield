"""Offline Microsoft Agent Framework boundary scenarios using safe functions."""

from agentshield.integrations.microsoft_agent_framework import (
    run_indirect_injection, run_multi_agent, run_scope_scenario,
)
from agentshield.runtime import ExecutionMode


def main() -> None:
    unprotected = run_indirect_injection(ExecutionMode.UNPROTECTED)
    protected = run_indirect_injection(ExecutionMode.PROTECTED)
    allowed = run_scope_scenario("demo@example.test")
    blocked = run_scope_scenario("other@example.test")
    multi = run_multi_agent()
    print("AgentShield Microsoft Agent Framework Experiments")
    print("=================================================")
    print(f"Indirect unprotected executed: {unprotected.executed}")
    print(f"Indirect protected blocked:    {protected.blocked}")
    print(f"Scoped recipient allowed:      {allowed.executed}")
    print(f"Scope expansion blocked:       {blocked.blocked}")
    print(f"Multi-agent origin:            {multi.attribution.source_name}")
    print(f"Multi-agent action blocked:    {multi.blocked}")


if __name__ == "__main__":
    main()
