# Threat model

## Assets

User authority, tool capability boundaries, sensitive action scopes, provenance, influence relationships, checkpoint lineage, and persistent security state.

## Adversarial influences

Retrieved content, poisoned memory, compromised tool output, model-generated actions, framework state, stale or replayed checkpoints, and local persistence tampering are modeled. Data may propose privileged behavior but cannot mint authority.

## Assumptions

- AgentShield enforcement code and its policy configuration are trusted.
- Every consequential tool path is instrumented.
- Demo tools remain simulated.
- A caller-supplied HMAC key remains outside attacker control.
- The Python process, host OS, and trusted authority issuer are not compromised.

## Non-goals

Universal malicious-language recognition, model correctness, prevention after host compromise, protection for uninstrumented side effects, malware analysis, offensive automation, and perfect attribution in genuinely ambiguous causal graphs.

See [security-model.md](security-model.md) for enforceable guarantees and limitations.
