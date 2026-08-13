# Security model

## What AgentShield enforces

- privileged capabilities require trusted authority in protected mode;
- authorization grants cannot exceed their capability scope or lifetime;
- untrusted and model-generated content cannot create authority;
- provenance and causal influence propagate across instrumented runtime boundaries;
- protected tool calls are evaluated immediately before execution;
- one-shot grants remain consumed after persistence and restore;
- stale checkpoints are rejected by default;
- persisted trace modification, removal, reordering, or chain breakage fails integrity validation.

## What AgentShield does not guarantee

- semantic detection of every malicious instruction;
- correctness or honesty of model output;
- security after process, key, or host compromise;
- protection across arbitrary uninstrumented tools;
- confidentiality or encryption of persisted data;
- perfect attribution when multiple causal sources are valid;
- production readiness or regulatory certification.

SHA-256 chains detect accidental or unkeyed modification when the trusted head is protected. HMAC improves authenticity only when its key is stored separately and securely.
