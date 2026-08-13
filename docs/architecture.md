# Architecture

AgentShield is framework-independent. `core` evaluates immutable security events and provenance; `runtime` captures causal influence and intercepts tool requests; `attacks` supplies controlled corpora; experimental `integrations` translate framework state into neutral contracts; experimental `persistence` stores traces and checkpoints.

The trusted path is: input registration → causal propagation → model proposal parsing → tool interception → authority/scope evaluation → simulated execution or block → attribution. Protected tools must not be reachable through an uninstrumented alternate path.

The core does not import optional frameworks, model providers, or network clients. Adapters depend inward on neutral contracts, preserving base-install isolation.
