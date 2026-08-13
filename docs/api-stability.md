# API stability

## Public API

The names in `agentshield.__all__` and documented runtime names in `agentshield.runtime.__all__` are intended v0.1 public contracts. Compatible additions may occur; breaking changes require release notes.

## Experimental API

`agentshield.integrations`, `agentshield.persistence`, `agentshield.experiments`, model experiment helpers, benchmark result schemas beyond their JSON envelope, and adapter-specific state bridges may change during the 0.1 series.

## Internal API

Undocumented modules, underscore-prefixed names, scenario runners, instrumentation implementation details, and test harnesses are internal. Explicit `__all__` declarations communicate export intent; module accessibility alone is not a stability promise.
