# Framework integrations

LangGraph and Microsoft Agent Framework support is experimental. Their adapters translate framework messages, retrieval, model output, function output, grants, and tool metadata into neutral AgentShield contracts.

Optional packages are installed with `agentshield-provenance[langgraph]`, `agentshield-provenance[microsoft-agent-framework]`, or `agentshield-provenance[frameworks]`. The controlled adapter harness does not require those packages.

Any future adapter must pass every shared security invariant: provenance retention, untrusted/model/function output cannot authorize, unauthorized protected calls block, valid scoped authority allows, scope cannot expand, provenance loss fails closed, and framework metadata cannot mint authority. A normal-execution demo alone is insufficient.
