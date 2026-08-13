# Quickstart

Install the base package and run the safe demo:

```bash
python -m pip install -e .
agentshield demo
```

Evaluate a security event:

```python
from agentshield import AgentShield, Capability, EventType, SecurityEvent

shield = AgentShield()
request = SecurityEvent(EventType.TOOL_REQUEST, "quickstart", capability=Capability.EMAIL_SEND)
decision = shield.evaluate(request)
assert decision.action.value == "block"
```

For an instrumented application, register simulated tools with `ToolRegistry`, create a `RunContext`, and route every proposal through `InstrumentedExecutor`. Grant privileged actions only with an `AuthorizationGrant` whose scope exactly matches the request. See demos under `demo/` for synchronous, asynchronous, framework, streaming, and persistence examples.
