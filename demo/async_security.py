import asyncio

from agentshield import AgentShield, Capability, EventType
from agentshield.runtime import AsyncInstrumentedExecutor, ExecutionMode, RunContext, RuntimeInstrumentation, ToolRegistry, ToolRequest, TrustBoundary


async def run() -> None:
    instrumentation = RuntimeInstrumentation(AgentShield(), RunContext(ExecutionMode.PROTECTED))
    root, _ = instrumentation.emit(EventType.USER_INPUT, "user", boundary=TrustBoundary.USER)
    results = await AsyncInstrumentedExecutor(ToolRegistry({"notes": "safe"}), instrumentation).execute_many((
        ToolRequest("read_document", {"name": "notes"}),
        ToolRequest("send_email", {"to": "other@example.test"}),
    ), (root.id,))
    print([result.status.value for result, _ in results])


if __name__ == "__main__":
    asyncio.run(run())
