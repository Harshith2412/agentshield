"""Deterministic demo agent for controlled security experiments."""

from __future__ import annotations

from agentshield.core.capabilities import Capability
from agentshield.core.engine import AgentShield
from agentshield.core.events import EventType
from agentshield.core.policies import PolicyAction
from agentshield.runtime.context import AgentTask, AuthorizationGrant, ExecutionMode, RunContext, TrustBoundary
from agentshield.runtime.executor import InstrumentedExecutor
from agentshield.runtime.instrumentation import ExecutionTrace, RuntimeInstrumentation
from agentshield.runtime.memory import RuntimeMemory
from agentshield.runtime.retrieval import DocumentStore
from agentshield.runtime.tools import ToolRegistry, ToolRequest, ToolStatus


class DemoAgent:
    """A scripted agent harness; it is deliberately not an LLM."""

    def __init__(
        self,
        *,
        documents: DocumentStore | None = None,
        memory: RuntimeMemory | None = None,
        tools: ToolRegistry | None = None,
    ) -> None:
        self.documents = documents or DocumentStore()
        self.memory = memory or RuntimeMemory()
        self.tools = tools or ToolRegistry()

    def run(
        self,
        user_input: str,
        *,
        task: AgentTask | None = None,
        mode: ExecutionMode = ExecutionMode.PROTECTED,
        authorized_capabilities: frozenset[Capability] = frozenset(),
        authorization_grants: tuple[AuthorizationGrant, ...] = (),
    ) -> ExecutionTrace:
        """Execute a structured task with deterministic planning and output."""
        task = task or self._infer_demo_task(user_input)
        shield = AgentShield()
        context = RunContext(mode, authorized_capabilities, authorization_grants)
        instrumentation = RuntimeInstrumentation(shield, context)
        executor = InstrumentedExecutor(self.tools, instrumentation)

        user_event, _ = instrumentation.emit(
            EventType.USER_INPUT,
            "user",
            content=user_input,
            boundary=TrustBoundary.USER,
            metadata={"explicit_authorizations": sorted(item.value for item in authorized_capabilities)},
        )
        inputs = [user_event.id]
        retrieved_content: str | None = None
        memory_content: str | None = None

        if task.document:
            document = self.documents.retrieve(task.document)
            retrieval, _ = instrumentation.emit(
                EventType.RETRIEVAL,
                document.name,
                content=document.content,
                parent_ids=(user_event.id,),
                boundary=document.boundary,
                metadata={"document": document.name},
            )
            inputs.append(retrieval.id)
            retrieved_content = document.content

        if task.memory_read:
            entry = self.memory.read(task.memory_read)
            memory_event, _ = instrumentation.emit(
                EventType.MEMORY_READ,
                "runtime_memory",
                content=entry.value if entry else None,
                parent_ids=(user_event.id,),
                boundary=entry.boundary if entry else TrustBoundary.MEMORY,
                metadata={"key": task.memory_read, "found": entry is not None},
            )
            inputs.append(memory_event.id)
            memory_content = entry.value if entry else None

        plan_steps = [name for name, enabled in (
            ("retrieve document", bool(task.document)),
            ("read memory", bool(task.memory_read)),
            (f"request tool {task.tool}", bool(task.tool)),
            (f"process tool output and request {task.followup_tool}", bool(task.followup_tool)),
            ("write memory", bool(task.memory_write)),
            ("produce deterministic response", True),
        ) if enabled]
        plan, _ = instrumentation.emit(
            EventType.MODEL_OUTPUT,
            "deterministic_planner",
            content={"plan": plan_steps},
            parent_ids=tuple(inputs),
            metadata={"kind": "plan", "deterministic": True},
        )

        tool_result = None
        final_parent = plan.id
        if task.tool:
            tool_result, final_parent = executor.execute(
                ToolRequest(task.tool, task.tool_arguments), (plan.id,)
            )

        if task.followup_tool:
            followup_plan, _ = instrumentation.emit(
                EventType.MODEL_OUTPUT,
                "deterministic_planner",
                content={"plan": [f"request tool {task.followup_tool}"], "trigger": "structured_tool_output_directive"},
                parent_ids=(final_parent,),
                metadata={"kind": "followup_plan", "deterministic": True},
            )
            tool_result, final_parent = executor.execute(
                ToolRequest(task.followup_tool, task.followup_tool_arguments), (followup_plan.id,)
            )

        if task.memory_write:
            key, value = task.memory_write
            definition_capability = Capability.MEMORY_WRITE
            authorized = context.authorizes(definition_capability, {"key": key})
            memory_write, decision = instrumentation.emit(
                EventType.MEMORY_WRITE,
                "runtime_memory",
                content={"key": key, "value": value},
                parent_ids=(final_parent,),
                boundary=TrustBoundary.MEMORY,
                capability=definition_capability,
                authorized=authorized,
            )
            if mode is ExecutionMode.UNPROTECTED or decision.action is PolicyAction.ALLOW:
                self.memory.write(key, value)
            final_parent = memory_write.id

        final_text = self._final_text(retrieved_content, memory_content, task.tool, tool_result)
        final_event, _ = instrumentation.emit(
            EventType.MODEL_OUTPUT,
            "deterministic_agent",
            content=final_text,
            parent_ids=(final_parent,),
            metadata={"kind": "final", "deterministic": True},
        )
        instrumentation.trace.final_result = str(final_event.content)
        return instrumentation.trace

    def _infer_demo_task(self, user_input: str) -> AgentTask:
        normalized = user_input.lower()
        if "project notes" in normalized:
            return AgentTask(document="project_notes.txt")
        return AgentTask()

    @staticmethod
    def _final_text(
        retrieved: str | None,
        memory: str | None,
        tool_name: str | None,
        tool_result: object | None,
    ) -> str:
        parts: list[str] = []
        if retrieved is not None:
            compact = " ".join(retrieved.split())
            parts.append(f"Document summary: {compact[:160]}")
        if memory is not None:
            parts.append(f"Memory: {memory}")
        if tool_name and tool_result is not None:
            status = getattr(tool_result, "status", ToolStatus.ERROR)
            parts.append(f"Tool {tool_name}: {status.value}")
        return " | ".join(parts) if parts else "Task completed with no external action."
