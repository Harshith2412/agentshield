"""Provenance-preserving execution boundary for model action proposals."""

from __future__ import annotations

from dataclasses import dataclass, replace

from agentshield.core.engine import AgentShield
from agentshield.core.events import EventType
from agentshield.models.base import ModelAdapter, ModelContext, ModelRequest, ModelResponse, ModelSettings
from agentshield.runtime.context import AuthorizationGrant, ExecutionMode, RunContext
from agentshield.runtime.executor import InstrumentedExecutor
from agentshield.runtime.instrumentation import ExecutionTrace, RuntimeInstrumentation
from agentshield.runtime.tools import ToolRegistry, ToolRequest, ToolResult, ToolStatus


@dataclass(frozen=True)
class ModelRunResult:
    response: ModelResponse
    trace: ExecutionTrace
    action_results: tuple[ToolResult, ...]


class ModelAgentRuntime:
    def __init__(self, adapter: ModelAdapter, *, tools: ToolRegistry | None = None) -> None:
        self.adapter = adapter
        self.tools = tools or ToolRegistry()

    def run(
        self,
        request: ModelRequest,
        *,
        mode: ExecutionMode = ExecutionMode.PROTECTED,
        authorization_grants: tuple[AuthorizationGrant, ...] = (),
    ) -> ModelRunResult:
        context = RunContext(mode, authorization_grants=authorization_grants)
        instrumentation = RuntimeInstrumentation(AgentShield(), context)
        source_event_ids = self._emit_context(request.context, instrumentation)
        model_request, _ = instrumentation.emit(
            EventType.MODEL_OUTPUT,
            "model_request",
            content={"request_id": request.request_id, "model": request.settings.model_name},
            parent_ids=source_event_ids,
            metadata={"kind": "model_request"},
        )
        try:
            response = self.adapter.generate(request)
        except Exception as exc:
            instrumentation.emit(
                EventType.SECURITY_ALERT, "model_adapter", content={"error": str(exc)},
                parent_ids=(model_request.id,), metadata={"kind": "adapter_error"},
            )
            instrumentation.trace.final_result = f"Model adapter error: {exc}"
            raise
        model_response, _ = instrumentation.emit(
            EventType.MODEL_OUTPUT,
            "model_response",
            content={"final_response": response.final_response, "malformed": response.malformed, "error": response.error},
            parent_ids=(model_request.id,),
            metadata={"kind": "model_response", "proposed_actions": len(response.proposed_actions)},
        )
        if response.malformed:
            instrumentation.emit(
                EventType.SECURITY_ALERT, "model_parser", content={"error": response.error},
                parent_ids=(model_response.id,), metadata={"kind": "malformed_model_output"},
            )
        executor = InstrumentedExecutor(self.tools, instrumentation)
        results: list[ToolResult] = []
        validation_errors: list[tuple[str, Exception]] = []
        if not response.malformed:
            for proposal in response.proposed_actions:
                try:
                    self.tools.validate_request(ToolRequest(proposal.tool, proposal.arguments))
                except (KeyError, ValueError) as exc:
                    validation_errors.append((proposal.tool, exc))
        if validation_errors:
            detail = "; ".join(str(exc) for _, exc in validation_errors)
            response = replace(response, malformed=True, error=f"invalid proposed action contract: {detail}")
            alert_kind = "unknown_tool" if all(isinstance(exc, KeyError) for _, exc in validation_errors) else "invalid_action_batch"
            instrumentation.emit(
                EventType.SECURITY_ALERT, "model_action_validator", content={"error": response.error},
                parent_ids=(model_response.id,), metadata={"kind": alert_kind},
            )
            for proposal in response.proposed_actions:
                result = ToolResult(proposal.tool, ToolStatus.ERROR, "action batch rejected before execution")
                instrumentation.trace.tool_results.append(result)
                results.append(result)
            instrumentation.trace.final_result = response.error
            return ModelRunResult(response, instrumentation.trace, tuple(results))
        for proposal in response.proposed_actions:
            request = ToolRequest(proposal.tool, proposal.arguments)
            result, _ = executor.execute(request, (model_response.id,))
            results.append(result)
        instrumentation.trace.final_result = response.final_response or response.error or ""
        return ModelRunResult(response, instrumentation.trace, tuple(results))

    @staticmethod
    def _emit_context(context: ModelContext, instrumentation: RuntimeInstrumentation) -> tuple[str, ...]:
        emitted: list[str] = []
        groups = (
            (EventType.MODEL_OUTPUT, context.system_instructions),
            (EventType.USER_INPUT, (context.user_instruction,) if context.user_instruction else ()),
            (EventType.RETRIEVAL, context.retrieved_sources),
            (EventType.MEMORY_READ, context.memories),
            (EventType.TOOL_RESPONSE, context.tool_outputs),
        )
        for event_type, items in groups:
            for item in items:
                event, _ = instrumentation.emit(
                    event_type, item.name, content=item.content, boundary=item.boundary,
                    metadata={"context_event_id": item.event_id, "kind": "model_context"},
                )
                emitted.append(event.id)
        return tuple(emitted)
