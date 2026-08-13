"""Incremental model stream recording and completed-action release."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from agentshield.core.events import EventType
from agentshield.models.base import ModelResponse, ProposedAction
from agentshield.models.parsing import parse_model_response
from agentshield.runtime.instrumentation import RuntimeInstrumentation


@dataclass(frozen=True)
class StreamResult:
    response: ModelResponse
    completed: bool
    cancelled: bool
    start_event_id: str
    end_event_id: str


class ModelStreamAssembler:
    def __init__(self, instrumentation: RuntimeInstrumentation, parent_ids: tuple[str, ...]) -> None:
        self.instrumentation = instrumentation
        self.parent_ids = parent_ids
        self._chunks: list[str] = []
        self._closed = False
        self.start, _ = instrumentation.emit(
            EventType.MODEL_STREAM_START, "model_stream", parent_ids=parent_ids,
            metadata={"stream_status": "started"},
        )
        self._last_event_id = self.start.id

    def add_chunk(self, chunk: str) -> str:
        if self._closed:
            raise RuntimeError("stream is already closed")
        self._chunks.append(chunk)
        event, _ = self.instrumentation.emit(
            EventType.MODEL_STREAM_CHUNK, "model_stream", content={"length": len(chunk)},
            parent_ids=(self._last_event_id,), metadata={"stream_status": "partial"},
        )
        self._last_event_id = event.id
        return event.id

    def finish(self) -> StreamResult:
        if self._closed:
            raise RuntimeError("stream is already closed")
        self._closed = True
        response = parse_model_response("".join(self._chunks))
        end, _ = self.instrumentation.emit(
            EventType.MODEL_STREAM_END, "model_stream",
            content={"malformed": response.malformed, "actions": len(response.proposed_actions)},
            parent_ids=(self._last_event_id,), metadata={"stream_status": "complete" if not response.malformed else "malformed"},
        )
        self._last_event_id = end.id
        return StreamResult(response, not response.malformed, False, self.start.id, end.id)

    def cancel(self) -> StreamResult:
        if self._closed:
            raise RuntimeError("stream is already closed")
        self._closed = True
        event, _ = self.instrumentation.emit(
            EventType.MODEL_STREAM_CANCELLED, "model_stream", content={"chunks": len(self._chunks)},
            parent_ids=(self._last_event_id,), metadata={"stream_status": "cancelled"},
        )
        return StreamResult(ModelResponse("", malformed=True, error="stream cancelled"), False, True, self.start.id, event.id)

    async def consume(self, chunks) -> StreamResult:
        try:
            async for chunk in chunks:
                self.add_chunk(chunk)
            return self.finish()
        except asyncio.CancelledError:
            self.cancel()
            raise
