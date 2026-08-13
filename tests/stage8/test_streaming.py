import asyncio
import json

import pytest

from agentshield import AgentShield, EventType
from agentshield.runtime import ExecutionMode, ModelStreamAssembler, RunContext, RuntimeInstrumentation, TrustBoundary


def assembler():
    instrumentation = RuntimeInstrumentation(AgentShield(), RunContext(ExecutionMode.PROTECTED))
    source = instrumentation.emit(EventType.RETRIEVAL, "untrusted.txt", boundary=TrustBoundary.EXTERNAL_UNTRUSTED)[0]
    return ModelStreamAssembler(instrumentation, (source.id,)), instrumentation


def valid_json(tool="send_email"):
    return json.dumps({"final_response": "done", "proposed_actions": [{"tool": tool, "arguments": {"to": "x.test"}, "reason": "controlled"}]})


def test_stream_lifecycle_records_start_chunks_end() -> None:
    stream, instrumentation = assembler()
    stream.add_chunk('{"final_response":"ok",')
    stream.add_chunk('"proposed_actions":[]}')
    result = stream.finish()
    assert result.completed
    assert [e.event_type for e in instrumentation.trace.events[-4:]] == [EventType.MODEL_STREAM_START, EventType.MODEL_STREAM_CHUNK, EventType.MODEL_STREAM_CHUNK, EventType.MODEL_STREAM_END]


@pytest.mark.parametrize("split", [1, 5, 10, 25, 50])
def test_partial_tool_call_never_released_before_finish(split: int) -> None:
    raw = valid_json()
    stream, instrumentation = assembler()
    stream.add_chunk(raw[:split])
    assert not instrumentation.trace.tools_requested
    assert all(event.event_type is not EventType.TOOL_REQUEST for event in instrumentation.trace.events)


def test_completed_tool_call_is_parsed_only_at_end() -> None:
    stream, _ = assembler(); raw = valid_json()
    for chunk in (raw[:20], raw[20:40], raw[40:]): stream.add_chunk(chunk)
    result = stream.finish()
    assert result.response.proposed_actions[0].tool == "send_email"


@pytest.mark.parametrize("raw", ["", "{", "[]", "not json", '{"proposed_actions": ['])
def test_malformed_or_abandoned_stream_executes_nothing(raw: str) -> None:
    stream, instrumentation = assembler(); stream.add_chunk(raw)
    result = stream.finish()
    assert result.response.malformed
    assert not instrumentation.trace.tools_executed


def test_cancelled_stream_records_cancellation() -> None:
    stream, instrumentation = assembler(); stream.add_chunk('{"tool":')
    result = stream.cancel()
    assert result.cancelled
    assert instrumentation.trace.events[-1].event_type is EventType.MODEL_STREAM_CANCELLED


def test_cancelled_stream_cannot_finish() -> None:
    stream, _ = assembler(); stream.cancel()
    with pytest.raises(RuntimeError): stream.finish()


def test_finished_stream_rejects_more_chunks() -> None:
    stream, _ = assembler(); stream.add_chunk('{"final_response":"x","proposed_actions":[]}'); stream.finish()
    with pytest.raises(RuntimeError): stream.add_chunk("x")


def test_stream_chunks_preserve_untrusted_provenance() -> None:
    stream, instrumentation = assembler(); stream.add_chunk("{}"); stream.finish()
    chunks = [e for e in instrumentation.trace.events if e.event_type is EventType.MODEL_STREAM_CHUNK]
    assert all(e.provenance.externally_influenced for e in chunks)


def test_stream_chain_is_causal() -> None:
    stream, instrumentation = assembler(); stream.add_chunk("{}"); result = stream.finish()
    chain = instrumentation.trace.propagation_chain(result.end_event_id)
    assert chain[-1].event_type is EventType.MODEL_STREAM_END
    assert EventType.RETRIEVAL in {event.event_type for event in chain}


def test_async_stream_cancellation_leaves_trace() -> None:
    stream, instrumentation = assembler()
    async def chunks():
        yield "{"
        await asyncio.sleep(10)
    async def run():
        task = asyncio.create_task(stream.consume(chunks()))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
    asyncio.run(run())
    assert instrumentation.trace.events[-1].event_type is EventType.MODEL_STREAM_CANCELLED


def test_stream_records_only_chunk_length_not_content() -> None:
    stream, instrumentation = assembler(); secret = "sensitive-placeholder"; stream.add_chunk(secret)
    chunk = instrumentation.trace.events[-1]
    assert chunk.content["length"] == len(secret)
    assert secret not in str(chunk.content)
