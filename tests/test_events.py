from datetime import datetime

import pytest

from agentshield import Capability, EventType, SecurityEvent


def test_event_has_unique_identifier() -> None:
    first = SecurityEvent(EventType.USER_INPUT, "user")
    second = SecurityEvent(EventType.USER_INPUT, "user")
    assert first.id != second.id


def test_event_timestamp_is_timezone_aware() -> None:
    event = SecurityEvent(EventType.USER_INPUT, "user")
    assert event.timestamp.tzinfo is not None


def test_event_rejects_empty_source() -> None:
    with pytest.raises(ValueError, match="source"):
        SecurityEvent(EventType.USER_INPUT, "  ")


def test_event_rejects_naive_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        SecurityEvent(EventType.USER_INPUT, "user", timestamp=datetime.now())


def test_event_copies_mutable_metadata() -> None:
    metadata = {"request": "one"}
    event = SecurityEvent(EventType.TOOL_REQUEST, "planner", metadata=metadata)
    metadata["request"] = "changed"
    assert event.metadata["request"] == "one"


def test_event_can_request_capability() -> None:
    event = SecurityEvent(
        EventType.TOOL_REQUEST, "planner", capability=Capability.NETWORK_READ
    )
    assert event.capability is Capability.NETWORK_READ
