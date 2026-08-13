from pathlib import Path

from agentshield import Capability
from agentshield.runtime import (
    SideEffectLevel,
    ToolDefinition,
    ToolRegistry,
    ToolRequest,
    ToolStatus,
)


def test_builtin_tools_are_registered() -> None:
    registry = ToolRegistry()
    assert registry.names == (
        "network_request", "read_document", "send_email", "shell_execute", "write_file"
    )


def test_custom_tool_registration() -> None:
    registry = ToolRegistry()
    registry.register(ToolDefinition("echo", Capability.READ_LOCAL, SideEffectLevel.NONE, lambda args: str(args["value"])))
    assert registry.execute(ToolRequest("echo", {"value": "ok"})).output == "ok"


def test_duplicate_tool_registration_is_rejected() -> None:
    registry = ToolRegistry()
    try:
        registry.register(ToolDefinition("read_document", Capability.READ_LOCAL, SideEffectLevel.NONE, lambda args: ""))
    except ValueError as exc:
        assert "already registered" in str(exc)
    else:
        raise AssertionError("duplicate registration was accepted")


def test_read_document_uses_in_memory_fixture() -> None:
    result = ToolRegistry({"notes.txt": "offline notes"}).execute(
        ToolRequest("read_document", {"name": "notes.txt"})
    )
    assert result.status is ToolStatus.SUCCESS
    assert result.output == "offline notes"


def test_email_is_recorded_not_sent() -> None:
    registry = ToolRegistry()
    result = registry.execute(ToolRequest("send_email", {"to": "a@example.test", "body": "hello"}))
    assert result.output["simulation"] == "email recorded"
    assert registry.simulated_emails[0]["to"] == "a@example.test"


def test_network_request_is_recorded_not_sent() -> None:
    registry = ToolRegistry()
    result = registry.execute(ToolRequest("network_request", {"url": "https://example.test"}))
    assert result.output["status"] == "not_sent"
    assert len(registry.simulated_network_requests) == 1


def test_shell_command_is_never_executed(monkeypatch) -> None:
    import os
    import subprocess

    monkeypatch.setattr(os, "system", lambda *args: (_ for _ in ()).throw(AssertionError("os.system called")))
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("subprocess called")))
    registry = ToolRegistry()
    result = registry.execute(ToolRequest("shell_execute", {"command": "touch /tmp/should-not-exist"}))
    assert result.output["status"] == "not_executed"
    assert registry.simulated_shell_commands == ["touch /tmp/should-not-exist"]


def test_file_write_stays_in_sandbox() -> None:
    registry = ToolRegistry()
    result = registry.execute(ToolRequest("write_file", {"path": "reports/result.txt", "content": "safe"}))
    assert result.status is ToolStatus.SUCCESS
    assert (registry.sandbox_path / "reports/result.txt").read_text() == "safe"


def test_file_write_rejects_parent_traversal(tmp_path: Path) -> None:
    registry = ToolRegistry()
    outside = tmp_path / "outside.txt"
    result = registry.execute(ToolRequest("write_file", {"path": f"../{outside.name}", "content": "unsafe"}))
    assert result.status is ToolStatus.ERROR
    assert not outside.exists()


def test_file_write_rejects_absolute_path(tmp_path: Path) -> None:
    registry = ToolRegistry()
    target = tmp_path / "absolute.txt"
    result = registry.execute(ToolRequest("write_file", {"path": str(target), "content": "unsafe"}))
    assert result.status is ToolStatus.ERROR
    assert not target.exists()
