import json

import pytest

from agentshield.models import parse_model_response


@pytest.mark.parametrize("raw", ["not json", "[1, 2]", "null", '"text"'])
def test_malformed_top_level_fails_safely(raw: str) -> None:
    response = parse_model_response(raw)
    assert response.malformed
    assert not response.proposed_actions


@pytest.mark.parametrize("payload", [
    {"final_response": 3, "proposed_actions": []},
    {"final_response": "x", "proposed_actions": {}},
    {"final_response": "x", "proposed_actions": ["send_email"]},
    {"final_response": "x", "proposed_actions": [{"tool": "", "arguments": {}}]},
    {"final_response": "x", "proposed_actions": [{"tool": "send_email"}]},
    {"final_response": "x", "proposed_actions": [{"tool": "send_email", "arguments": [], "reason": "x"}]},
    {"final_response": "x", "proposed_actions": [{"tool": "send_email", "arguments": {}, "reason": 2}]},
])
def test_invalid_action_contract_fails_safely(payload) -> None:
    response = parse_model_response(json.dumps(payload))
    assert response.malformed
    assert not response.proposed_actions


def test_valid_contract_parses_multiple_actions() -> None:
    response = parse_model_response(json.dumps({
        "final_response": "done",
        "proposed_actions": [
            {"tool": "send_email", "arguments": {"to": "demo@example.test"}, "reason": "requested"},
            {"tool": "write_file", "arguments": {"path": "reports/x.txt"}, "reason": "archive"},
        ],
    }))
    assert not response.malformed
    assert response.final_response == "done"
    assert [action.tool for action in response.proposed_actions] == ["send_email", "write_file"]


def test_parser_never_evaluates_code(tmp_path) -> None:
    target = tmp_path / "executed"
    response = parse_model_response(f'__import__("pathlib").Path("{target}").touch()')
    assert response.malformed
    assert not target.exists()
