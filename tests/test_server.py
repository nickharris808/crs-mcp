"""MCP protocol tests.

The tool-layer tests cover the verdict logic. These cover the thing that is easy
to get silently wrong: that the server actually registers its handlers and that a
real ``tools/list`` and ``tools/call`` round-trip returns what we think it does.

A server whose tool functions are perfect but whose handlers are misregistered
would pass every test in ``test_tools.py``.
"""

import json

import anyio
import pytest

from crs_mcp.server import TOOLS, build_server

mcp_types = pytest.importorskip("mcp.types")
ListToolsRequest = mcp_types.ListToolsRequest
CallToolRequest = mcp_types.CallToolRequest


DOMAIN = [
    {"coeff": {"payload": -1}, "const": 0},
    {"coeff": {"payload": 1}, "const": -255},
]
SAFETY = [{"coeff": {"payload": 1, "record_len": -1}, "const": 3}]
BOX = {"payload": [0, 255], "record_len": [0, 255]}


def _call(name, arguments):
    async def run():
        server = build_server()
        handler = server.request_handlers[CallToolRequest]
        req = CallToolRequest(method="tools/call", params={"name": name, "arguments": arguments})
        result = await handler(req)
        return json.loads(result.root.content[0].text)

    return anyio.run(run)


def test_server_builds_and_advertises_tools():
    async def run():
        server = build_server()
        handler = server.request_handlers[ListToolsRequest]
        result = await handler(ListToolsRequest(method="tools/list"))
        return [t.name for t in result.root.tools]

    names = anyio.run(run)
    assert names == [t.name for t in TOOLS]
    assert "certify_guard" in names


def test_call_tool_round_trip_certified():
    guard = [{"coeff": {"payload": 1, "record_len": -1}, "const": 19}]
    payload = _call(
        "certify_guard",
        {"domain": DOMAIN, "guard": guard, "safety": SAFETY, "box": BOX},
    )
    assert payload["verdict"] == "CERTIFIED"


def test_call_tool_round_trip_unsound_includes_counterexample():
    guard = [{"coeff": {"payload": 1, "record_len": -1}, "const": 1}]
    payload = _call(
        "certify_guard",
        {"domain": DOMAIN, "guard": guard, "safety": SAFETY, "box": BOX},
    )
    assert payload["verdict"] == "PROVEN_UNSOUND"
    assert payload["detail"]["counterexample"] is not None


def test_every_tool_description_warns_against_reading_refusal_as_approval():
    """The safety property of an agent-facing tool is in its description text."""
    certify = next(t for t in TOOLS if t.name == "certify_guard")
    text = certify.description
    assert "OUT_OF_SCOPE is NOT an approval" in text
    assert "no issues" in text


def test_tool_schemas_require_a_box():
    """An unbounded request must be impossible to express, not merely refused."""
    for name in ("certify_guard", "count_exploitability"):
        tool = next(t for t in TOOLS if t.name == name)
        assert "box" in tool.inputSchema["required"]


def test_mcp_dependency_is_pinned_to_a_tested_major():
    """mcp 2.0.0 removed the decorator API this server uses.

    The dependency was originally `mcp>=1.0.0`, which silently pulled 2.0.0 the
    day it shipped and broke every server test. Verified working on 1.9.0
    through 1.29.0; the upper bound must stay until 2.x is actually supported.
    """
    import re
    from pathlib import Path

    text = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text()
    # Only dependency specifiers carry a version; the bare "mcp" keyword does not.
    specs = re.findall(r'"mcp(>=[^"]*)"', text)
    assert specs, "no pinned mcp dependency found"
    for spec in specs:
        assert "<2" in spec, f"mcp constraint {spec!r} lacks an upper bound"
