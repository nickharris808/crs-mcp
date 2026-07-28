"""MCP server exposing the verdict surfaces to AI agents.

Run over stdio (the transport Claude Desktop and Cursor use)::

    crs-mcp

The tool descriptions below are written *for the model*, not for a human reading
docs. Each one states explicitly what the verdict means and, more importantly,
what it does not mean -- an agent that reads ``OUT_OF_SCOPE`` as "no problems
found" will commit unsafe code, so the wording works against that reading.
"""

from __future__ import annotations

import json
from typing import Any

from . import tools

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool
except ImportError as exc:  # pragma: no cover - exercised only without the SDK
    raise SystemExit(
        "the 'mcp' package is required to run the server: pip install 'crs-mcp[server]'"
    ) from exc


ATOM_SCHEMA = {
    "type": "array",
    "description": (
        "Conjunction of linear atoms. Each atom means "
        "sum(coeff[v]*v) + const <= 0, or < 0 when strict is true. "
        'Example: {"coeff": {"payload": 1, "record_len": -1}, "const": 19} '
        "means payload - record_len + 19 <= 0, i.e. 19 + payload <= record_len."
    ),
    "items": {
        "type": "object",
        "properties": {
            "coeff": {"type": "object", "additionalProperties": {"type": "number"}},
            "const": {"type": "number", "default": 0},
            "strict": {"type": "boolean", "default": False},
        },
        "required": ["coeff"],
    },
}

BOX_SCHEMA = {
    "type": "object",
    "description": (
        'Integer bounds per variable, e.g. {"payload": [0, 65535]}. Required: an '
        "unbounded domain has no finite state count and will be refused."
    ),
    "additionalProperties": {
        "type": "array",
        "items": {"type": "integer"},
        "minItems": 2,
        "maxItems": 2,
    },
}


def _guard_args(required_safety: bool = True) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "domain": {**ATOM_SCHEMA, "description": "Constraints bounding the state space."},
            "guard": {**ATOM_SCHEMA, "description": "What the code checks before the access."},
            "safety": {
                **ATOM_SCHEMA,
                "description": "What must hold. Each atom is one obligation.",
            },
            "box": BOX_SCHEMA,
        },
        "required": ["guard", "safety", "box"],
    }


TOOLS: list[Tool] = [
    Tool(
        name="certify_guard",
        description=(
            "Decide whether a guard predicate is sound: does it admit any state the "
            "safety property forbids, within a declared integer box?\n\n"
            "Returns exactly one of three verdicts:\n"
            "  CERTIFIED      - no forbidden state is admitted, over the whole box.\n"
            "  PROVEN_UNSOUND - at least one is, and a concrete counterexample is given.\n"
            "  OUT_OF_SCOPE   - the box is too large to decide by enumeration.\n\n"
            "IMPORTANT: OUT_OF_SCOPE is NOT an approval and NOT a clean bill of health. "
            "It means no verdict was reached. Never report it to a user as 'no issues "
            "found'. CERTIFIED is a statement about the declared box only and says "
            "nothing about states outside it."
        ),
        inputSchema=_guard_args(),
    ),
    Tool(
        name="count_exploitability",
        description=(
            "Count exactly how many states a guard admits that the safety property "
            "forbids, and return one concrete example. Use this after "
            "certify_guard returns PROVEN_UNSOUND to quantify the exposure.\n\n"
            "The count is a triggerability figure under uniform sampling over the "
            "declared box. It is not a severity score, not CVSS, and not a claim that "
            "any counted state is weaponisable."
        ),
        inputSchema=_guard_args(),
    ),
    Tool(
        name="verify_certificate",
        description=(
            "Re-check a certkit proof certificate against its specification. Use this "
            "when someone hands you a certificate and you want to confirm it without "
            "trusting the tool that produced it.\n\n"
            "The checker rebuilds every obligation from the spec and ignores any atoms "
            "the certificate carries, so a certificate that proves an unrelated easy "
            "system cannot pass."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "spec": {"type": "object", "description": "A certkit/spec/v1 object."},
                "cert": {"type": "object", "description": "A certkit/farkas/v1 object."},
            },
            "required": ["spec", "cert"],
        },
    ),
    Tool(
        name="explain_refusal",
        description=(
            "Turn a verdict from certify_guard into prose suitable for relaying to a "
            "human, including what the verdict does not establish. Use this rather "
            "than paraphrasing a verdict yourself."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "verdict": {"type": "object", "description": "A verdict object as returned above."}
            },
            "required": ["verdict"],
        },
    ),
]


def build_server() -> Server:
    server = Server("crs-mcp")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return TOOLS

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        result = dispatch(name, arguments or {})
        return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]

    return server


def dispatch(name: str, arguments: dict[str, Any]) -> Any:
    """Route a tool call. Separated from the server so tests can call it directly."""
    if name == "certify_guard":
        return tools.certify_guard(
            arguments.get("domain", []),
            arguments.get("guard", []),
            arguments.get("safety", []),
            arguments.get("box", {}),
        ).to_dict()

    if name == "count_exploitability":
        return tools.count_exploitability(
            arguments.get("domain", []),
            arguments.get("guard", []),
            arguments.get("safety", []),
            arguments.get("box", {}),
        )

    if name == "verify_certificate":
        return tools.verify_certificate(arguments.get("spec", {}), arguments.get("cert", {}))

    if name == "explain_refusal":
        return {"explanation": tools.explain_refusal(arguments.get("verdict", {}))}

    return {"error": f"unknown tool {name!r}"}


def main() -> None:
    import anyio

    async def _run() -> None:
        server = build_server()
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    anyio.run(_run)


if __name__ == "__main__":
    main()
