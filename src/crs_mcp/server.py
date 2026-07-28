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

from . import adapters
from .catalog import TOOL_SPECS

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool
except ImportError as exc:  # pragma: no cover - exercised only without the SDK
    raise SystemExit(
        "the 'mcp' package is required to run the server: pip install 'crs-mcp[server]'"
    ) from exc


# The tool catalogue lives in `catalog`, which imports nothing outside the
# standard library. This module turns it into MCP `Tool` objects; `adapters`
# turns the same catalogue into OpenAI, Anthropic and LangChain shapes. One
# source, so a caveat cannot be present in one integration and missing from
# another.
TOOLS: list[Tool] = [
    Tool(name=spec.name, description=spec.description, inputSchema=spec.input_schema)
    for spec in TOOL_SPECS
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
    """Route a tool call. Separated from the server so tests can call it directly.

    The handlers live in `adapters` so that every integration -- MCP, OpenAI,
    LangChain, a plain script -- runs the same code path. A second copy here
    would be a second place for a verdict to be reshaped.
    """
    try:
        return adapters.call(name, arguments)
    except adapters.UnknownTool:
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
