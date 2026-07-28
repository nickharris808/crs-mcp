"""Adapters for agent frameworks that are not MCP.

MCP is the transport this package was built around, but most agents today are not
on it. The tools themselves have nothing to do with any framework: they take
JSON, they return JSON, and :func:`call` runs one without importing anything
beyond the standard library and this package's own siblings.

So this module offers the same five tools in the shapes other runtimes expect:

    from crs_mcp.adapters import openai_tools, anthropic_tools, call

    tools = openai_tools()                 # OpenAI function-calling schema
    result = call("decide_guard", args)    # run one, no framework at all

Everything is generated from :mod:`crs_mcp.catalog`, so a caveat cannot be
present in one integration and missing from another.

**On abstention.** These adapters convert shapes; they do not convert verdicts.
No adapter maps ``OUT_OF_SCOPE`` onto a boolean, a score, or a pass -- the whole
point of that verdict is that no answer was reached, and flattening it to fit a
framework's idea of "result" would be the single most damaging thing this file
could do.
"""

from __future__ import annotations

from typing import Any, Callable

from . import tools as _tools
from .catalog import TOOL_SPECS, TOOLS_BY_NAME, tool_names

__all__ = [
    "openai_tools",
    "anthropic_tools",
    "json_schemas",
    "langchain_tools",
    "call",
    "python_callables",
    "UnknownTool",
]


class UnknownTool(KeyError):
    """Raised for a tool name this package does not implement.

    A dedicated type because the alternative -- returning an error dict that a
    framework renders as a normal result -- lets a model read "unknown tool" as
    an answer.
    """


def openai_tools() -> list[dict[str, Any]]:
    """The catalogue in OpenAI function-calling form.

    Usable with the OpenAI SDK's ``tools=`` parameter, and accepted unchanged by
    the several other runtimes that copied that shape.
    """
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description,
                "parameters": t.input_schema,
            },
        }
        for t in TOOL_SPECS
    ]


def anthropic_tools() -> list[dict[str, Any]]:
    """The catalogue in Anthropic tool-use form (``input_schema``, not ``parameters``)."""
    return [
        {"name": t.name, "description": t.description, "input_schema": t.input_schema}
        for t in TOOL_SPECS
    ]


def json_schemas() -> dict[str, dict[str, Any]]:
    """Standalone JSON Schema documents, one per tool, keyed by name.

    For anything that wants to validate arguments before calling -- a gateway, a
    form, another language's client.
    """
    return {t.name: t.to_json_schema() for t in TOOL_SPECS}


_HANDLERS: dict[str, Callable[[dict[str, Any]], Any]] = {
    "certify_guard": lambda a: _tools.certify_guard(
        a.get("domain", []), a.get("guard", []), a.get("safety", []), a.get("box", {})
    ).to_dict(),
    "decide_guard": lambda a: _tools.decide_guard(
        a.get("domain", []), a.get("guard", []), a.get("safety", []), a.get("box", {})
    ).to_dict(),
    "count_exploitability": lambda a: _tools.count_exploitability(
        a.get("domain", []), a.get("guard", []), a.get("safety", []), a.get("box", {})
    ),
    "verify_certificate": lambda a: _tools.verify_certificate(a.get("spec", {}), a.get("cert", {})),
    "explain_refusal": lambda a: {"explanation": _tools.explain_refusal(a.get("verdict", {}))},
}


def call(name: str, arguments: dict[str, Any] | None = None) -> Any:
    """Run one tool by name and return its JSON-ready result.

    This is the whole runtime. No server, no transport, no framework -- which
    also makes it the thing to call from a test, a script, or a CI step.

    Raises :class:`UnknownTool` for an unrecognised name.
    """
    if name not in _HANDLERS:
        raise UnknownTool(f"unknown tool {name!r}; available: {', '.join(tool_names())}")
    return _HANDLERS[name](arguments or {})


def python_callables() -> dict[str, Callable[..., Any]]:
    """The tools as plain keyword-argument functions, for frameworks that
    introspect signatures rather than read schemas."""
    return {name: _bind(name) for name in _HANDLERS}


def _bind(name: str) -> Callable[..., Any]:
    spec = TOOLS_BY_NAME[name]

    def run(**kwargs: Any) -> Any:
        return call(name, kwargs)

    run.__name__ = name
    run.__doc__ = spec.description
    return run


def langchain_tools() -> list[Any]:
    """The catalogue as LangChain ``StructuredTool`` objects.

    LangChain is an optional, unpinned dependency: this package does not list it,
    does not import it at module load, and refuses loudly here if it is absent
    rather than degrading into a partial integration.
    """
    try:
        from langchain_core.tools import StructuredTool
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise ImportError(
            "langchain_tools() needs langchain-core, which crs-mcp deliberately does "
            "not depend on. Install it (`pip install langchain-core`), or use "
            "openai_tools()/anthropic_tools()/call(), which need nothing extra."
        ) from exc

    return [
        StructuredTool.from_function(
            func=_bind(t.name),
            name=t.name,
            description=t.description,
            args_schema=None,
            infer_schema=False,
        )
        for t in TOOL_SPECS
    ]


def rendered_descriptions(adapter: Callable[[], list[dict[str, Any]]]) -> dict[str, str]:
    """Extract ``{name: description}`` from an adapter's output.

    Used by the test suite to assert that every caveat survived the conversion.
    An adapter that silently dropped the "OUT_OF_SCOPE is NOT an approval"
    sentence would still look right in every other respect.
    """
    out: dict[str, str] = {}
    for entry in adapter():
        if "function" in entry:
            out[entry["function"]["name"]] = entry["function"]["description"]
        else:
            out[entry["name"]] = entry["description"]
    return out


def _main() -> int:
    """``python -m crs_mcp.adapters [openai|anthropic|jsonschema]`` -- print the
    catalogue in one of its shapes, for pasting into an agent config."""
    import argparse
    import json as _json

    parser = argparse.ArgumentParser(prog="python -m crs_mcp.adapters", description=__doc__)
    parser.add_argument(
        "shape",
        nargs="?",
        default="openai",
        choices=["openai", "anthropic", "jsonschema"],
    )
    args = parser.parse_args()
    payload = {
        "openai": openai_tools,
        "anthropic": anthropic_tools,
        "jsonschema": json_schemas,
    }[args.shape]()
    print(_json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
