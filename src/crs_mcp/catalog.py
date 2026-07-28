"""The tool catalogue: one definition per tool, and no framework in sight.

Every integration -- MCP, OpenAI function calling, Anthropic tool use, LangChain,
a plain HTTP handler -- needs the same three things: a name, a description
written for a model rather than for a human, and a JSON Schema for the arguments.
Those used to live inside ``server.py``, which cannot be imported without the
``mcp`` package installed. That made the schemas unreachable for anyone not on
MCP, and it made "add another adapter" mean "copy the descriptions again", which
is how two integrations start disagreeing about what a verdict means.

So the catalogue lives here, in a module that imports nothing outside the
standard library. ``server.py`` builds MCP ``Tool`` objects from it;
``adapters.py`` builds everything else from it.

The descriptions are load-bearing, not decoration. Each states what a verdict
does **not** establish, because an agent that reads ``OUT_OF_SCOPE`` as "no
problems found" will merge unsafe code. An adapter that dropped those sentences
while keeping the name and schema would look correct and be dangerous -- so
:func:`check_descriptions_intact` exists, and the test suite runs it against
every adapter's output.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = [
    "ToolSpec",
    "TOOL_SPECS",
    "TOOLS_BY_NAME",
    "CAVEATS",
    "tool_names",
    "input_schema",
    "check_descriptions_intact",
]

ATOM_SCHEMA: dict[str, Any] = {
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

BOX_SCHEMA: dict[str, Any] = {
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


def _guard_args() -> dict[str, Any]:
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


@dataclass(frozen=True)
class ToolSpec:
    """One tool, in the form every framework needs it.

    ``caveat`` is the sentence that must survive into any adapter's output. It is
    kept as its own field so a test can assert on it rather than grepping prose.
    """

    name: str
    description: str
    input_schema: dict[str, Any]
    caveat: str = ""

    def to_json_schema(self) -> dict[str, Any]:
        """The argument schema, as a standalone JSON Schema document."""
        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": f"https://github.com/nickharris808/crs-mcp/schemas/{self.name}.json",
            "title": self.name,
            "description": self.description,
            **self.input_schema,
        }


_CERTIFY_DESC = (
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
)

_DECIDE_DESC = (
    "Decide whether a guard is sound, WITHOUT counting how unsound it is. "
    "Same three verdicts as certify_guard, reached by stopping at the first "
    "escaping state instead of enumerating the whole violating region.\n\n"
    "Prefer this when the question is 'is this safe?'. It is dramatically "
    "faster on unsound guards (a measured 286 ms of counting becomes 0.04 ms "
    "of search) and identical on sound ones, where the full enumeration is "
    "required either way.\n\n"
    "The result carries NO over_acceptance field, because nothing was counted. "
    "Use certify_guard when you need the magnitude.\n\n"
    "IMPORTANT: OUT_OF_SCOPE is NOT an approval. It means no search was run."
)

_COUNT_DESC = (
    "Count exactly how many states a guard admits that the safety property "
    "forbids, and return one concrete example. Use this after "
    "certify_guard returns PROVEN_UNSOUND to quantify the exposure.\n\n"
    "The count is a triggerability figure under uniform sampling over the "
    "declared box. It is not a severity score, not CVSS, and not a claim that "
    "any counted state is weaponisable."
)

_VERIFY_DESC = (
    "Re-check a certkit proof certificate against its specification. Use this "
    "when someone hands you a certificate and you want to confirm it without "
    "trusting the tool that produced it.\n\n"
    "The checker rebuilds every obligation from the spec and ignores any atoms "
    "the certificate carries, so a certificate that proves an unrelated easy "
    "system cannot pass."
)

_EXPLAIN_DESC = (
    "Turn a verdict from certify_guard into prose suitable for relaying to a "
    "human, including what the verdict does not establish. Use this rather "
    "than paraphrasing a verdict yourself."
)

TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "certify_guard",
        _CERTIFY_DESC,
        _guard_args(),
        caveat="OUT_OF_SCOPE is NOT an approval",
    ),
    ToolSpec(
        "decide_guard",
        _DECIDE_DESC,
        _guard_args(),
        caveat="OUT_OF_SCOPE is NOT an approval",
    ),
    ToolSpec(
        "count_exploitability",
        _COUNT_DESC,
        _guard_args(),
        caveat="not a severity score",
    ),
    ToolSpec(
        "verify_certificate",
        _VERIFY_DESC,
        {
            "type": "object",
            "properties": {
                "spec": {"type": "object", "description": "A certkit/spec/v1 object."},
                "cert": {"type": "object", "description": "A certkit/farkas/v1 object."},
            },
            "required": ["spec", "cert"],
        },
        caveat="ignores any atoms the certificate carries",
    ),
    ToolSpec(
        "explain_refusal",
        _EXPLAIN_DESC,
        {
            "type": "object",
            "properties": {
                "verdict": {"type": "object", "description": "A verdict object as returned above."}
            },
            "required": ["verdict"],
        },
        caveat="what the verdict does not establish",
    ),
)

TOOLS_BY_NAME: dict[str, ToolSpec] = {t.name: t for t in TOOL_SPECS}

#: The phrases that must appear in whatever description reaches the model.
CAVEATS: dict[str, str] = {t.name: t.caveat for t in TOOL_SPECS}


def tool_names() -> list[str]:
    return [t.name for t in TOOL_SPECS]


def input_schema(name: str) -> dict[str, Any]:
    """The argument schema for one tool, by name.

    Raises :class:`KeyError` on an unknown name rather than returning an empty
    schema -- a permissive "anything goes" schema handed to a model is how a tool
    call ends up silently malformed.
    """
    return TOOLS_BY_NAME[name].input_schema


def check_descriptions_intact(rendered: dict[str, str]) -> list[str]:
    """Return the names whose caveat did not survive into ``rendered``.

    ``rendered`` maps a tool name to the description an adapter is about to hand
    a model. An empty result means every caveat is still there. This is not
    decoration: the difference between a useful verdict and a dangerous one is
    entirely in these sentences.
    """
    missing = []
    for name, caveat in CAVEATS.items():
        if not caveat:
            continue
        text = rendered.get(name)
        if text is None or caveat not in text:
            missing.append(name)
    return missing
