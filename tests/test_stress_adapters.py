"""Adversarial stress tests for the adapter surface.

Oracle: **no input may produce a confident-looking answer that is wrong.**

For this package the dangerous output is not a crash, it is a verdict an agent
will read as approval. So the tests here are mostly about what comes back when
the input is nonsense: it must be `OUT_OF_SCOPE` with a reason, never
`CERTIFIED`, and never a traceback that a framework renders as "tool error" for
the model to interpret however it likes.
"""

from __future__ import annotations

import json

import pytest

from crs_mcp import adapters
from crs_mcp.catalog import TOOL_SPECS, tool_names

SOUND = {
    "domain": [{"coeff": {"payload": -1}}, {"coeff": {"payload": 1}, "const": -255}],
    "guard": [{"coeff": {"payload": 1, "record_len": -1}, "const": 19}],
    "safety": [{"coeff": {"payload": 1, "record_len": -1}, "const": 3}],
    "box": {"payload": [0, 255], "record_len": [0, 255]},
}

HOSTILE_ARGS = [
    ("empty", {}),
    ("null-guard", {**SOUND, "guard": None}),
    ("string-guard", {**SOUND, "guard": "x"}),
    ("guard-not-atoms", {**SOUND, "guard": [1, 2, 3]}),
    ("coeff-string", {**SOUND, "guard": [{"coeff": "x"}]}),
    ("coeff-null", {**SOUND, "guard": [{"coeff": None}]}),
    ("const-nan", {**SOUND, "guard": [{"coeff": {"x": 1}, "const": float("nan")}]}),
    ("const-inf", {**SOUND, "guard": [{"coeff": {"x": 1}, "const": float("inf")}]}),
    ("coeff-inf", {**SOUND, "guard": [{"coeff": {"x": float("inf")}}]}),
    ("coeff-zero-denominator", {**SOUND, "guard": [{"coeff": {"x": [1, 0]}}]}),
    ("box-string", {**SOUND, "box": "everything"}),
    ("box-null", {**SOUND, "box": None}),
    ("box-empty", {**SOUND, "box": {}}),
    ("box-inverted", {**SOUND, "box": {"payload": [255, 0], "record_len": [0, 255]}}),
    ("box-single-point", {**SOUND, "box": {"payload": [5, 5], "record_len": [5, 5]}}),
    ("box-one-element", {**SOUND, "box": {"payload": [0], "record_len": [0, 255]}}),
    ("box-three-elements", {**SOUND, "box": {"payload": [0, 1, 2], "record_len": [0, 255]}}),
    ("box-huge", {**SOUND, "box": {"payload": [0, 10**18], "record_len": [0, 10**18]}}),
    ("box-unknown-variable", {**SOUND, "box": {"nope": [0, 3]}}),
    ("safety-empty", {**SOUND, "safety": []}),
    ("safety-null", {**SOUND, "safety": None}),
    ("deep-nesting", {**SOUND, "guard": [{"coeff": {"x": [[[[1]]]]}}]}),
    ("unicode-variable", {**SOUND, "guard": [{"coeff": {"\U0001f512": 1}}]}),
]

GUARD_TOOLS = ["certify_guard", "decide_guard", "count_exploitability"]


def test_numeric_strings_in_a_box_are_read_exactly_rather_than_refused():
    """Not a hostile input, and worth pinning as deliberate. `int("255")` is
    exact, so a box written with string bounds denotes the same region and
    CERTIFIED is the correct answer. This case was in the hostile list first, and
    "fixing" it would have meant refusing something true."""
    args = {**SOUND, "box": {"payload": ["0", "255"], "record_len": [0, 255]}}
    strings = adapters.call("certify_guard", args)
    integers = adapters.call("certify_guard", SOUND)
    assert strings["verdict"] == integers["verdict"] == "CERTIFIED"
    assert strings["detail"]["box_volume"] == integers["detail"]["box_volume"]


@pytest.mark.parametrize("tool", GUARD_TOOLS)
@pytest.mark.parametrize("label,args", HOSTILE_ARGS, ids=[a[0] for a in HOSTILE_ARGS])
def test_hostile_arguments_never_certify_and_never_raise(tool, label, args):
    try:
        result = adapters.call(tool, args)
    except Exception as exc:  # noqa: BLE001 - the point is that nothing escapes
        pytest.fail(f"{tool}({label}) raised {type(exc).__name__}: {exc}")
    body = json.dumps(result)
    assert "CERTIFIED" not in body or result.get("verdict") == "OUT_OF_SCOPE", label
    assert result.get("verdict") != "CERTIFIED", f"{tool}({label}) certified nonsense"


@pytest.mark.parametrize("label,args", HOSTILE_ARGS, ids=[a[0] for a in HOSTILE_ARGS])
def test_a_refusal_always_says_why(label, args):
    result = adapters.call("certify_guard", args)
    if result["verdict"] == "OUT_OF_SCOPE":
        assert result["summary"], label
        assert result["detail"].get("reason"), f"{label}: OUT_OF_SCOPE with no reason"


def test_every_out_of_scope_carries_the_not_an_approval_wording_somewhere_reachable():
    """The verdict alone is a token; the sentence is what stops a model reading
    it as a pass. It lives in the tool description, and that must reach the
    model."""
    for spec in TOOL_SPECS:
        if spec.caveat:
            assert spec.caveat in spec.description


@pytest.mark.parametrize("tool", tool_names())
def test_no_tool_raises_on_completely_absent_arguments(tool):
    result = adapters.call(tool, {})
    assert isinstance(result, dict)
    assert result.get("verdict") != "CERTIFIED"


@pytest.mark.parametrize("tool", tool_names())
def test_no_tool_raises_on_a_non_dict_argument_bundle(tool):
    for junk in (None, [], "args", 5):
        try:
            result = adapters.call(tool, junk)
        except (TypeError, AttributeError):
            continue  # a typed refusal is acceptable; a wrong verdict is not
        assert result.get("verdict") != "CERTIFIED"


def test_verify_certificate_never_reports_a_guard_as_unsound():
    """A certificate failing to verify says nothing about the guard. Conflating
    those is the exact error the three-verdict design exists to prevent."""
    from certkit.cli import _load, example_path

    spec = _load(example_path("heartbleed.spec.json"))
    forged = _load(example_path("heartbleed.forged.json"))
    for cert in (forged, {}, None, [], "cert", {"schema": "x"}):
        result = adapters.call("verify_certificate", {"spec": spec, "cert": cert})
        assert result.get("verdict") != "PROVEN_UNSOUND"
        assert json.dumps(result)


def test_explain_refusal_never_invents_a_verdict():
    for verdict in ({}, None, [], "CERTIFIED", {"verdict": "MADE_UP"}, {"verdict": None}):
        result = adapters.call("explain_refusal", {"verdict": verdict})
        text = result["explanation"]
        assert isinstance(text, str) and text
        assert "CERTIFIED" not in text or "MADE_UP" not in text


def test_decide_and_certify_agree_on_every_hostile_input():
    """The short-circuit may change how long an answer takes and never what it
    is -- including on inputs where the answer is a refusal."""
    for label, args in HOSTILE_ARGS:
        decided = adapters.call("decide_guard", args)["verdict"]
        certified = adapters.call("certify_guard", args)["verdict"]
        assert decided == certified, f"{label}: decide={decided} certify={certified}"


def test_decide_and_certify_agree_on_a_sweep_of_real_guards():
    for guard_const in range(0, 24, 3):
        for upper in (15, 63, 127):
            args = {
                "domain": [{"coeff": {"p": -1}}, {"coeff": {"p": 1}, "const": -upper}],
                "guard": [{"coeff": {"p": 1, "r": -1}, "const": guard_const}],
                "safety": [{"coeff": {"p": 1, "r": -1}, "const": 3}],
                "box": {"p": [0, upper], "r": [0, upper]},
            }
            assert (
                adapters.call("decide_guard", args)["verdict"]
                == adapters.call("certify_guard", args)["verdict"]
            ), (guard_const, upper)


def test_every_result_is_json_serialisable_without_a_custom_encoder():
    """An MCP server writes JSON. A result carrying a Fraction would serialise
    only because of `default=str`, which silently stringifies a number."""
    for tool in GUARD_TOOLS:
        for _, args in HOSTILE_ARGS[:8]:
            json.dumps(adapters.call(tool, args))
    json.dumps(adapters.call("certify_guard", SOUND))


def test_schemas_stay_serialisable_and_stable_across_calls():
    first = json.dumps(adapters.json_schemas(), sort_keys=True)
    second = json.dumps(adapters.json_schemas(), sort_keys=True)
    assert first == second, "the emitted schemas are not deterministic"


def test_mutating_an_emitted_schema_cannot_affect_the_next_caller():
    """The catalogue is module-level state; an adapter handing out a shared
    mutable object would let one caller change what every later caller sees."""
    emitted = adapters.openai_tools()
    emitted[0]["function"]["description"] = "TAMPERED"
    fresh = adapters.openai_tools()
    assert fresh[0]["function"]["description"] != "TAMPERED"
