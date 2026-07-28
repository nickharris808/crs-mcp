"""Tool-layer tests.

The verdict semantics are the product here, so most of these tests are about the
three-way distinction and specifically about OUT_OF_SCOPE never masquerading as
an approval.
"""

import pytest

from crs_mcp import tools
from crs_mcp.tools import CERTIFIED, OUT_OF_SCOPE, PROVEN_UNSOUND

# 0 <= payload <= 255
DOMAIN = [
    {"coeff": {"payload": -1}, "const": 0},
    {"coeff": {"payload": 1}, "const": -255},
]
SAFETY = [{"coeff": {"payload": 1, "record_len": -1}, "const": 3}]
BOX = {"payload": [0, 255], "record_len": [0, 255]}


def test_sound_guard_is_certified():
    guard = [{"coeff": {"payload": 1, "record_len": -1}, "const": 19}]
    v = tools.certify_guard(DOMAIN, guard, SAFETY, BOX)
    assert v.verdict == CERTIFIED
    assert v.detail["over_acceptance"] == 0


def test_weak_guard_is_proven_unsound_with_a_counterexample():
    guard = [{"coeff": {"payload": 1, "record_len": -1}, "const": 1}]
    v = tools.certify_guard(DOMAIN, guard, SAFETY, BOX)
    assert v.verdict == PROVEN_UNSOUND
    assert v.detail["over_acceptance"] > 0

    cx = v.detail["counterexample"]
    assert cx is not None
    # The counterexample must really satisfy the guard and violate safety.
    p, r = cx["payload"], cx["record_len"]
    assert 1 + p <= r  # guard passes
    assert not (3 + p <= r)  # safety fails


def test_oversized_box_is_out_of_scope_not_certified():
    """The load-bearing test: refusing must never look like passing."""
    guard = [{"coeff": {"payload": 1, "record_len": -1}, "const": 19}]
    big = {"payload": [0, 65535], "record_len": [0, 65535], "extra": [0, 65535]}
    v = tools.certify_guard(DOMAIN, guard, SAFETY, big, exact_cap=1000)
    assert v.verdict == OUT_OF_SCOPE
    assert v.verdict != CERTIFIED
    assert v.detail["reason"] == "enumeration-too-large"
    # The refusal must name the quantity that actually hit the limit -- the
    # enumerated product -- not the box volume, which is far larger and would
    # send the reader off narrowing the wrong variable.
    assert v.detail["enumerated_points"] <= v.detail["box_volume"]
    assert v.detail["closed_form_variable"] in big
    assert f"{v.detail['enumerated_points']:,}" in v.summary


def test_missing_safety_is_out_of_scope():
    v = tools.certify_guard(DOMAIN, [], [], BOX)
    assert v.verdict == OUT_OF_SCOPE
    assert v.detail["reason"] == "empty-safety"


def test_missing_box_is_out_of_scope():
    guard = [{"coeff": {"payload": 1, "record_len": -1}, "const": 19}]
    v = tools.certify_guard(DOMAIN, guard, SAFETY, {})
    assert v.verdict == OUT_OF_SCOPE
    assert v.detail["reason"] == "empty-box"


def test_malformed_input_is_out_of_scope_not_an_exception():
    v = tools.certify_guard(DOMAIN, [{"coeff": "not-a-dict"}], SAFETY, BOX)
    assert v.verdict == OUT_OF_SCOPE


def test_certkit_pair_atom_form_is_accepted():
    """Atoms in [num, den] form (the on-disk certkit encoding) must work too."""
    domain = [
        {"coeff": {"payload": [-1, 1]}, "const": [0, 1], "strict": False},
        {"coeff": {"payload": [1, 1]}, "const": [-255, 1], "strict": False},
    ]
    guard = [
        {"coeff": {"payload": [1, 1], "record_len": [-1, 1]}, "const": [19, 1], "strict": False}
    ]
    safety = [
        {"coeff": {"payload": [1, 1], "record_len": [-1, 1]}, "const": [3, 1], "strict": False}
    ]
    v = tools.certify_guard(domain, guard, safety, BOX)
    assert v.verdict == CERTIFIED


def test_box_dict_form_is_accepted():
    guard = [{"coeff": {"payload": 1, "record_len": -1}, "const": 19}]
    box = {"payload": {"lo": 0, "hi": 255}, "record_len": {"lo": 0, "hi": 255}}
    v = tools.certify_guard(DOMAIN, guard, safety=SAFETY, box=box)
    assert v.verdict == CERTIFIED


def test_count_exploitability_carries_the_scope_note():
    guard = [{"coeff": {"payload": 1, "record_len": -1}, "const": 1}]
    out = tools.count_exploitability(DOMAIN, guard, SAFETY, BOX)
    assert out["detail"]["over_acceptance"] > 0
    assert "not a severity score" in out["note"]


# --------------------------------------------------------------------------- #
# explain_refusal
# --------------------------------------------------------------------------- #


def test_explain_certified_states_its_limits():
    guard = [{"coeff": {"payload": 1, "record_len": -1}, "const": 19}]
    v = tools.certify_guard(DOMAIN, guard, SAFETY, BOX).to_dict()
    text = tools.explain_refusal(v)
    assert "CERTIFIED" in text
    assert "says nothing about states outside it" in text


def test_explain_unsound_gives_the_assignment():
    guard = [{"coeff": {"payload": 1, "record_len": -1}, "const": 1}]
    v = tools.certify_guard(DOMAIN, guard, SAFETY, BOX).to_dict()
    text = tools.explain_refusal(v)
    assert "PROVEN UNSOUND" in text
    assert "payload=" in text and "record_len=" in text
    assert "Strengthen the guard" in text


def test_explain_out_of_scope_says_it_is_not_approval():
    guard = [{"coeff": {"payload": 1, "record_len": -1}, "const": 19}]
    big = {"payload": [0, 65535], "record_len": [0, 65535], "extra": [0, 65535]}
    v = tools.certify_guard(DOMAIN, guard, SAFETY, big, exact_cap=1000).to_dict()
    text = tools.explain_refusal(v)
    assert "not a pass" in text or "not treat this as approval" in text.lower()
    assert "Do not treat this as approval" in text


@pytest.mark.parametrize("reason", ["empty-safety", "empty-box", "malformed-input"])
def test_every_out_of_scope_reason_says_not_an_approval(reason):
    v = {"verdict": OUT_OF_SCOPE, "summary": "", "detail": {"reason": reason}}
    text = tools.explain_refusal(v)
    assert "not an approval" in text.lower() or "not treat this as approval" in text.lower()


# --------------------------------------------------------------------------- #
# certificate verification
# --------------------------------------------------------------------------- #


def test_verify_certificate_accepts_a_good_one():
    from certkit import atom, make_spec
    from certkit.cert import CERT_SCHEMA

    domain = [atom({"p": -1}), atom({"p": 1}, -65535)]
    guard = [atom({"p": 1, "r": -1}, 19)]
    safety = [atom({"p": 1, "r": -1}, 3)]
    spec = make_spec(domain, guard, safety, name="hb")
    cert = {
        "schema": CERT_SCHEMA,
        "spec_fingerprint": spec["fingerprint"],
        "obligations": [{"multipliers": {"2": 1, "3": 1}}],
    }
    out = tools.verify_certificate(spec, cert)
    assert out["ok"] is True
    assert out["verdict"] == CERTIFIED


def test_verify_certificate_rejects_a_forged_one():
    from certkit import atom, make_spec
    from certkit.cert import CERT_SCHEMA

    domain = [atom({"p": -1}), atom({"p": 1}, -65535)]
    guard = [atom({"p": 1, "r": -1}, 19)]
    safety = [atom({"p": 1, "r": -1}, 3)]
    spec = make_spec(domain, guard, safety, name="hb")
    cert = {
        "schema": CERT_SCHEMA,
        "spec_fingerprint": spec["fingerprint"],
        "obligations": [{"multipliers": {"0": 1, "1": 1}}],
    }
    out = tools.verify_certificate(spec, cert)
    assert out["ok"] is False


# --------------------------------------------------------------------------- #
# dispatch layer
# --------------------------------------------------------------------------- #


def test_dispatch_routes_each_tool():
    from crs_mcp.server import dispatch

    guard = [{"coeff": {"payload": 1, "record_len": -1}, "const": 19}]
    args = {"domain": DOMAIN, "guard": guard, "safety": SAFETY, "box": BOX}

    assert dispatch("certify_guard", args)["verdict"] == CERTIFIED
    assert "note" in dispatch("count_exploitability", args)
    assert "explanation" in dispatch("explain_refusal", {"verdict": {"verdict": CERTIFIED}})
    assert "error" in dispatch("no_such_tool", {})


def test_every_declared_tool_is_dispatchable():
    """A tool advertised to an agent but not routed would be a silent dead end."""
    from crs_mcp.server import TOOLS, dispatch

    for tool in TOOLS:
        out = dispatch(tool.name, {})
        assert not (isinstance(out, dict) and out.get("error", "").startswith("unknown tool"))
