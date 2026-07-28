"""Adversarial regression suite for the agent-facing verdict surface.

The oracle for every test in this file is one sentence:

    **No input may produce a confident-looking answer that is wrong.**

An agent reads ``CERTIFIED`` as "approved, commit it", so ``CERTIFIED`` is the
only answer worth attacking. Everything here tries to obtain one without
earning it, or to obtain a crash -- because an unhandled traceback in an
agent-facing tool is its own failure mode.

This is also the only package that depends on both ``certkit`` and
``exploit-counter``, so the **differential** test lives here: the proof checker
and the counter are independent implementations of the same question, and they
must agree with brute force and with each other on every input.
"""

from __future__ import annotations

import itertools
import random

import pytest
from certkit import atom, check_certificate, make_spec, negate

from crs_mcp import tools
from crs_mcp.tools import CERTIFIED, OUT_OF_SCOPE, PROVEN_UNSOUND

DOMAIN = [{"coeff": {"payload": -1}}, {"coeff": {"payload": 1}, "const": -255}]
GUARD = [{"coeff": {"payload": 1, "record_len": -1}, "const": 19}]
SAFETY = [{"coeff": {"payload": 1, "record_len": -1}, "const": 3}]
BOX = {"payload": [0, 255], "record_len": [0, 255]}


def brute_force_witness(atoms, box):
    """Ground truth by exhaustion: the first point satisfying every atom."""
    names = list(box)
    for point in itertools.product(*(range(box[v][0], box[v][1] + 1) for v in names)):
        assign = dict(zip(names, point))
        ok = True
        for a in atoms:
            s = a.const + sum(c * assign[v] for v, c in a.coeff.items())
            if (s >= 0) if a.strict else (s > 0):
                ok = False
                break
        if ok:
            return assign
    return None


# --------------------------------------------------------------------------- #
# degenerate and inverted boxes -- must never certify
# --------------------------------------------------------------------------- #


UNSOUND_GUARD = [{"coeff": {"payload": 1, "record_len": -1}, "const": 1}]


def test_single_point_box_is_not_certified():
    """The guard is unsound, but a one-point box has nowhere to show it."""
    v = tools.certify_guard(
        DOMAIN, UNSOUND_GUARD, SAFETY, {"payload": [0, 0], "record_len": [0, 0]}
    )
    assert v.verdict == OUT_OF_SCOPE
    assert v.detail["reason"] == "unusable-box"


def test_inverted_box_is_not_certified():
    v = tools.certify_guard(
        DOMAIN, UNSOUND_GUARD, SAFETY, {"payload": [10, 2], "record_len": [0, 255]}
    )
    assert v.verdict == OUT_OF_SCOPE
    assert "inverted" in v.detail["detail"]


def test_unusable_box_refusal_explains_it_is_not_approval():
    v = tools.certify_guard(
        DOMAIN, UNSOUND_GUARD, SAFETY, {"payload": [0, 0], "record_len": [0, 0]}
    )
    prose = tools.explain_refusal(v.to_dict())
    assert "not an approval" in prose.lower()


# --------------------------------------------------------------------------- #
# out-of-distribution: variables the box never declared -- the old KeyError
# --------------------------------------------------------------------------- #


def test_atom_naming_an_undeclared_variable_is_refused_not_raised():
    safety = [{"coeff": {"q": 1, "record_len": -1}, "const": 3}]
    v = tools.certify_guard(DOMAIN, GUARD, safety, BOX)
    assert v.verdict == OUT_OF_SCOPE
    assert "'q'" in v.summary


def test_undeclared_variable_in_the_guard_is_also_refused():
    guard = [{"coeff": {"payload": 1, "zzz": -1}, "const": 19}]
    v = tools.certify_guard(DOMAIN, guard, SAFETY, BOX)
    assert v.verdict == OUT_OF_SCOPE
    assert "'zzz'" in v.summary


# --------------------------------------------------------------------------- #
# the ceiling is the enumerated product, not the box volume -- D4
# --------------------------------------------------------------------------- #


def test_two_variable_box_of_four_billion_points_is_decided():
    """The README used to claim this would be refused. It is not.

    Only the narrower variable is enumerated, so a 2^32-point box costs 2^16.
    """
    v = tools.certify_guard(
        DOMAIN, GUARD, SAFETY, {"payload": [0, 65535], "record_len": [0, 65535]}
    )
    assert v.verdict == CERTIFIED
    assert v.detail["box_volume"] == 4294967296


def test_refusal_reports_the_enumerated_product_not_the_box_volume():
    big = {"payload": [0, 999], "record_len": [0, 999], "extra": [0, 999]}
    v = tools.certify_guard(DOMAIN, GUARD, SAFETY, big, exact_cap=1000)
    assert v.verdict == OUT_OF_SCOPE
    assert v.detail["reason"] == "enumeration-too-large"
    assert v.detail["enumerated_points"] < v.detail["box_volume"]
    prose = tools.explain_refusal(v.to_dict())
    assert "not the" in prose and "box volume" in prose


# --------------------------------------------------------------------------- #
# malformed / empty -- reject, never raise
# --------------------------------------------------------------------------- #

GARBAGE = [
    None,
    "string",
    42,
    [None],
    [{"coeff": "not-a-mapping"}],
    [{"coeff": {"p": None}}],
    [{"coeff": {"p": float("nan")}}],
    [{"coeff": {"p": float("inf")}}],
    [{"coeff": {"p": 1}, "const": "banana"}],
    [{"coeff": {"p": [1, 0]}}],
]


@pytest.mark.parametrize("junk", GARBAGE)
def test_garbage_atoms_never_certify_and_never_raise(junk):
    for slot in range(3):
        args = [DOMAIN, GUARD, SAFETY]
        args[slot] = junk
        v = tools.certify_guard(*args, BOX)
        assert v.verdict != CERTIFIED


BAD_BOXES = [
    None,
    "string",
    {},
    {"payload": None},
    {"payload": [0]},
    {"payload": [0, 1, 2]},
    {"payload": {"lo": 0}},
    {"payload": ["a", "b"]},
]


@pytest.mark.parametrize("box", BAD_BOXES)
def test_garbage_boxes_never_certify_and_never_raise(box):
    v = tools.certify_guard(DOMAIN, GUARD, SAFETY, box)
    assert v.verdict != CERTIFIED


def test_empty_safety_is_not_a_pass():
    v = tools.certify_guard(DOMAIN, GUARD, [], BOX)
    assert v.verdict == OUT_OF_SCOPE
    assert "not an approval" in tools.explain_refusal(v.to_dict()).lower()


def test_empty_guard_is_decided_honestly_not_certified():
    """No guard at all admits everything, so it cannot be sound here."""
    v = tools.certify_guard(DOMAIN, [], SAFETY, BOX)
    assert v.verdict == PROVEN_UNSOUND


# --------------------------------------------------------------------------- #
# a failed certificate is NOT proof of unsoundness
# --------------------------------------------------------------------------- #


def test_failed_certificate_is_never_reported_as_proven_unsound():
    """Refusal means 'not proven', never 'proven false'.

    Reporting PROVEN_UNSOUND here would be a confident claim about the guard
    derived from nothing but a bad proof.
    """
    d = [atom({"payload": -1}), atom({"payload": 1}, -65535)]
    g = [atom({"payload": 1, "record_len": -1}, 19)]
    s = [atom({"payload": 1, "record_len": -1}, 3)]
    spec = make_spec(d, g, s, name="hb")
    bogus = {
        "schema": "certkit/farkas/v1",
        "spec_fingerprint": spec["fingerprint"],
        "obligations": [{"multipliers": {"0": 1, "1": 1}}],
    }
    out = tools.verify_certificate(spec, bogus)
    assert out["verdict"] != PROVEN_UNSOUND
    assert out["verdict"] == OUT_OF_SCOPE
    assert out["ok"] is False
    assert "not proven" in out["note"].lower()


def test_verify_certificate_surfaces_the_missing_trust_anchor():
    spec = {"schema": "certkit/spec/v1", "safety": [{"coeff": {"x": [1, 1]}}]}
    out = tools.verify_certificate(spec, {"schema": "certkit/farkas/v1", "obligations": []})
    assert out["verdict"] != CERTIFIED
    assert out["binding_verified"] in (True, False)


def test_verify_certificate_does_not_raise_on_garbage():
    for spec, cert in [({}, {}), (None, None), ("x", "y"), ({"schema": 1}, {"schema": 2})]:
        out = tools.verify_certificate(spec if spec is not None else {}, cert or {})
        assert out["verdict"] != CERTIFIED


# --------------------------------------------------------------------------- #
# differential: two independent implementations plus brute force must agree
# --------------------------------------------------------------------------- #


def test_differential_certified_iff_brute_force_finds_no_witness():
    """crs-mcp's verdict vs. exhaustive point testing, on 200 random guards."""
    rng = random.Random(20260728)
    box = {"payload": (0, 20), "record_len": (0, 20)}
    raw_box = {k: list(v) for k, v in box.items()}
    d = [atom({"payload": -1}), atom({"payload": 1}, -20)]
    for _ in range(200):
        gk = rng.randint(0, 8)
        sk = rng.randint(0, 8)
        g = [atom({"payload": 1, "record_len": -1}, gk)]
        s = [atom({"payload": 1, "record_len": -1}, sk)]
        truth = brute_force_witness(d + g + [negate(s[0])], box)

        v = tools.certify_guard(
            [{"coeff": {"payload": -1}}, {"coeff": {"payload": 1}, "const": -20}],
            [{"coeff": {"payload": 1, "record_len": -1}, "const": gk}],
            [{"coeff": {"payload": 1, "record_len": -1}, "const": sk}],
            raw_box,
        )
        assert (v.verdict == CERTIFIED) == (truth is None), (gk, sk, v.verdict, truth)


def test_differential_counter_agrees_with_the_proof_checker():
    """certkit accepts a Farkas certificate only when the counter counts zero.

    The two share an atom type and nothing else: one does rational refutation
    arithmetic, the other enumerates integer points. A disagreement is a
    soundness bug in whichever is wrong, and this is how it would be caught.
    """
    box = {"payload": (0, 60), "record_len": (0, 60)}
    raw_box = {k: list(v) for k, v in box.items()}
    for gk in range(0, 9):
        for sk in range(0, 9):
            d = [atom({"payload": -1}), atom({"payload": 1}, -60)]
            g = [atom({"payload": 1, "record_len": -1}, gk)]
            s = [atom({"payload": 1, "record_len": -1}, sk)]
            spec = make_spec(d, g, s, name=f"g{gk}s{sk}")

            # The refutation, when one exists, is guard + negated safety.
            cert = {
                "schema": "certkit/farkas/v1",
                "spec_fingerprint": spec["fingerprint"],
                "obligations": [{"multipliers": {"2": 1, "3": 1}}],
            }
            proof_accepts = check_certificate(spec, cert).ok

            v = tools.certify_guard(
                [{"coeff": {"payload": -1}}, {"coeff": {"payload": 1}, "const": -60}],
                [{"coeff": {"payload": 1, "record_len": -1}, "const": gk}],
                [{"coeff": {"payload": 1, "record_len": -1}, "const": sk}],
                raw_box,
            )
            counter_certifies = v.verdict == CERTIFIED

            # A proof is sufficient, never wrong: if certkit accepts, the
            # counter must find zero escapes. (The converse may fail only
            # because this fixed multiplier vector is not the only proof.)
            if proof_accepts:
                assert counter_certifies, (gk, sk)


def test_counterexample_is_real_whenever_one_is_reported():
    """A reported counterexample must actually violate the property."""
    rng = random.Random(999)
    for _ in range(120):
        gk = rng.randint(0, 5)
        sk = rng.randint(gk + 1, 10)  # guaranteed unsound
        v = tools.certify_guard(
            [{"coeff": {"payload": -1}}, {"coeff": {"payload": 1}, "const": -40}],
            [{"coeff": {"payload": 1, "record_len": -1}, "const": gk}],
            [{"coeff": {"payload": 1, "record_len": -1}, "const": sk}],
            {"payload": [0, 40], "record_len": [0, 40]},
        )
        if v.verdict != PROVEN_UNSOUND:
            continue
        cx = v.detail["counterexample"]
        p, r = cx["payload"], cx["record_len"]
        assert gk + p <= r  # the guard passes
        assert not (sk + p <= r)  # the safety property does not hold


# --------------------------------------------------------------------------- #
# metamorphic
# --------------------------------------------------------------------------- #


def test_strengthening_the_guard_never_widens_the_gap():
    previous = None
    for overhead in range(0, 8):
        v = tools.certify_guard(
            DOMAIN,
            [{"coeff": {"payload": 1, "record_len": -1}, "const": overhead}],
            SAFETY,
            BOX,
        )
        n = v.detail.get("over_acceptance", 0)
        if previous is not None:
            assert n <= previous
        previous = n


def test_renaming_variables_does_not_change_the_verdict():
    a = tools.certify_guard(DOMAIN, GUARD, SAFETY, BOX)
    ren = {"payload": "alpha", "record_len": "beta"}
    rename = lambda xs: [  # noqa: E731
        {**x, "coeff": {ren[k]: v for k, v in x["coeff"].items()}} for x in xs
    ]
    b = tools.certify_guard(
        rename(DOMAIN), rename(GUARD), rename(SAFETY), {ren[k]: v for k, v in BOX.items()}
    )
    assert a.verdict == b.verdict
