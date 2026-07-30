"""The verdict surfaces, as plain functions.

These are deliberately independent of the MCP transport so they can be tested
directly and reused from a CLI. :mod:`crs_mcp.server` is a thin wiring layer.

The design principle throughout: **an agent must not be able to mistake a refusal
for an approval.** Every verdict is one of three values, and the third one is not
a failure mode -- it is the honest answer when the question is outside what this
tool can decide:

    CERTIFIED       the guard admits no forbidden state, over the declared box
    PROVEN_UNSOUND  it admits at least one, and here is a concrete example
    OUT_OF_SCOPE    the box is too large to decide by exhaustive counting

``OUT_OF_SCOPE`` is never rendered as a pass. That matters more here than in a
human-facing tool, because an agent will happily read "no errors" as "approved"
and commit.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any

from certkit import Atom, atom, atom_from_json, check_certificate, negate
from exploit_counter import (
    BoxError,
    box_volume,
    count_conjunction,
    decide_soundness,
    enumeration_cost,
    find_witness,
    validate_box,
)

__all__ = [
    "CERTIFIED",
    "PROVEN_UNSOUND",
    "OUT_OF_SCOPE",
    "Verdict",
    "certify_guard",
    "decide_guard",
    "count_exploitability",
    "verify_certificate",
    "explain_refusal",
    "parse_atoms",
    "parse_box",
]

CERTIFIED = "CERTIFIED"
PROVEN_UNSOUND = "PROVEN_UNSOUND"
OUT_OF_SCOPE = "OUT_OF_SCOPE"

# The cap applies to the *enumerated* points, not the box volume. The counter
# enumerates every variable except the widest and closes the form over that one,
# so a two-variable box spanning 2^32 points costs only 2^16 enumerations and is
# decided in well under a second. Three-variable boxes are where the product
# bites. Kept well below the counting package's default because an agent-facing
# tool should answer in seconds or decline.
AGENT_EXACT_CAP = 500_000


@dataclass
class Verdict:
    verdict: str
    summary: str
    detail: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def _repr_html_(self) -> str:
        """Notebook rendering.

        OUT_OF_SCOPE gets its own colour and its own sentence. It is the verdict
        most likely to be skimmed as "fine", and it is the one that means no
        answer was reached at all.
        """
        from html import escape

        colours = {
            CERTIFIED: ("#0f7b3f", "#eaf6ee"),
            PROVEN_UNSOUND: ("#a41b1b", "#fbeaea"),
            OUT_OF_SCOPE: ("#8a5a00", "#fff6e5"),
        }
        meaning = {
            CERTIFIED: (
                "No forbidden state is admitted <b>over the declared box</b>. "
                "This says nothing about states outside it."
            ),
            PROVEN_UNSOUND: "The guard admits a state the safety property forbids.",
            OUT_OF_SCOPE: (
                "<b>No verdict was reached.</b> This is not an approval and not a "
                "clean bill of health."
            ),
        }
        fg, bg = colours.get(self.verdict, ("#333", "#f2f2f2"))
        return (
            f'<div style="border-left:4px solid {fg};background:{bg};padding:10px 14px;'
            f'font-family:system-ui,sans-serif;font-size:13px;color:#111;max-width:46em">'
            f'<div style="font-weight:700;color:{fg};font-family:ui-monospace,monospace">'
            f"{escape(self.verdict)}</div>"
            f"<div>{escape(self.summary)}</div>"
            f'<div style="margin-top:6px">{meaning.get(self.verdict, "")}</div></div>'
        )


# --------------------------------------------------------------------------- #
# input parsing
# --------------------------------------------------------------------------- #


def _num(detail: dict, key: str) -> str:
    """Render a count, or say it is unknown -- never default a missing count to 0.

    `detail.get(key, 0)` reads as "would enumerate 0 points", which is a confident
    statement about a quantity nobody measured, in a message a user actually sees. Found
    by `scripts/refusal_audit.py` once its roots were widened to reach `oss/` -- the
    published packages had never been audited.
    """
    v = detail.get(key)
    return f"{v:,}" if isinstance(v, int) else "an unrecorded number of"


def parse_atoms(raw: Sequence[Mapping[str, Any]]) -> list[Atom]:
    """Accept either the certkit JSON atom form or a friendlier agent form.

    The friendly form is what a language model will actually produce::

        {"coeff": {"p": 1, "r": -1}, "const": 19, "strict": false}

    Plain integers rather than ``[num, den]`` pairs. Both are accepted.
    """
    out: list[Atom] = []
    for a in raw:
        if not isinstance(a, Mapping):
            raise ValueError(f"atom must be an object, got {type(a).__name__}")
        coeff = a.get("coeff", {})
        if not isinstance(coeff, Mapping):
            raise ValueError(f"atom 'coeff' must be an object, got {type(coeff).__name__}")
        const = a.get("const", 0)
        strict = bool(a.get("strict", False))
        if coeff and all(isinstance(v, (list, tuple)) for v in coeff.values()):
            out.append(atom_from_json(a))
            continue
        out.append(atom(dict(coeff.items()), const, strict))
    return out


def parse_box(raw: Mapping[str, Any]) -> dict[str, tuple[int, int]]:
    """Accept ``{"p": [0, 65535]}`` or ``{"p": {"lo": 0, "hi": 65535}}``."""
    box: dict[str, tuple[int, int]] = {}
    for name, spec in raw.items():
        if isinstance(spec, Mapping):
            box[name] = (int(spec["lo"]), int(spec["hi"]))
        else:
            lo, hi = spec
            box[name] = (int(lo), int(hi))
    return box


# --------------------------------------------------------------------------- #
# the tools
# --------------------------------------------------------------------------- #


def certify_guard(
    domain: Sequence[Mapping[str, Any]],
    guard: Sequence[Mapping[str, Any]],
    safety: Sequence[Mapping[str, Any]],
    box: Mapping[str, Any],
    *,
    exact_cap: int = AGENT_EXACT_CAP,
) -> Verdict:
    """Decide whether ``guard`` implies ``safety`` over ``domain``, within ``box``.

    Decided by exhaustive integer counting over the declared box. That is sound
    and complete *for the box you declare*, and says nothing outside it -- which
    is why the box is a required argument rather than something inferred.
    """
    try:
        d = parse_atoms(domain)
        g = parse_atoms(guard)
        s = parse_atoms(safety)
        b = parse_box(box)
    except (KeyError, TypeError, ValueError, AttributeError, ArithmeticError) as exc:
        # ArithmeticError covers the two an adversarial suite found escaping:
        # a coefficient of Infinity (OverflowError from Fraction) and a
        # [numerator, 0] pair (ZeroDivisionError). Both are attacker-reachable
        # from a model-authored atom, and a traceback out of an agent-facing
        # tool is a failure mode of its own.
        return Verdict(
            OUT_OF_SCOPE,
            f"could not parse the request: {exc}",
            {"reason": "malformed-input"},
        )

    if not s:
        return Verdict(
            OUT_OF_SCOPE,
            "no safety property was supplied, so there is nothing to certify",
            {"reason": "empty-safety"},
        )
    if not b:
        return Verdict(
            OUT_OF_SCOPE,
            "no variable box was supplied; an unbounded domain cannot be counted",
            {"reason": "empty-box"},
        )

    base = list(d) + list(g)
    all_atoms = base + [negate(c) for c in s]

    # Refuse a box that cannot carry a verdict before counting anything. An
    # inverted or single-point box would otherwise count zero escapes and be
    # reported as CERTIFIED, and an atom naming an undeclared variable used to
    # escape as a raw KeyError.
    try:
        validate_box(b, all_atoms, allow_degenerate=False)
    except BoxError as exc:
        return Verdict(
            OUT_OF_SCOPE,
            f"the declared box cannot support a verdict: {exc}",
            {"reason": "unusable-box", "detail": str(exc)},
        )

    total = 0
    witness: dict[str, int] | None = None
    volume = box_volume(b)
    enumerated, closed_form = enumeration_cost(b)

    for _i, conjunct in enumerate(s):
        atoms = base + [negate(conjunct)]
        n = count_conjunction(atoms, b, exact_cap=exact_cap)
        if n is None:
            return Verdict(
                OUT_OF_SCOPE,
                (
                    f"deciding this box would enumerate {enumerated:,} points, above the "
                    f"{exact_cap:,} limit. The counter enumerates every variable except the "
                    f"widest ({closed_form!r}, which is solved in closed form), so the cost "
                    f"is the product of the other ranges -- not the {volume:,}-point box "
                    "volume. Narrowing any variable other than the widest is what reduces "
                    "it. Deciding domains of this size without enumerating needs the "
                    "solver-free decision procedure, which is not part of this package."
                ),
                {
                    "reason": "enumeration-too-large",
                    "enumerated_points": enumerated,
                    "closed_form_variable": closed_form,
                    "box_volume": volume,
                    "exact_cap": exact_cap,
                },
            )
        if n and witness is None:
            witness = find_witness(atoms, b, exact_cap=exact_cap)
        total += n

    if total == 0:
        return Verdict(
            CERTIFIED,
            (
                f"The guard admits no state the safety property forbids, over all "
                f"{volume:,} points of the declared box."
            ),
            {"over_acceptance": 0, "box_volume": volume, "n_conjuncts": len(s)},
        )

    return Verdict(
        PROVEN_UNSOUND,
        (
            f"The guard admits {total:,} state(s) the safety property forbids "
            f"(out of {volume:,}). Example: {witness}."
        ),
        {
            "over_acceptance": total,
            "box_volume": volume,
            "counterexample": witness,
            "hit_probability": total / volume if volume else None,
            "expected_draws_to_hit": (volume / total) if total else None,
        },
    )


def decide_guard(
    domain: Sequence[Mapping[str, Any]],
    guard: Sequence[Mapping[str, Any]],
    safety: Sequence[Mapping[str, Any]],
    box: Mapping[str, Any],
    *,
    exact_cap: int = AGENT_EXACT_CAP,
) -> Verdict:
    """Same verdict as :func:`certify_guard`, reached without counting.

    Stops at the first escaping state instead of counting the whole violating
    region. On a measured unsound guard that is 286 ms of counting replaced by
    0.04 ms of search -- worth having when the question is "is this safe?" rather
    than "how unsafe?".

    The detail deliberately carries **no** ``over_acceptance`` field. Nothing was
    counted, so reporting a number here -- even zero -- would be a figure the
    analysis did not produce.
    """
    try:
        d = parse_atoms(domain)
        g = parse_atoms(guard)
        s = parse_atoms(safety)
        b = parse_box(box)
    except (KeyError, TypeError, ValueError, AttributeError, ArithmeticError) as exc:
        return Verdict(
            OUT_OF_SCOPE,
            f"could not parse the request: {exc}",
            {"reason": "malformed-input", "counted": False},
        )

    if not s:
        return Verdict(
            OUT_OF_SCOPE,
            "no safety property was supplied, so there is nothing to certify",
            {"reason": "empty-safety", "counted": False},
        )
    if not b:
        return Verdict(
            OUT_OF_SCOPE,
            "no variable box was supplied; an unbounded domain cannot be decided",
            {"reason": "empty-box", "counted": False},
        )

    try:
        decision = decide_soundness(d, g, s, b, exact_cap=exact_cap, allow_degenerate=False)
    except BoxError as exc:
        return Verdict(
            OUT_OF_SCOPE,
            f"the declared box cannot support a verdict: {exc}",
            {"reason": "unusable-box", "detail": str(exc), "counted": False},
        )

    volume = box_volume(b)
    _, closed_form = enumeration_cost(b)
    base = {
        "counted": False,
        "box_volume": volume,
        "enumerated_points": decision.enumerated_points,
        "exact_cap": decision.exact_cap,
    }

    if decision.is_sound is None:
        return Verdict(
            OUT_OF_SCOPE,
            (
                f"deciding this box would enumerate {decision.enumerated_points:,} points, "
                f"above the {decision.exact_cap:,} limit. The counter enumerates every "
                f"variable except the widest ({closed_form!r}, solved in closed form), so "
                f"narrowing any other variable is what reduces it. No search was run."
            ),
            base | {"reason": "enumeration-too-large", "closed_form_variable": closed_form},
        )

    if decision.is_sound:
        return Verdict(
            CERTIFIED,
            (
                f"The guard admits no state the safety property forbids, over all "
                f"{volume:,} points of the declared box. (Decided by search; the "
                f"number of admitted states was not counted.)"
            ),
            base | {"n_conjuncts": len(s)},
        )

    return Verdict(
        PROVEN_UNSOUND,
        (
            f"The guard admits at least one state the safety property forbids. "
            f"Example: {decision.witness}. (Decided by search; use certify_guard "
            f"for the exact count.)"
        ),
        base | {"counterexample": decision.witness},
    )


def count_exploitability(
    domain: Sequence[Mapping[str, Any]],
    guard: Sequence[Mapping[str, Any]],
    safety: Sequence[Mapping[str, Any]],
    box: Mapping[str, Any],
    *,
    exact_cap: int = AGENT_EXACT_CAP,
) -> dict[str, Any]:
    """Exactly how many states the guard wrongly admits, plus a witness."""
    v = certify_guard(domain, guard, safety, box, exact_cap=exact_cap)
    out = v.to_dict()
    out["note"] = (
        "This is a triggerability count under a uniform sampling model over the "
        "declared box. It is not a severity score and not a claim of "
        "weaponisability."
    )
    return out


def verify_certificate(spec: Mapping[str, Any], cert: Mapping[str, Any]) -> dict[str, Any]:
    """Re-check a certkit certificate against its specification.

    A certificate that fails to check is **not** evidence that the guard is
    unsound -- it is the absence of a proof, which is why this never returns
    ``PROVEN_UNSOUND``. Only counting states can prove unsoundness; use
    :func:`certify_guard` for that.
    """
    try:
        report = check_certificate(spec, cert)
    except (KeyError, TypeError, ValueError, AttributeError, ArithmeticError) as exc:
        return {
            "verdict": OUT_OF_SCOPE,
            "ok": False,
            "certificate_verdict": "REFUSED",
            "reason": f"the certificate or spec could not be parsed: {exc}",
            "obligations": [],
            "note": "Malformed input is a refusal, not an approval.",
        }

    if report.verdict == "ACCEPTED":
        verdict = CERTIFIED
        note = (
            "The checker rebuilds each obligation from the spec and ignores any "
            "atoms the certificate carries, so a certificate proving an unrelated "
            "easy system cannot pass."
        )
    elif report.verdict == "UNVERIFIED":
        verdict = OUT_OF_SCOPE
        note = (
            "The multipliers checked out, but the certificate is not bound to this "
            "spec, so nothing establishes that it was issued for it. This is NOT an "
            "approval."
        )
    else:
        verdict = OUT_OF_SCOPE
        note = (
            "The certificate did not check. That means 'not proven' -- it is NOT "
            "evidence that the guard is unsound, and must not be reported as such. "
            "To decide soundness, count states with certify_guard."
        )

    return {
        "verdict": verdict,
        "ok": report.ok,
        "certificate_verdict": report.verdict,
        "binding_verified": report.binding_verified,
        "reason": report.reason,
        "obligations": report.obligations,
        "note": note,
    }


def explain_refusal(verdict: Mapping[str, Any]) -> str:
    """Turn a verdict into prose an agent can relay to a human.

    Anything that is not a verdict object gets a sentence saying so. This used to
    raise `AttributeError` on `None`, which an agent framework renders as a tool
    error for the model to interpret however it likes -- and "the tool errored"
    is a far more permissive thing for a model to read than "that was not a
    verdict".
    """
    if not isinstance(verdict, Mapping):
        return (
            "That is not a verdict object, so there is nothing to explain. Pass "
            "the object returned by certify_guard or decide_guard. No claim is "
            "being made about any guard."
        )
    v = verdict.get("verdict")
    detail = verdict.get("detail", {}) or {}
    if not isinstance(detail, Mapping):
        detail = {}

    if v == CERTIFIED:
        return (
            "The guard was CERTIFIED over the declared box: exhaustive counting "
            "found no assignment that satisfies the guard while violating the "
            "safety property. This is a statement about the box that was declared "
            "and says nothing about states outside it."
        )

    if v == PROVEN_UNSOUND:
        n = detail.get("over_acceptance")
        cx = detail.get("counterexample")
        draws = detail.get("expected_draws_to_hit")
        parts = [
            f"The guard was PROVEN UNSOUND. It admits {n:,} state(s) that the "
            "safety property forbids."
        ]
        if cx:
            assignment = ", ".join(f"{k}={val}" for k, val in sorted(cx.items()))
            parts.append(
                f"A concrete counterexample is {assignment} -- at that assignment the "
                "guard passes but the safety property does not hold."
            )
        if draws:
            parts.append(
                f"Under uniform sampling a fuzzer would need roughly {draws:,.0f} "
                "draws to find one, which is why testing may not have caught it."
            )
        parts.append("Strengthen the guard so that this assignment is rejected.")
        return " ".join(parts)

    reason = detail.get("reason", "unknown")
    if reason in ("enumeration-too-large", "box-too-large"):
        return (
            "The request was OUT OF SCOPE, which is not a pass and not a failure. "
            f"Deciding it would enumerate {_num(detail, 'enumerated_points')} points, "
            f"beyond the {_num(detail, 'exact_cap')} this package will spend. Note that "
            "the limit is the enumerated product, not the "
            f"{_num(detail, 'box_volume')}-point box volume -- the widest variable "
            f"({detail.get('closed_form_variable')!r}) is solved in closed form and costs "
            "nothing, so narrowing one of the *other* variables is what helps. Do not "
            "treat this as approval."
        )
    if reason == "unusable-box":
        return (
            "The request was OUT OF SCOPE: the declared box cannot support a verdict. "
            f"{detail.get('detail', '')} Nothing was certified and nothing was refuted; "
            "this is emphatically not an approval."
        )
    if reason == "empty-safety":
        return (
            "The request was OUT OF SCOPE: no safety property was supplied, so "
            "there was nothing to certify. This is not an approval."
        )
    if reason == "empty-box":
        return (
            "The request was OUT OF SCOPE: no variable bounds were supplied. An "
            "unbounded domain has no finite state count. This is not an approval."
        )
    return (
        "The request was OUT OF SCOPE and no verdict was reached. This is not an "
        "approval. Reason: " + str(reason)
    )
