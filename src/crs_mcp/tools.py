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
from exploit_counter import box_volume, count_conjunction, find_witness

__all__ = [
    "CERTIFIED",
    "PROVEN_UNSOUND",
    "OUT_OF_SCOPE",
    "Verdict",
    "certify_guard",
    "count_exploitability",
    "verify_certificate",
    "explain_refusal",
    "parse_atoms",
    "parse_box",
]

CERTIFIED = "CERTIFIED"
PROVEN_UNSOUND = "PROVEN_UNSOUND"
OUT_OF_SCOPE = "OUT_OF_SCOPE"

# Kept well below the counting package's default. An agent-facing tool should
# answer in seconds or decline; a thirty-second stall is a worse experience than
# an honest "too big for the open tier".
AGENT_EXACT_CAP = 500_000


@dataclass
class Verdict:
    verdict: str
    summary: str
    detail: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# input parsing
# --------------------------------------------------------------------------- #


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
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
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
    total = 0
    witness: dict[str, int] | None = None
    volume = box_volume(b)

    for _i, conjunct in enumerate(s):
        atoms = base + [negate(conjunct)]
        n = count_conjunction(atoms, b, exact_cap=exact_cap)
        if n is None:
            return Verdict(
                OUT_OF_SCOPE,
                (
                    "the declared box is too large to decide by exhaustive counting "
                    f"({volume:,} points). This open tier decides by enumeration; "
                    "deciding domains of this size needs the solver-free decision "
                    "procedure, which is not part of this package."
                ),
                {
                    "reason": "box-too-large",
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
    """Re-check a certkit certificate against its specification."""
    report = check_certificate(spec, cert)
    return {
        "verdict": CERTIFIED
        if report.ok
        else PROVEN_UNSOUND
        if report.obligations
        else OUT_OF_SCOPE,
        "ok": report.ok,
        "reason": report.reason,
        "obligations": report.obligations,
        "note": (
            "The checker rebuilds each obligation from the spec and ignores any "
            "atoms the certificate carries, so a certificate proving an unrelated "
            "easy system cannot pass."
        ),
    }


def explain_refusal(verdict: Mapping[str, Any]) -> str:
    """Turn a verdict into prose an agent can relay to a human."""
    v = verdict.get("verdict")
    detail = verdict.get("detail", {}) or {}

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
    if reason == "box-too-large":
        return (
            "The request was OUT OF SCOPE, which is not a pass and not a failure. "
            f"The declared box has {detail.get('box_volume', 0):,} points, beyond "
            "what this package decides by exhaustive enumeration. Either narrow the "
            "box, or use a decision procedure that does not enumerate. Do not treat "
            "this as approval."
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
