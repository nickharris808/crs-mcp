# Honest scope

What `crs-mcp` establishes, and what it does not.

This matters more here than in the sibling packages, because the consumer is an AI agent rather than
a person. An agent reads "no errors" as "approved" and commits. Every design choice below exists to
make that reading impossible.

## The three verdicts

| Verdict | Means |
|---|---|
| `CERTIFIED` | No point of the declared box satisfies the guard while violating safety. |
| `PROVEN_UNSOUND` | At least one does, and here it is. |
| `OUT_OF_SCOPE` | **No verdict was reached.** Not a pass, not a failure. |

`OUT_OF_SCOPE` is the load-bearing one. It is returned when the box is too large to enumerate, when
the box cannot carry a verdict at all, and when the input does not parse. `explain_refusal` renders
it as prose that says *"Do not treat this as approval"* in those words, because that sentence is the
entire point of the tool.

A tool that only ever returns green is worse than no tool.

## What `CERTIFIED` does NOT mean

### It is scoped to the box, and the box is your claim

`CERTIFIED` over `{"payload": [0, 255]}` says nothing whatsoever about `payload = 256`. The box is a
required argument precisely so it cannot be inferred, defaulted, or forgotten.

If an agent picks the box, then the agent picked the claim. Review the box the way you would review
an assertion.

### It says nothing about the program

The tool checks relations between symbols. Whether those relations describe the code is a human
judgement made when the atoms were written. An agent that models the wrong relation gets a correct
verdict about the wrong thing.

This is the failure mode to watch for in agent use, and no tool in this portfolio can catch it.

### It is not a severity claim

`over_acceptance` counts states that reach a forbidden relation under uniform sampling. It is not
CVSS, not impact, and not a claim that any counted state is weaponisable. See
[exploit-counter's scope](https://github.com/nickharris808/exploit-counter/blob/main/SCOPE.md).

### Boxes that cannot carry a verdict are refused

A single-point box, an inverted range, or an atom naming a variable the box does not declare all
return `OUT_OF_SCOPE` with `reason: "unusable-box"`. Each of those would otherwise produce a count of
zero and read as `CERTIFIED` — a soundness claim over a region containing nothing.

## A failed certificate is not a proof of unsoundness

`verify_certificate` never returns `PROVEN_UNSOUND`. A certificate that fails to check means *not
proven*; it is the absence of evidence, not evidence of a defect. Reporting it as unsoundness would
be a confident claim derived from nothing.

It returns `OUT_OF_SCOPE` with `certificate_verdict` carrying certkit's own
`ACCEPTED` / `REFUSED` / `UNVERIFIED`, and a note saying so. Only counting states proves unsoundness,
which is what `certify_guard` does.

`UNVERIFIED` there means the multipliers checked out but the certificate was never bound to the spec.
Also not an approval.

## The fragment

Quantifier-free linear integer arithmetic over a bounded box. Not in scope: nonlinear terms, bitwise
operations, machine-word wraparound, floating point, pointers, aliasing, the heap, loops, control
flow, or quantifiers.

The tool will not pretend otherwise: atoms it cannot parse are refused with a reason naming the
offending value, never silently reinterpreted.

## Where the ceiling is

The cap is **500,000 enumerated points**, and the enumerated count is *not* the box volume: the
widest variable is solved in closed form, so a two-variable box spanning 2³² costs 2¹⁶ and is decided
in about 30 ms. Three variables is where the product bites.

`benchmarks/ceiling.py` prints the measured table. Above the cap you get `OUT_OF_SCOPE` with
`enumerated_points`, `closed_form_variable`, and `exact_cap` in the detail, so the refusal tells you
which variable to narrow — narrowing the widest one does nothing, because it was already free.

Deciding full machine-word domains in three or more variables needs a decision procedure that does
not enumerate. That is not in this package.

## Reliability properties an agent can depend on

- **It does not raise.** Malformed atoms, hostile boxes, `NaN`, `Infinity`, zero denominators, and
  non-JSON types are refusals with reasons. A traceback out of an agent-facing tool is its own
  failure mode.
- **Refusals are never green.** No input produces `CERTIFIED` unless the enumeration actually ran and
  found nothing. This is what `tests/test_adversarial.py` exists to keep true.
- **The verdict is deterministic.** Same input, same answer; no sampling on this path.
- **Counterexamples are real.** When `PROVEN_UNSOUND` reports one, it satisfies the guard and
  violates the safety property, and a test asserts that on every reported witness.

## Version support

`mcp >= 1.9.0, < 2.0.0`, verified against 1.9.0 through 1.29.0. `mcp` 2.0.0 changed the server
decorator API (`Server.list_tools` no longer exists) and is not supported yet — CI caught it the day
2.0.0 shipped. 2.x is tracked as future work, not claimed.

## When to use something else

| If you need | Use |
|---|---|
| A portable proof artefact | [certkit](https://github.com/nickharris808/certkit) |
| The count and bracket API directly | [exploit-counter](https://github.com/nickharris808/exploit-counter) |
| A CI gate rather than an agent tool | [certkit-action](https://github.com/nickharris808/certkit-action) |
| Nonlinear, bitvector, or heap reasoning | a general SMT solver |

## The one-sentence version

crs-mcp decides, by exhaustive counting over a box you declare, whether a guard admits a state a
safety property forbids — and when it cannot decide, it says so in a way an agent cannot mistake for
approval.
