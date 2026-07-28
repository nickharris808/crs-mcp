# Changelog

All notable changes to this package. Format follows [Keep a Changelog](https://keepachangelog.com/);
versioning is [semantic](https://semver.org/).

## [0.4.0]

### Added
- **The tools are usable without MCP.** `crs_mcp.adapters` emits the catalogue as OpenAI
  function-calling schemas, Anthropic tool-use schemas, standalone JSON Schema documents, plain
  Python callables, and (on request) LangChain `StructuredTool`s. `call(name, args)` runs a tool with
  no server and no transport. `python -m crs_mcp.adapters anthropic` prints a config to paste.
- `crs_mcp.catalog` — one dependency-free definition per tool (name, model-facing description,
  argument schema). The schemas previously lived inside `server.py`, which cannot be imported
  without the `mcp` package, so nobody off MCP could reach them.
- `check_descriptions_intact()` and tests over every adapter: the sentences that say what a verdict
  does **not** establish must survive the conversion. An adapter that dropped
  "OUT_OF_SCOPE is NOT an approval" while keeping the name and schema would look correct and be
  dangerous.

### Changed
- `server.dispatch` now delegates to `adapters.call`, so MCP and every other integration run the
  same code path rather than two copies that can drift.

## [0.3.0]

### Added
- **`decide_guard` tool**: the same three verdicts as `certify_guard`, reached without counting.
  Measured **287.8 ms → 0.03 ms** on an unsound guard. Registered as an MCP tool.
  Its result carries **no** `over_acceptance` field, because nothing was counted — reporting a
  number there, even zero, would be a figure the analysis did not produce.
- `py.typed`.

## [0.2.0]

**Breaking** for anyone reading the refusal payload.

| Change | 0.1.0 | 0.2.0 |
|---|---|---|
| Oversized-box refusal | `reason: "box-too-large"`, `box_volume` | `reason: "enumeration-too-large"`, with `enumerated_points` and `closed_form_variable` |
| Atom naming an undeclared variable | raised `KeyError` | `OUT_OF_SCOPE` naming the variable |
| Degenerate or inverted box | counted 0, returned `CERTIFIED` | `OUT_OF_SCOPE`, `reason: "unusable-box"` |
| A certificate that fails to check | `PROVEN_UNSOUND` | `OUT_OF_SCOPE` with `certificate_verdict` |

That last row matters: a bad proof is the absence of evidence, not evidence of a defect. Only
counting states can prove a guard unsound.

The documented ceiling was also wrong. The cap applies to the **enumerated product**, not box
volume — a two-variable box spanning 2^32 is decided in ~30 ms, which the README previously claimed
would be refused.

## [0.1.0]
- First release: `certify_guard`, `count_exploitability`, `verify_certificate`, `explain_refusal`.
