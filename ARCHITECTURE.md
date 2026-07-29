# Architecture

## What this package is

A thin, carefully worded shell around `certkit` and `exploit-counter`, aimed at a reader that is not
a person: an agent deciding whether a patch is safe to propose. The engineering here is mostly in
the *wording* and in the refusal paths, because the failure mode is not a crash — it is a model
reading `OUT_OF_SCOPE` as "no problems found" and merging.

## Module map

| Module | Role |
|---|---|
| `catalog.py` | One dependency-free definition per tool: name, model-facing description, argument schema. **Imports nothing outside the standard library.** |
| `adapters.py` | The catalogue in every shape other than MCP — OpenAI, Anthropic, JSON Schema, plain callables, LangChain on request — plus `call()`, which runs a tool with no server at all. |
| `tools.py` | The five tool implementations and the `Verdict` type. |
| `server.py` | MCP over stdio. Builds `Tool` objects from the catalogue; dispatch delegates to `adapters.call`. |

## Why the catalogue was extracted

The schemas and descriptions used to live in `server.py`, which cannot be imported without the `mcp`
package installed. That made them unreachable for anyone not on MCP, and it made "add another
integration" mean "copy the descriptions again" — which is how two integrations start disagreeing
about what a verdict means.

Now there is one source and several emitters, and `server.dispatch` runs the same code path as every
other adapter rather than a second copy of it.

## The descriptions are load-bearing

Each tool description states what its verdict does **not** establish. An adapter that dropped those
sentences while keeping the name and schema would look entirely correct and would be the most
dangerous file in the package.

So `check_descriptions_intact()` exists, and every adapter's output is tested against it —
including a test that the check itself can fail when handed stripped descriptions. No adapter maps
`OUT_OF_SCOPE` onto a boolean, a score, or a pass.

## The three verdicts

| Verdict | Means | Does **not** mean |
|---|---|---|
| `CERTIFIED` | No forbidden state is admitted over the declared box | Anything about states outside the box |
| `PROVEN_UNSOUND` | A concrete forbidden state exists, and here it is | A severity, a CVSS score, or reachability |
| `OUT_OF_SCOPE` | No verdict was reached | An approval, or a clean bill of health |

`decide_guard` deliberately carries **no** `over_acceptance` field and sets `"counted": false`.
Reporting a number there — even zero — would be a figure the analysis did not produce.

## Failure paths

Every tool converts hostile input into a refusal with a reason. `ArithmeticError` is caught
explicitly (an `Infinity` coefficient raises `OverflowError`; a `[1, 0]` rational raises
`ZeroDivisionError`), because a traceback out of an MCP server is a denial-of-service surface at
best. `verify_certificate` never returns `PROVEN_UNSOUND`: a certificate failing to verify says
nothing about whether the guard is sound, and conflating those is the exact error the three-verdict
design exists to prevent.
