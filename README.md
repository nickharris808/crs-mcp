# crs-mcp

[![ci](https://github.com/nickharris808/crs-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/nickharris808/crs-mcp/actions/workflows/ci.yml)
[![MCP](https://img.shields.io/badge/MCP-server-blueviolet.svg)](https://modelcontextprotocol.io)
[![status](https://img.shields.io/badge/status-pre--release-orange.svg)](#install)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**The agent that wrote your patch cannot mark its own homework.**

> **Try it now, no install:** [open the browser demo](https://huggingface.co/spaces/nickh007/certkit-demo) and press **Load a forgery** — the checker refuses it, client-side.

An MCP server that gives AI coding agents a verdict surface they cannot talk their way past. The
agent proposes a guard; this decides whether the guard is actually sound, and hands back a concrete
counterexample when it is not.

<a id="install"></a>
```bash
pip install "crs-mcp@git+https://github.com/nickharris808/crs-mcp@main"
```

> **Pre-release.** The PyPI name is reserved and publication is imminent; until then the line above
> is the working install. It is tested in CI on Linux, macOS, and Windows.

## 30-second quickstart

Add it to Claude Desktop (`claude_desktop_config.json`) or Cursor:

```json
{
  "mcpServers": {
    "crs": {
      "command": "crs-mcp"
    }
  }
}
```

Then ask your agent: *"I added a bounds check `1 + payload <= record_len` before this read. Certify
it against `3 + payload <= record_len`."*

```json
{
  "verdict": "PROVEN_UNSOUND",
  "summary": "The guard admits 509 state(s) the safety property forbids (out of 65,536). Example: {'record_len': 1, 'payload': 0}.",
  "detail": {
    "over_acceptance": 509,
    "box_volume": 65536,
    "counterexample": {"record_len": 1, "payload": 0},
    "hit_probability": 0.0077667236328125,
    "expected_draws_to_hit": 128.75442043222003
  }
}
```

That is a real counterexample: at `payload=0, record_len=1` the guard passes and the safety property
does not hold. The agent cannot argue with it, and neither can you.

## The three verdicts

| Verdict | Meaning |
|---|---|
| `CERTIFIED` | No forbidden state is admitted, over the whole declared box. |
| `PROVEN_UNSOUND` | At least one is — with a concrete counterexample. |
| `OUT_OF_SCOPE` | The box is too large to decide by enumeration. **No verdict was reached.** |

`OUT_OF_SCOPE` is the important one. It is not a failure and it is emphatically **not a pass**. An
agent will read "no errors" as "approved" and commit; the tool descriptions are written to fight
that reading, and `explain_refusal` returns prose that says *"Do not treat this as approval"* in so
many words. A tool that only ever returns green is worse than no tool.

## Tools

| Tool | Purpose |
|---|---|
| `certify_guard` | Is this guard sound over the declared box, and by how much? |
| `decide_guard` | The same verdict, without counting — far faster on unsound guards |
| `count_exploitability` | Exactly how many states escape, and one example |
| `verify_certificate` | Re-check a `certkit` certificate without trusting its producer |
| `explain_refusal` | Turn a verdict into prose, including what it does *not* establish |

`verify_certificate` additionally returns `certificate_verdict`, which is `certkit`'s own
`ACCEPTED` / `REFUSED` / `UNVERIFIED`. A certificate that **fails** to check is reported as
`OUT_OF_SCOPE`, never as `PROVEN_UNSOUND`: a bad proof is the absence of evidence, not evidence of
unsoundness. Only counting states can prove a guard unsound, which is what `certify_guard` does.

## `decide_guard`: the same answer, sooner

Most of the time an agent is asking *is this safe?*, not *how unsafe?*. `decide_guard` stops at the
first escaping state instead of counting the whole region. Measured on an unsound guard:

| Box | `certify_guard` (counts) | `decide_guard` (first witness) | Factor |
|---|---:|---:|---:|
| `payload=0:255, record_len=0:255` | 0.15 ms | 0.0131 ms | 11x |
| `payload=0:4095, record_len=0:4095` | 2.29 ms | 0.0134 ms | 171x |
| `payload=0:65535, record_len=0:65535` | 36.72 ms | 0.0129 ms | 2,843x |

Regenerate with `python benchmarks/decide_vs_count.py` in the `exploit-counter` repository, which is
where the counting happens. The gap grows with the box because counting enumerates the whole
violating region and deciding stops at the first escaping state.

Identical verdicts — a test asserts they agree on 150 random specs. Sound guards cost the same
either way, because the full enumeration is genuinely required to establish soundness.

The result carries **no** `over_acceptance` field. Nothing was counted, so reporting a number there,
even zero, would be a figure the analysis did not produce.

## How it decides, and the honest limit

Certification is by **exhaustive integer counting** over the box you declare. That is sound and
complete *for that box* — and says nothing outside it, which is why the box is a required argument
rather than something inferred from context.

The counter enumerates every variable **except the widest**, which it solves in closed form. So the
cost is the product of the *other* ranges, and the ceiling applies to that product — not to the box
volume. The limit is **500,000 enumerated points**. Measured on this machine:

| Box | Volume | Enumerated | Verdict | Time |
|---|---|---|---|---|
| `payload=0:255, record_len=0:255` | 65,536 | 256 | CERTIFIED | 0 ms |
| `payload=0:65535, record_len=0:65535` | 4,294,967,296 | 65,536 | CERTIFIED | 30 ms |
| `payload=0:499999, record_len=0:10^9` | 5.0 × 10^14 | 500,000 | CERTIFIED | 227 ms |
| `payload=0:500000, record_len=0:10^9` | 5.0 × 10^14 | 500,001 | `OUT_OF_SCOPE` | 0 ms |
| three variables, `0:699` each | 343,000,000 | 490,000 | CERTIFIED | 212 ms |
| three variables, `0:800` each | 513,922,401 | 641,601 | `OUT_OF_SCOPE` | 0 ms |

The millisecond column is from one machine and will differ on yours; `python benchmarks/ceiling.py` will regenerate this table on yours. The volumes, the enumerated counts and the verdicts are exact and machine-independent.

Every decision inside the cap lands in under a quarter second, so an agent call does not stall. That
was not true before: profiling the worst case showed ~70% of the time inside Python's `Fraction`
type, so `exploit-counter` now runs an integer-only inner loop when every coefficient is an integer
(which every bounds relation is). Integers are a subset of the rationals, so this is the same
arithmetic — not a faster approximation — and `test_integer_and_rational_paths_agree` checks the two
implementations against each other. Measured effect on the row above: **3,309 ms → 227 ms**.

Reproduce with `python benchmarks/ceiling.py` — that script generates exactly this table, and the
numbers above are its real output. Timings are machine-dependent; the verdicts and enumerated counts
are not.

Two consequences worth stating plainly, because the earlier version of this README got both wrong:

- **A two-variable box spanning the full 2^32 is decided**, in under half a second. This README
  previously claimed it would be refused.
- **Narrowing the widest variable does not help.** It is already free. If you get `OUT_OF_SCOPE`,
  narrow one of the others; the refusal message names which variable is the free one.

Deciding a full 32-bit domain in *three or more* variables needs a decision procedure that does not
enumerate — a solver-free elimination method with replayable certificates. **That procedure is not
part of this package.** This tier gives you real verdicts on the boxes it can enumerate, and an
honest refusal on the ones it cannot.

If you need verdicts over full machine-word domains, that is the commercial offering.

## What the tool refuses to answer

A verdict is only worth having if the question could have come out the other way. These are rejected
with `OUT_OF_SCOPE` rather than answered:

| Input | Why it is refused |
|---|---|
| A box holding one point, e.g. `{"p": [0,0], "r": [0,0]}` | "No escapes found" is true there no matter how unsound the guard is. |
| An inverted range, e.g. `{"p": [10,2]}` | The box is empty, so a zero count is vacuous. |
| An atom naming a variable the box does not declare | That variable is unbounded; it used to raise `KeyError`. |
| A guard or safety atom that fails to parse | Malformed input is a refusal with a reason, never a traceback. |

Each refusal names the offending variable and says what to change.

## Use from Python

The tool layer is transport-independent, so you can call it without MCP at all:

```python
from crs_mcp import certify_guard

v = certify_guard(
    domain=[{"coeff": {"payload": -1}}, {"coeff": {"payload": 1}, "const": -255}],
    guard=[{"coeff": {"payload": 1, "record_len": -1}, "const": 19}],
    safety=[{"coeff": {"payload": 1, "record_len": -1}, "const": 3}],
    box={"payload": [0, 255], "record_len": [0, 255]},
)
print(v.verdict)  # CERTIFIED
```

Atoms accept either plain integers (what a model will produce) or the `[numerator, denominator]`
pairs of the on-disk `certkit` format.

## Not on MCP? The tools work anyway

MCP is the transport this package was built around, but the tools are just functions that take JSON
and return JSON. Nothing about them requires a framework — or even a server:

```python
from crs_mcp import call, openai_tools, anthropic_tools, json_schemas

call("decide_guard", {"guard": [...], "safety": [...], "box": {...}})   # run one, no server
openai_tools()       # OpenAI function-calling schema, for `tools=`
anthropic_tools()    # Anthropic tool-use schema (input_schema, not parameters)
json_schemas()       # standalone JSON Schema documents, one per tool
```

```bash
python -m crs_mcp.adapters anthropic > tools.json    # paste into an agent config
```

LangChain users get `crs_mcp.adapters.langchain_tools()`. LangChain is **not** a dependency of this
package; the function imports it on call and raises with an install instruction if it is missing,
rather than silently returning a partial integration.

All of these are generated from one catalogue (`crs_mcp.catalog`), which imports nothing outside the
standard library — the schemas used to live inside the MCP server module and were therefore
unreachable unless you had `mcp` installed.

**The descriptions are load-bearing.** Each one states what a verdict does *not* establish, because
an agent that reads `OUT_OF_SCOPE` as "no problems found" will merge unsafe code. An adapter that
dropped those sentences while keeping the name and schema would look perfectly correct, so
`check_descriptions_intact()` exists and every adapter's output is tested against it. No adapter
maps `OUT_OF_SCOPE` onto a boolean, a score, or a pass.

## Supported MCP versions

Verified against **mcp 1.9.0 through 1.29.0**, and pinned to `>=1.9.0,<2.0.0`.

`mcp` 2.0.0 changed the server decorator API (`Server.list_tools` no longer exists) and is not yet
supported — CI caught this the day 2.0.0 shipped. 2.x support is tracked as future work rather than
claimed here.

## Scope

- **Linear integer arithmetic only.** Nonlinear terms, heap shape, and aliasing are out of the
  fragment. The tool will not pretend otherwise.
- **The count is triggerability, not severity.** It bounds reachability of a forbidden state under
  uniform sampling. It is not CVSS and not a weaponisability claim.
- **`CERTIFIED` is scoped to the box.** It is a real proof over a real domain, and it is silent
  about everything outside that domain.

## Related

- [`certkit`](https://github.com/nickharris808/certkit) — the certificate format and the independent checker
- [`exploit-counter`](https://github.com/nickharris808/exploit-counter) — the counting engine underneath

## Tests

```bash
pip install -e ".[dev]"
pytest
```

231 tests. `test_tools.py` covers verdict semantics; `test_server.py` does real `tools/list` and
`tools/call` round-trips through the registered handlers, because a server whose tool functions are
perfect but whose handlers are misregistered would pass every test in the other file.

`test_adversarial.py` holds the ones that matter most. Its oracle is a single sentence — *no input
may produce a confident-looking answer that is wrong* — and it attacks `CERTIFIED` specifically,
because that is the word an agent reads as "approved, commit it". It also carries the
**differential** test: `certkit` and `exploit-counter` are independent implementations of the same
question (rational refutation arithmetic vs. integer enumeration), and both are cross-checked against
brute force on every input. A disagreement between them is a soundness bug in whichever is wrong.

## Documentation

| | |
|---|---|
| [`SCOPE.md`](SCOPE.md) | what each verdict establishes, and what it does not |
| [`benchmarks/ceiling.py`](benchmarks/ceiling.py) | regenerates the decision-ceiling table above |
| [certkit's TUTORIAL](https://github.com/nickharris808/certkit/blob/main/TUTORIAL.md) | end-to-end worked example |
| [certkit's TROUBLESHOOTING](https://github.com/nickharris808/certkit/blob/main/TROUBLESHOOTING.md) | every error string in the toolkit |

## The rest of the toolkit

| | |
|---|---|
| **[certkit](https://github.com/nickharris808/certkit)** | the certificate format and the independent checker |
| **[exploit-counter](https://github.com/nickharris808/exploit-counter)** | if a guard is unsound, exactly how many states escape |
| **[crs-mcp](https://github.com/nickharris808/crs-mcp)** | the verdict surface AI coding agents call, over MCP |
| **[soundnessbench](https://github.com/nickharris808/soundnessbench)** | the benchmark that grades all of the above |
| **[certkit-action](https://github.com/nickharris808/certkit-action)** | run the check in your CI |
| **[pytest-mutation-verified](https://github.com/nickharris808/pytest-mutation-verified)** | prove your regression test can actually fail |
| **[cve-proof-corpus](https://huggingface.co/datasets/nickh007/cve-proof-corpus)** | six real CVEs with machine-checkable proofs |
| **[Try it in your browser](https://huggingface.co/spaces/nickh007/certkit-demo)** | no install; watch a forgery get refused |

---

## The closed core

These packages are the *checking* half. They deliberately contain no proof search, which is what keeps
them small enough to audit — and it means something upstream has to produce certificates.

For obligations over full machine-word domains, enumeration does not scale and a decision procedure
that does not enumerate is required: solver-free elimination emitting replayable certificates. That
engine, the repair synthesiser that derives a minimal guard from a refutation, and the evolutionary
search that drives them are **not** in this repository and are available commercially.

The split is deliberate and permanent. **The checker is free and always will be** — a certificate you
cannot independently verify is worth nothing, so charging for verification would defeat the format.
What costs money is *producing* certificates at scale.

## License

Apache-2.0 for the client and tool layer.

---

Part of **[certified discovery](https://nickharris808.github.io/certified-discovery/)** — ten artifacts built on one asymmetry: checking a proof is cheap and auditable, so the thing that produced it does not have to be trusted.
