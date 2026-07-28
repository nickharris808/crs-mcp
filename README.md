# crs-mcp

[![ci](https://github.com/nickharris808/crs-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/nickharris808/crs-mcp/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/crs-mcp.svg)](https://pypi.org/project/crs-mcp/)
[![MCP](https://img.shields.io/badge/MCP-server-blueviolet.svg)](https://modelcontextprotocol.io)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**The agent that wrote your patch cannot mark its own homework.**

An MCP server that gives AI coding agents a verdict surface they cannot talk their way past. The
agent proposes a guard; this decides whether the guard is actually sound, and hands back a concrete
counterexample when it is not.

```
pip install "crs-mcp[server]"
```

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
    "counterexample": {"record_len": 1, "payload": 0},
    "hit_probability": 0.00776672,
    "expected_draws_to_hit": 128.75
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
| `certify_guard` | Is this guard sound over the declared box? |
| `count_exploitability` | Exactly how many states escape, and one example |
| `verify_certificate` | Re-check a `certkit` certificate without trusting its producer |
| `explain_refusal` | Turn a verdict into prose, including what it does *not* establish |

## How it decides, and the honest limit

Certification is by **exhaustive integer counting** over the box you declare. That is sound and
complete *for that box* — and says nothing outside it, which is why the box is a required argument
rather than something inferred from context.

Enumeration has a ceiling. Past roughly 500,000 points this returns `OUT_OF_SCOPE` rather than
stalling your agent for a minute. Deciding a full 32-bit domain needs a decision procedure that does
not enumerate — a solver-free elimination method with replayable certificates. **That procedure is
not part of this package.** This tier gives you real verdicts on the boxes it can enumerate, and an
honest refusal on the ones it cannot.

If you need verdicts over full machine-word domains, that is the commercial offering.

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
print(v.verdict)   # CERTIFIED
```

Atoms accept either plain integers (what a model will produce) or the `[numerator, denominator]`
pairs of the on-disk `certkit` format.

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

24 tests. `test_tools.py` covers verdict semantics; `test_server.py` does real `tools/list` and
`tools/call` round-trips through the registered handlers, because a server whose tool functions are
perfect but whose handlers are misregistered would pass every test in the other file.

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
