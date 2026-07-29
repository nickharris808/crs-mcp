# Troubleshooting

## `the 'mcp' package is required to run the server`

```bash
pip install "crs-mcp[server]"
```

Only the *server* needs it. The tools themselves do not: `crs_mcp.adapters.call("decide_guard", …)`
and the OpenAI/Anthropic schema emitters work with no extra dependency at all.

## My agent read `OUT_OF_SCOPE` as "no problems found"

That is the failure this package is shaped against, and if it still happened, the caveat probably
did not reach the model. Check that your integration passes the **description** and not just the
name and schema:

```python
from crs_mcp import openai_tools
openai_tools()[0]["function"]["description"]   # must contain "NOT an approval"
```

`crs_mcp.catalog.check_descriptions_intact()` takes `{name: description}` and returns the tools whose
caveat went missing. If your framework truncates descriptions, that is worth knowing before you ship.

## `OUT_OF_SCOPE` on every call

Usually the box. An unbounded or enormous box cannot be enumerated, and the verdict detail says
which: `enumeration-too-large` with `enumerated_points` and `exact_cap`, or `empty-safety` when the
`safety` list is missing. Send a box, and send one that is finite.

## `decide_guard` gives no `over_acceptance`

By design. Nothing was counted — it stopped at the first escaping state — so reporting a number,
even zero, would be a figure the analysis did not produce. `"counted": false` is in the detail. Use
`certify_guard` when you need the magnitude.

## `verify_certificate` never says `PROVEN_UNSOUND`

Also by design. A certificate failing to verify says nothing about whether the guard is sound; it
says this certificate did not establish it. The result carries `certificate_verdict` and
`binding_verified` instead. Conflating those two is the error the three-verdict design exists to
prevent.

## Claude Desktop / Cursor does not list the tools

Check the server actually starts:

```bash
crs-mcp </dev/null    # should exit cleanly, not traceback
```

Then check the config points at the installed entry point rather than a source path, and that the
Python it names is the environment you installed into.

## A tool call raised instead of returning a verdict

It should not — hostile input is a refusal with a reason, including zero denominators and infinite
coefficients. If you have an input that produces a traceback, that is a bug worth reporting; see
`SECURITY.md`.

## LangChain import error

`langchain_tools()` raises `ImportError` naming `langchain-core` if it is absent. That is
deliberate: LangChain is not a dependency of this package, and half-working integrations are worse
than absent ones. `openai_tools()`, `anthropic_tools()` and `call()` need nothing extra.
