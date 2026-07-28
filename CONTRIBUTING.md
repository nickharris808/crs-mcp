# Contributing to crs-mcp

## The invariant: a refusal must never read as an approval

This is an agent-facing tool. An agent that sees no error will commit. So:

- `OUT_OF_SCOPE` must never be presented, formatted, or summarised as a pass.
- Every `OUT_OF_SCOPE` branch of `explain_refusal` must say, in words, that it is not an approval.
  There is a parametrised test asserting exactly this for every reason code — if you add a reason
  code, add it to that test.
- Tool *descriptions* are part of the safety surface, not documentation. They are read by a model,
  not a human. Changing them needs the same care as changing code.

## Two test layers, both required

`test_tools.py` covers verdict semantics against the pure functions. `test_server.py` does real
`tools/list` and `tools/call` round-trips through the registered MCP handlers.

Both matter: a server whose tool functions are perfect but whose handlers are misregistered passes
every test in the first file and is completely broken.

```bash
pip install -e ".[dev]"
pytest
```

## Keep the tool layer transport-independent

`tools.py` must not import from `mcp`. It is called from tests, and could be called from a CLI or a
web handler. `server.py` is the only place the protocol appears.

## Do not add a proof search

Certification here is by exhaustive counting, and the ceiling is deliberate. If you want to raise
it, raise `AGENT_EXACT_CAP` and measure the latency. Do not add a solver: the honest `OUT_OF_SCOPE`
is a feature, and a half-working search that sometimes returns a wrong `CERTIFIED` would be much
worse than a refusal.

## License

Contributions are accepted under Apache-2.0.
