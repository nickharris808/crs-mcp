"""The tools, reachable without MCP.

Two properties matter here, and only one of them is about shapes.

**Shape.** Each adapter emits the form its runtime expects, from one catalogue,
so adding an integration cannot fork the definitions.

**Meaning.** The descriptions carry the sentences that stop an agent reading
``OUT_OF_SCOPE`` as "no problems found". An adapter that dropped those while
keeping the name and the schema would look entirely correct and would be the most
dangerous file in the package. Every adapter is checked for them.
"""

from __future__ import annotations

import json

import pytest

from crs_mcp import adapters
from crs_mcp.catalog import CAVEATS, TOOL_SPECS, check_descriptions_intact, input_schema

SOUND = {
    "domain": [{"coeff": {"payload": -1}}, {"coeff": {"payload": 1}, "const": -255}],
    "guard": [{"coeff": {"payload": 1, "record_len": -1}, "const": 19}],
    "safety": [{"coeff": {"payload": 1, "record_len": -1}, "const": 3}],
    "box": {"payload": [0, 255], "record_len": [0, 255]},
}
UNSOUND = {**SOUND, "guard": [{"coeff": {"payload": 1, "record_len": -1}, "const": 1}]}


# --------------------------------------------------------------------------- #
# the catalogue is the single source
# --------------------------------------------------------------------------- #


def test_catalogue_imports_without_the_mcp_package():
    """The whole reason the catalogue was extracted from server.py.

    `crs_mcp.server` cannot be imported without `mcp` installed. If the schemas
    lived there, nobody off MCP could reach them.
    """
    import subprocess
    import sys

    probe = (
        "import sys\n"
        "sys.modules['mcp'] = None\n"  # any import of mcp now raises
        "from crs_mcp.catalog import TOOL_SPECS\n"
        "from crs_mcp.adapters import openai_tools, call\n"
        "assert len(openai_tools()) == len(TOOL_SPECS)\n"
        "print('ok')\n"
    )
    result = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ok" in result.stdout


def test_every_tool_has_a_name_description_and_object_schema():
    for spec in TOOL_SPECS:
        assert spec.name and spec.description
        assert spec.input_schema["type"] == "object"
        assert spec.input_schema["properties"]
        assert spec.input_schema["required"]


def test_the_server_builds_its_tools_from_the_catalogue():
    """If the server ever grows its own list again, this fails."""
    pytest.importorskip("mcp")
    from crs_mcp.server import TOOLS

    assert [t.name for t in TOOLS] == [s.name for s in TOOL_SPECS]
    for tool, spec in zip(TOOLS, TOOL_SPECS):
        assert tool.description == spec.description
        assert tool.inputSchema == spec.input_schema


# --------------------------------------------------------------------------- #
# shapes
# --------------------------------------------------------------------------- #


def test_openai_tools_have_the_function_calling_shape():
    for entry in adapters.openai_tools():
        assert entry["type"] == "function"
        fn = entry["function"]
        assert set(fn) == {"name", "description", "parameters"}
        assert fn["parameters"]["type"] == "object"


def test_anthropic_tools_use_input_schema_not_parameters():
    for entry in adapters.anthropic_tools():
        assert set(entry) == {"name", "description", "input_schema"}
        assert "parameters" not in entry


def test_json_schemas_are_standalone_documents():
    for name, schema in adapters.json_schemas().items():
        assert schema["$schema"].startswith("https://json-schema.org/")
        assert schema["title"] == name
        assert schema["type"] == "object"
        json.dumps(schema)  # must be serialisable as-is


def test_json_schemas_actually_validate_a_real_call():
    jsonschema = pytest.importorskip("jsonschema")
    schema = adapters.json_schemas()["certify_guard"]
    jsonschema.validate(SOUND, schema)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"guard": []}, schema)  # missing safety and box


def test_input_schema_raises_on_an_unknown_tool():
    """Not an empty schema: a permissive schema handed to a model is how a call
    ends up malformed with nothing noticing."""
    with pytest.raises(KeyError):
        input_schema("no_such_tool")


# --------------------------------------------------------------------------- #
# meaning: the caveats must survive every conversion
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("adapter", ["openai_tools", "anthropic_tools"])
def test_caveats_survive_the_adapter(adapter):
    rendered = adapters.rendered_descriptions(getattr(adapters, adapter))
    missing = check_descriptions_intact(rendered)
    assert not missing, f"{adapter} dropped the caveat for: {', '.join(missing)}"


def test_caveats_survive_into_plain_callables():
    rendered = {name: fn.__doc__ or "" for name, fn in adapters.python_callables().items()}
    assert not check_descriptions_intact(rendered)


def test_the_check_itself_can_fail():
    """A guard that cannot fail is not a guard."""
    stripped = dict.fromkeys(CAVEATS, "do a thing")
    assert set(check_descriptions_intact(stripped)) == {n for n, c in CAVEATS.items() if c}


# --------------------------------------------------------------------------- #
# running a tool without any framework at all
# --------------------------------------------------------------------------- #


def test_call_runs_a_tool_and_returns_json_ready_output():
    result = adapters.call("decide_guard", SOUND)
    assert result["verdict"] == "CERTIFIED"
    json.dumps(result)


def test_call_reports_an_unsound_guard_with_a_counterexample():
    result = adapters.call("decide_guard", UNSOUND)
    assert result["verdict"] == "PROVEN_UNSOUND"
    assert result["detail"]["counterexample"]


def test_decide_never_reports_a_count_it_did_not_make():
    result = adapters.call("decide_guard", UNSOUND)
    assert "over_acceptance" not in result["detail"]
    assert result["detail"]["counted"] is False


def test_call_raises_on_an_unknown_tool_rather_than_returning_a_result():
    with pytest.raises(adapters.UnknownTool):
        adapters.call("certify_everything", {})


def test_call_with_no_arguments_refuses_rather_than_assuming():
    result = adapters.call("certify_guard", {})
    assert result["verdict"] == "OUT_OF_SCOPE"
    assert result["detail"]["reason"] == "empty-safety"
    assert "nothing to certify" in result["summary"]


def test_out_of_scope_is_never_flattened_into_a_pass():
    """The verdict that must not be helpfully simplified by any adapter."""
    huge = {**SOUND, "box": {"payload": [0, 10**9], "record_len": [0, 10**9]}}
    for tool in ("certify_guard", "decide_guard"):
        result = adapters.call(tool, huge)
        assert result["verdict"] == "OUT_OF_SCOPE"
        assert result.get("ok") is not True
        assert "certified" not in json.dumps(result).lower().replace("out_of_scope", "")


def test_python_callables_take_keyword_arguments():
    fn = adapters.python_callables()["decide_guard"]
    assert fn(**SOUND)["verdict"] == "CERTIFIED"


def test_langchain_adapter_refuses_loudly_when_langchain_is_absent():
    """It must not half-work. Either the tools come back, or the reason does."""
    try:
        tools = adapters.langchain_tools()
    except ImportError as exc:
        assert "langchain-core" in str(exc)
        assert "openai_tools" in str(exc), "the refusal should name a working alternative"
    else:
        assert [t.name for t in tools] == [s.name for s in TOOL_SPECS]


# --------------------------------------------------------------------------- #
# notebook rendering
# --------------------------------------------------------------------------- #


def test_verdicts_render_in_a_notebook_without_losing_their_caveats():
    from crs_mcp.tools import certify_guard

    sound = certify_guard(SOUND["domain"], SOUND["guard"], SOUND["safety"], SOUND["box"])
    html = sound._repr_html_()
    assert "CERTIFIED" in html
    assert "outside it" in html, "a CERTIFIED badge must carry its own boundary"


def test_out_of_scope_is_not_rendered_as_a_pass():
    from crs_mcp.tools import certify_guard

    huge = certify_guard(
        SOUND["domain"],
        SOUND["guard"],
        SOUND["safety"],
        {"payload": [0, 10**9], "record_len": [0, 10**9]},
    )
    html = huge._repr_html_()
    assert "OUT_OF_SCOPE" in html
    assert "not an approval" in html.lower()
    assert "CERTIFIED" not in html


def test_a_hostile_summary_cannot_inject_markup():
    from crs_mcp.tools import Verdict

    html = Verdict("CERTIFIED", "<script>alert(1)</script>", {})._repr_html_()
    assert "<script>" not in html
