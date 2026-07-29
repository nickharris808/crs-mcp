"""crs-mcp -- proof-gated code review for AI agents, over MCP.

The agent that wrote your patch cannot mark its own homework.
"""

from .adapters import anthropic_tools, call, json_schemas, openai_tools
from .catalog import TOOL_SPECS, tool_names
from .tools import (
    CERTIFIED,
    OUT_OF_SCOPE,
    PROVEN_UNSOUND,
    Verdict,
    certify_guard,
    count_exploitability,
    explain_refusal,
    verify_certificate,
)

__version__ = "0.4.1"

__all__ = [
    "openai_tools",
    "anthropic_tools",
    "json_schemas",
    "call",
    "tool_names",
    "TOOL_SPECS",
    "certify_guard",
    "count_exploitability",
    "verify_certificate",
    "explain_refusal",
    "Verdict",
    "CERTIFIED",
    "PROVEN_UNSOUND",
    "OUT_OF_SCOPE",
    "__version__",
]
