"""crs-mcp -- proof-gated code review for AI agents, over MCP.

The agent that wrote your patch cannot mark its own homework.
"""

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

__version__ = "0.3.0"

__all__ = [
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
