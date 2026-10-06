"""Shared CWE -> sink-type mapping used by every static analyzer adapter.

Both Bandit (numeric `issue_cwe.id`) and Semgrep (`metadata.cwe` strings)
report a CWE for most findings. Centralizing the mapping here means a sink
category is only ever defined once, regardless of which tool reported it.
"""

from __future__ import annotations

import re

# Limited to the sink categories in the project proposal/fixture. Extend as
# new sink categories are added; never guess a sink type from a rule name.
_CWE_SINK_TYPES: dict[int, str] = {
    78: "command_execution",
    77: "command_execution",
    95: "dynamic_evaluation",
    94: "dynamic_evaluation",
    502: "unsafe_deserialization",
    22: "path_traversal",
    89: "sql_injection",
}

_CWE_NUM_RE = re.compile(r"CWE-(\d+)")


def sink_type_for_cwe_id(cwe_id: int | None) -> str | None:
    """Bandit gives a numeric CWE id directly (`issue_cwe.id`)."""
    if cwe_id is None:
        return None
    return _CWE_SINK_TYPES.get(cwe_id)


def sink_type_for_cwe_strings(cwe_strings: list[str] | None) -> str | None:
    """Semgrep gives CWE as free-text strings like "CWE-95: Improper ..."."""
    if not cwe_strings:
        return None
    for raw in cwe_strings:
        match = _CWE_NUM_RE.search(raw)
        if match:
            sink = _CWE_SINK_TYPES.get(int(match.group(1)))
            if sink:
                return sink
    return None
