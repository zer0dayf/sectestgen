"""Bounded tree-sitter source-to-sink ReachabilityEngine for Java (Spring).

Same contract and scope as the Python `BoundedReachabilityEngine`: find the
method enclosing the reported sink line, check whether it's a discovered
Spring route, then do a single-method taint pass — direct references to a
source parameter plus same-method propagation through local declarations
and assignments (`String cmd = "ping " + host; exec(cmd)`). No call is
followed into another method, and nothing is compiled or executed.

  - `reachable=True`  — a source reference reaches a sink argument or the
    sink call's receiver.
  - `reachable=False` — the sink's arguments are fully literal.
  - `reachable=None`  — not inside a known route, or an argument the
    bounded analysis can't resolve. The classifier turns the `entry_point`
    flag into POTENTIALLY_REACHABLE vs. INCONCLUSIVE.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from tree_sitter import Node

from sectestgen.adapters.java_ast import end_line, parse_file, start_line, text, walk
from sectestgen.core.adapters import ReachabilityEngine
from sectestgen.core.models import Finding, ReachabilityEvidence

_CALL_TYPES = ("method_invocation", "object_creation_expression")
# Anything that can carry a runtime value; a sink argument made only of
# other node types (string/number literals, operators) is fully literal.
_NON_LITERAL_TYPES = {
    "identifier",
    "field_access",
    "method_invocation",
    "object_creation_expression",
    "array_access",
    "lambda_expression",
    "method_reference",
    "this",
}


class JavaReachabilityEngine(ReachabilityEngine):
    def __init__(self, routes: Iterable[dict]) -> None:
        self._routes_by_file: dict[str, list[dict]] = {}
        for route in routes:
            if route["file_path"].endswith(".java"):
                self._routes_by_file.setdefault(route["file_path"], []).append(route)
        self._tree_cache: dict[str, Node | None] = {}

    def analyze(self, finding: Finding, target: Path) -> Finding:
        location = finding.location
        if location is None or location.line is None or not location.file_path:
            finding.reachability = ReachabilityEvidence(
                reachable=None, notes="finding has no source location"
            )
            return finding

        file_key = str(Path(location.file_path).resolve())
        route = self._find_enclosing_route(file_key, location.line)
        if route is None:
            finding.raw["entry_point"] = False
            finding.reachability = ReachabilityEvidence(
                reachable=None,
                notes="sink is not inside a discovered Spring route; cannot establish an entry point",
            )
            return finding

        finding.raw["entry_point"] = True
        finding.raw["route"] = f"{route['method']} {route['path']}"
        if route["sources"]:
            source = route["sources"][0]
            finding.user_input_source = (
                f"{route['method']} {route['path']} :: {source['kind']}:{source['binding']}"
            )

        method = self._method_node(file_key, route["start_line"])
        if method is None:
            finding.reachability = ReachabilityEvidence(
                reachable=None, notes="could not re-parse the enclosing route method"
            )
            return finding

        reachable, trail, note = _trace_taint(method, location.line, route)
        finding.reachability = ReachabilityEvidence(path=trail, reachable=reachable, notes=note)
        return finding

    def _find_enclosing_route(self, file_key: str, line: int) -> dict | None:
        for route in self._routes_by_file.get(file_key, []):
            if route["start_line"] <= line <= route["end_line"]:
                return route
        return None

    def _method_node(self, file_key: str, method_start: int) -> Node | None:
        if file_key not in self._tree_cache:
            self._tree_cache[file_key] = parse_file(Path(file_key))
        root = self._tree_cache[file_key]
        if root is None:
            return None
        for node in walk(root):
            if node.type == "method_declaration" and start_line(node) == method_start:
                return node
        return None


def _trace_taint(method: Node, sink_line: int, route: dict) -> tuple[bool | None, list[str], str]:
    name = text(method.child_by_field_name("name"))
    derived = {source["name"] for source in route["sources"]}

    # Single-method propagation in source order: a local declared or
    # assigned from a tainted expression becomes tainted too.
    for node in walk(method):
        if node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            if value is not None and _contains_taint(value, derived):
                derived.add(text(node.child_by_field_name("name")))
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            if left is not None and left.type == "identifier" and _contains_taint(
                node.child_by_field_name("right"), derived
            ):
                derived.add(text(left))
        elif node.type == "enhanced_for_statement":
            if _contains_taint(node.child_by_field_name("value"), derived):
                derived.add(text(node.child_by_field_name("name")))

    sink_calls = _calls_at_line(method, sink_line)
    if not sink_calls:
        return None, [], f"no call expression found on line {sink_line} inside {name}()"

    arg_exprs = [
        arg
        for call in sink_calls
        for arg in (call.child_by_field_name("arguments").named_children if call.child_by_field_name("arguments") else [])
    ]
    receivers = [
        call.child_by_field_name("object")
        for call in sink_calls
        if call.type == "method_invocation" and call.child_by_field_name("object") is not None
    ]
    source_desc = ", ".join(f"{s['kind']}:{s['binding']}" for s in route["sources"]) or "no declared source"

    if any(_contains_taint(expr, derived) for expr in arg_exprs + receivers):
        return True, [source_desc, f"{name}() line {sink_line}"], "source reference reaches the sink's arguments"

    if arg_exprs and all(_is_fully_literal(expr) for expr in arg_exprs):
        return False, [], "sink arguments are fully static/literal; no source reference found"

    if not arg_exprs and not receivers:
        return False, [], "sink call takes no arguments and has no receiver object to taint"

    return (
        None,
        [],
        "sink argument references a value the bounded analysis could not resolve "
        "(e.g. a field or the result of an unanalyzed call)",
    )


def _calls_at_line(method: Node, line: int) -> list[Node]:
    calls = [n for n in walk(method) if n.type in _CALL_TYPES]
    starting = [c for c in calls if start_line(c) == line]
    if starting:
        return starting
    # Semgrep reports the match's end line; a call spanning several lines
    # doesn't start there, so fall back to the innermost call covering it.
    covering = [c for c in calls if start_line(c) <= line <= end_line(c)]
    if not covering:
        return []
    return [min(covering, key=lambda c: (end_line(c) - start_line(c), c.end_byte - c.start_byte))]


def _contains_taint(expr: Node | None, names: set[str]) -> bool:
    if expr is None:
        return False
    for node in walk(expr):
        if node.type != "identifier" or text(node) not in names:
            continue
        parent = node.parent
        # `obj.name` / `obj.name()` refer to a member, not the local `name`.
        if parent is not None and parent.type == "field_access" and parent.child_by_field_name("field") == node:
            continue
        if parent is not None and parent.type == "method_invocation" and parent.child_by_field_name("name") == node:
            continue
        return True
    return False


def _is_fully_literal(expr: Node) -> bool:
    return not any(node.type in _NON_LITERAL_TYPES for node in walk(expr))
