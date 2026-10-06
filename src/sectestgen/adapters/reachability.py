"""Bounded AST-based source-to-sink ReachabilityEngine.

Scope (per proposal): locate the function enclosing the reported sink line,
check whether that function is a discovered FastAPI route, then do a
single-function taint pass combining direct name/attribute references and
simple same-function variable propagation (`x = payload.expression; eval(x)`).

This never claims a sink is safe just because the bounded analysis can't
resolve it. Three outcomes:
  - `reachable=True`  — a source reference reaches the sink's arguments.
  - `reachable=False` — the sink's arguments are fully static/literal.
  - `reachable=None`  — not inside a known route (no entry point), or the
    sink's arguments reference something the bounded analysis can't
    resolve (unsupported dynamic construct). The classifier turns the
    `entry_point` flag into POTENTIALLY_REACHABLE vs. INCONCLUSIVE.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable

from sectestgen.core.adapters import ReachabilityEngine
from sectestgen.core.models import Finding, ReachabilityEvidence

FuncNode = ast.FunctionDef | ast.AsyncFunctionDef


class BoundedReachabilityEngine(ReachabilityEngine):
    def __init__(self, routes: Iterable[dict]) -> None:
        self._routes_by_file: dict[str, list[dict]] = {}
        for route in routes:
            self._routes_by_file.setdefault(route["file_path"], []).append(route)
        self._tree_cache: dict[str, ast.Module] = {}

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
                notes="sink is not inside a discovered FastAPI route; cannot establish an entry point",
            )
            return finding

        finding.raw["entry_point"] = True
        finding.raw["route"] = f"{route['method']} {route['path']}"
        if route["sources"]:
            source = route["sources"][0]
            field = f".{source['field']}" if source.get("field") else ""
            finding.user_input_source = (
                f"{route['method']} {route['path']} :: {source['kind']}:{source['name']}{field}"
            )

        func_node = self._function_node(file_key, route["function"], route["start_line"])
        if func_node is None:
            finding.reachability = ReachabilityEvidence(
                reachable=None, notes="could not re-parse the enclosing route function"
            )
            return finding

        names, attrs = _tainted_refs(route["sources"])
        reachable, trail, note = _trace_taint(func_node, location.line, names, attrs, route)
        finding.reachability = ReachabilityEvidence(path=trail, reachable=reachable, notes=note)
        return finding

    def _find_enclosing_route(self, file_key: str, line: int) -> dict | None:
        for route in self._routes_by_file.get(file_key, []):
            if route["start_line"] <= line <= route["end_line"]:
                return route
        return None

    def _function_node(self, file_key: str, function_name: str, start_line: int) -> FuncNode | None:
        tree = self._tree_cache.get(file_key)
        if tree is None:
            try:
                tree = ast.parse(Path(file_key).read_text(encoding="utf-8"), filename=file_key)
            except (SyntaxError, UnicodeDecodeError, OSError):
                return None
            self._tree_cache[file_key] = tree

        for node in ast.walk(tree):
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == function_name
                and node.lineno == start_line
            ):
                return node
        return None


def _tainted_refs(sources: list[dict]) -> tuple[set[str], set[tuple[str, str]]]:
    names: set[str] = set()
    attrs: set[tuple[str, str]] = set()
    for source in sources:
        if source["kind"] == "body" and source.get("field"):
            attrs.add((source["name"], source["field"]))
        else:
            names.add(source["name"])
    return names, attrs


def _trace_taint(
    func: FuncNode,
    sink_line: int,
    names: set[str],
    attrs: set[tuple[str, str]],
    route: dict,
) -> tuple[bool | None, list[str], str]:
    derived = set(names)

    # Single-hop propagation: `x = <expr referencing a source>` makes `x`
    # tainted too. Intentionally shallow (no cross-function resolution).
    for stmt in ast.walk(func):
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
            and _expr_contains_taint(stmt.value, derived, attrs)
        ):
            derived.add(stmt.targets[0].id)

    sink_calls = [
        node for node in ast.walk(func) if isinstance(node, ast.Call) and node.lineno == sink_line
    ]
    if not sink_calls:
        return (
            None,
            [],
            f"no call expression found on line {sink_line} inside {func.name}()",
        )

    arg_exprs = [arg for call in sink_calls for arg in (*call.args, *(kw.value for kw in call.keywords))]
    # A method-call sink (`target.read_text()`) can be tainted through its
    # receiver object rather than through any argument.
    receiver_exprs = [
        call.func.value for call in sink_calls if isinstance(call.func, ast.Attribute)
    ]
    source_desc = ", ".join(
        f"{kind}:{name}" for name, kind in _describe_sources(route["sources"])
    ) or "no declared source"

    if any(_expr_contains_taint(expr, derived, attrs) for expr in arg_exprs + receiver_exprs):
        trail = [source_desc, f"{func.name}() line {sink_line}"]
        return True, trail, "source reference reaches the sink's arguments"

    if arg_exprs and all(_expr_is_fully_literal(expr) for expr in arg_exprs):
        return (
            False,
            [],
            "sink arguments are fully static/literal; no source reference found",
        )

    if not arg_exprs and not receiver_exprs:
        return (
            False,
            [],
            "sink call takes no arguments and has no receiver object to taint",
        )

    return (
        None,
        [],
        "sink argument references a value the bounded analysis could not resolve "
        "(e.g. forwarded through an unanalyzed call or container)",
    )


def _describe_sources(sources: list[dict]) -> list[tuple[str, str]]:
    return [(source["name"], source["kind"]) for source in sources]


def _expr_contains_taint(expr: ast.AST, names: set[str], attrs: set[tuple[str, str]]) -> bool:
    for node in ast.walk(expr):
        if isinstance(node, ast.Name) and node.id in names:
            return True
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id in names or (node.value.id, node.attr) in attrs:
                return True
    return False


def _expr_is_fully_literal(expr: ast.AST) -> bool:
    for node in ast.walk(expr):
        if isinstance(node, (ast.Name, ast.Attribute, ast.Call)):
            return False
    return True
