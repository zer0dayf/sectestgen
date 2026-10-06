"""FastAPI FrameworkAdapter: bounded, AST-only route/user-input discovery.

This is a heuristic, not a FastAPI implementation. It matches any
`@<obj>.<verb>("path", ...)` decorator (so both `@app.get` and
`@router.post` are found without resolving what `<obj>` actually is) and
treats a locally-defined `BaseModel` subclass used as a parameter as a body
source. No code is imported or executed.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterable

from sectestgen.core.adapters import FrameworkAdapter

_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}
_SOURCE_MARKERS = {"Query": "query", "Path": "path", "Cookie": "cookie", "Header": "header"}
_PATH_PARAM_RE = re.compile(r"{([^:}]+)(?::[^}]+)?}")
_SKIP_PARAM_NAMES = {"self", "request"}


class FastAPIFrameworkAdapter(FrameworkAdapter):
    def discover_routes(self, target: Path) -> Iterable[dict]:
        for py_file in sorted(target.rglob("*.py")):
            try:
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(py_file))
            except (SyntaxError, UnicodeDecodeError, OSError):
                continue

            models = _collect_basemodel_fields(tree)

            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for decorator in node.decorator_list:
                    route = _match_route_decorator(decorator)
                    if route is None:
                        continue
                    method, route_path = route
                    path_params = set(_PATH_PARAM_RE.findall(route_path))
                    sources = _collect_sources(node, path_params, models)
                    yield {
                        "method": method.upper(),
                        "path": route_path,
                        "function": node.name,
                        "file_path": str(py_file.resolve()),
                        "start_line": node.lineno,
                        "end_line": getattr(node, "end_lineno", node.lineno),
                        "sources": sources,
                    }


def _match_route_decorator(decorator: ast.expr) -> tuple[str, str] | None:
    if not isinstance(decorator, ast.Call):
        return None
    func = decorator.func
    if not isinstance(func, ast.Attribute) or func.attr not in _HTTP_METHODS:
        return None
    if not decorator.args:
        return None
    first_arg = decorator.args[0]
    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
        return func.attr, first_arg.value
    return None


def _collect_basemodel_fields(tree: ast.Module) -> dict[str, list[str]]:
    models: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        base_names = [b.id for b in node.bases if isinstance(b, ast.Name)]
        if "BaseModel" not in base_names:
            continue
        fields = [
            stmt.target.id
            for stmt in node.body
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)
        ]
        models[node.name] = fields
    return models


def _collect_sources(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    path_params: set[str],
    models: dict[str, list[str]],
) -> list[dict]:
    sources: list[dict] = []
    args = func.args.args
    defaults = func.args.defaults
    offset = len(args) - len(defaults)
    default_by_name = {args[offset + i].arg: d for i, d in enumerate(defaults)}

    for arg in args:
        name = arg.arg
        if name in _SKIP_PARAM_NAMES:
            continue
        if name in path_params:
            sources.append({"name": name, "kind": "path", "field": None})
            continue

        default = default_by_name.get(name)
        marker = _marker_kind(default)
        if marker is not None:
            sources.append({"name": name, "kind": marker, "field": None})
            continue

        annotation_name = _annotation_type_name(arg.annotation)
        if annotation_name in models:
            fields = models[annotation_name]
            if fields:
                for field in fields:
                    sources.append({"name": name, "kind": "body", "field": field})
            else:
                sources.append({"name": name, "kind": "body", "field": None})
            continue

        if default is None and annotation_name not in (None, "Request", "Depends"):
            # Bare primitive param with no explicit marker: FastAPI treats it
            # as a query parameter by default when it isn't a path param.
            sources.append({"name": name, "kind": "query", "field": None})

    return sources


def _marker_kind(default: ast.expr | None) -> str | None:
    if not isinstance(default, ast.Call):
        return None
    func = default.func
    if isinstance(func, ast.Name):
        name = func.id
    elif isinstance(func, ast.Attribute):
        name = func.attr
    else:
        return None
    return _SOURCE_MARKERS.get(name)


def _annotation_type_name(annotation: ast.expr | None) -> str | None:
    if annotation is None:
        return None
    if isinstance(annotation, ast.Name):
        return annotation.id
    if isinstance(annotation, ast.Attribute):
        return annotation.attr
    if isinstance(annotation, ast.Subscript):
        return _annotation_type_name(annotation.value)
    if isinstance(annotation, ast.BinOp):  # e.g. `str | None`
        return _annotation_type_name(annotation.left)
    return None
