"""Spring (Spring MVC / Spring Boot) FrameworkAdapter: tree-sitter-only
route and user-input source discovery for Java.

Like the FastAPI adapter this is a bounded heuristic, not a Spring
implementation: classes annotated `@RestController`/`@Controller` (or
carrying a class-level `@RequestMapping`) contribute one route per handler
path, with the class-level prefix joined on. Nothing is compiled or run.

Parameter -> source kind:
  @PathVariable/@MatrixVariable -> path, @RequestParam/@ModelAttribute ->
  query, @RequestHeader -> header, @CookieValue -> cookie,
  @RequestBody/@RequestPart -> body. A raw request object
  (HttpServletRequest, WebRequest, ...) -> request. An unannotated
  parameter is bound from the query string by Spring, so it's a query
  source unless it's a known framework-injected type (Model, Principal, ...).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from sectestgen.adapters.java_ast import (
    annotation_element,
    annotation_strings,
    annotations,
    end_line,
    parse_file,
    start_line,
    text,
    walk,
)
from sectestgen.core.adapters import FrameworkAdapter

_MAPPING_METHODS = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
    "RequestMapping": None,  # method comes from `method = RequestMethod.X`
}
_CONTROLLER_ANNOTATIONS = {"RestController", "Controller"}
_PARAM_SOURCES = {
    "PathVariable": "path",
    "MatrixVariable": "path",
    "RequestParam": "query",
    "ModelAttribute": "query",
    "RequestHeader": "header",
    "CookieValue": "cookie",
    "RequestBody": "body",
    "RequestPart": "body",
}
_REQUEST_TYPES = {
    "HttpServletRequest",
    "ServletRequest",
    "WebRequest",
    "NativeWebRequest",
    "ServerHttpRequest",
    "ServerWebExchange",
    "HttpEntity",
    "RequestEntity",
}
# Injected by Spring itself, not bound from request data.
_FRAMEWORK_TYPES = {
    "HttpServletResponse",
    "ServletResponse",
    "HttpSession",
    "Model",
    "ModelMap",
    "BindingResult",
    "Errors",
    "Principal",
    "Authentication",
    "Locale",
    "TimeZone",
    "RedirectAttributes",
    "UriComponentsBuilder",
    "SessionStatus",
}
_REQUEST_METHOD_RE = re.compile(r"RequestMethod\.(\w+)")
_GENERIC_RE = re.compile(r"<.*>")


class SpringFrameworkAdapter(FrameworkAdapter):
    def discover_routes(self, target: Path) -> Iterable[dict]:
        target = Path(target)
        files = [target] if target.is_file() else sorted(target.rglob("*.java"))
        for java_file in files:
            if java_file.suffix != ".java":
                continue
            root = parse_file(java_file)
            if root is None:
                continue
            file_path = str(java_file.resolve())
            for node in walk(root):
                if node.type == "class_declaration":
                    yield from _class_routes(node, file_path)


def _class_routes(cls, file_path: str) -> Iterable[dict]:
    class_annotations = dict(annotations(cls))
    has_class_mapping = "RequestMapping" in class_annotations
    if not (_CONTROLLER_ANNOTATIONS & class_annotations.keys() or has_class_mapping):
        return
    prefixes = annotation_strings(class_annotations.get("RequestMapping")) or [""]

    body = cls.child_by_field_name("body")
    if body is None:
        return
    for method in body.named_children:
        if method.type != "method_declaration":
            continue
        for name, arguments in annotations(method):
            if name not in _MAPPING_METHODS:
                continue
            http_methods = _http_methods(name, arguments)
            sources = _collect_sources(method)
            for prefix in prefixes:
                for suffix in annotation_strings(arguments) or [""]:
                    for http_method in http_methods:
                        yield {
                            "method": http_method,
                            "path": _join(prefix, suffix),
                            "function": text(method.child_by_field_name("name")),
                            "file_path": file_path,
                            "start_line": start_line(method),
                            "end_line": end_line(method),
                            "sources": sources,
                            "framework": "spring",
                        }


def _http_methods(annotation_name: str, arguments) -> list[str]:
    fixed = _MAPPING_METHODS[annotation_name]
    if fixed is not None:
        return [fixed]
    declared = _REQUEST_METHOD_RE.findall(annotation_element(arguments, "method") or "")
    return declared or ["ANY"]


def _join(prefix: str, suffix: str) -> str:
    path = "/" + "/".join(part.strip("/") for part in (prefix, suffix) if part.strip("/"))
    return path


def _collect_sources(method) -> list[dict]:
    sources: list[dict] = []
    params = method.child_by_field_name("parameters")
    if params is None:
        return sources
    for param in params.named_children:
        if param.type not in ("formal_parameter", "spread_parameter"):
            continue
        name = text(param.child_by_field_name("name"))
        if not name and param.type == "spread_parameter":
            declarator = next((c for c in param.named_children if c.type == "variable_declarator"), None)
            name = text(declarator.child_by_field_name("name")) if declarator else ""
        if not name:
            continue
        type_name = _GENERIC_RE.sub("", text(param.child_by_field_name("type"))).rsplit(".", 1)[-1]

        kind = None
        binding = None
        for annotation_name, arguments in annotations(param):
            if annotation_name in _PARAM_SOURCES:
                kind = _PARAM_SOURCES[annotation_name]
                bound = annotation_strings(arguments)
                binding = bound[0] if bound else None
                break
        if kind is None:
            if type_name in _REQUEST_TYPES:
                kind = "request"
            elif type_name in _FRAMEWORK_TYPES or any(a == "AuthenticationPrincipal" for a, _ in annotations(param)):
                continue
            else:
                kind = "query"
        sources.append({"name": name, "kind": kind, "field": None, "binding": binding or name})
    return sources
