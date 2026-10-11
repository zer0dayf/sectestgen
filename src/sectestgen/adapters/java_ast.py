"""Shared tree-sitter helpers for the Java adapters.

Java sources are only parsed, never compiled or executed. tree-sitter is
error-tolerant: a file with syntax errors still yields a tree (with ERROR
nodes), so one bad file never stops discovery for the rest of a project.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

import tree_sitter_java
from tree_sitter import Language, Node, Parser

_PARSER = Parser(Language(tree_sitter_java.language()))


def parse_file(path: Path) -> Node | None:
    try:
        return _PARSER.parse(Path(path).read_bytes()).root_node
    except OSError:
        return None


def parse_source(source: str) -> Node:
    return _PARSER.parse(source.encode("utf-8")).root_node


def text(node: Node | None) -> str:
    return node.text.decode("utf-8", errors="replace") if node is not None and node.text else ""


def start_line(node: Node) -> int:
    return node.start_point[0] + 1


def end_line(node: Node) -> int:
    return node.end_point[0] + 1


def walk(node: Node) -> Iterator[Node]:
    """Pre-order traversal (source order)."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def annotations(node: Node) -> list[tuple[str, Node | None]]:
    """(simple name, argument list) for each annotation on a declaration."""
    found: list[tuple[str, Node | None]] = []
    for child in node.children:
        if child.type != "modifiers":
            continue
        for item in child.named_children:
            if item.type in ("marker_annotation", "annotation"):
                name = text(item.child_by_field_name("name")).rsplit(".", 1)[-1]
                found.append((name, item.child_by_field_name("arguments")))
    return found


def annotation_strings(arguments: Node | None, keys: tuple[str, ...] = ("value", "path", "name")) -> list[str]:
    """String values of an annotation's positional argument or the given keys:
    `@GetMapping("/a")`, `@RequestMapping(path = {"/a", "/b"})`."""
    if arguments is None:
        return []
    values: list[str] = []
    for arg in arguments.named_children:
        if arg.type == "element_value_pair":
            if text(arg.child_by_field_name("key")) in keys:
                values.extend(_string_literals(arg.child_by_field_name("value")))
        else:
            values.extend(_string_literals(arg))
    return values


def annotation_element(arguments: Node | None, key: str) -> str | None:
    """Raw source text of one `key = value` annotation element."""
    if arguments is None:
        return None
    for arg in arguments.named_children:
        if arg.type == "element_value_pair" and text(arg.child_by_field_name("key")) == key:
            return text(arg.child_by_field_name("value"))
    return None


def _string_literals(node: Node | None) -> list[str]:
    if node is None:
        return []
    if node.type == "string_literal":
        return [text(node)[1:-1]]
    if node.type == "element_value_array_initializer":
        return [s for child in node.named_children for s in _string_literals(child)]
    return []
