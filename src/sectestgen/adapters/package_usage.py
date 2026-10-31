"""Import/usage ReachabilityEngine for SCA findings (Python + Java).

Answers "is this vulnerable package actually used by the project?" with
bounded, text/AST-only evidence. No project code is imported, compiled, or
executed.

For each finding's purl the package is mapped to the module/package names
code would import (`PyYAML` -> `yaml`, `log4j-core` ->
`org.apache.logging.log4j`), then the project's sources are searched:

- Python: `ast` imports + `Name` references to the bound names; a reference
  inside a FastAPI route handler counts as an entry-point reference.
- Java: `import` statements + references to the imported simple class
  names (comments stripped); a reference in a file carrying a Spring
  controller/mapping annotation counts as an entry-point reference.

The result is recorded as `finding.raw["usage"]` (a `status` plus import
and reference locations) and a `ReachabilityEvidence` whose `path` lists
those locations. Absence of an import can't prove the vulnerable code never
runs (a transitive dependency may be exercised through its parent).

Symbol level: when the advisory's vulnerable symbols are known (provider
metadata or `VulnerableSymbolDB`), references are resolved to qualified
names - Python through import aliases (`import yaml as y; y.load` ->
`yaml.load`), Java through imports and declared variable types
(`Logger log; log.info(..)` -> `org.apache.logging.log4j.Logger.info`) -
and matched against them (`usage["symbol_status"]`). Only a vulnerable
symbol referenced inside an entry point sets `reachable=True`; argument
values are not checked. Without symbol metadata `reachable` stays `None`,
since a package reference can't show the vulnerable path runs.
`SCAClassifier` turns `status`/`symbol_status` into a classification.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote

from sectestgen.adapters.cyclonedx import SBOM, purl_type
from sectestgen.core.adapters import ReachabilityEngine
from sectestgen.core.models import Finding, ReachabilityEvidence, SourceLocation

if TYPE_CHECKING:
    from sectestgen.adapters.vulnerable_symbols import VulnerableSymbolDB

# Usage statuses, strongest evidence first.
REFERENCED_IN_ENTRY_POINT = "referenced_in_entry_point"
REFERENCED = "referenced"
IMPORTED_ONLY = "imported_only"
NOT_IMPORTED = "not_imported"
NO_SOURCES = "no_sources"
UNSUPPORTED = "unsupported"

# Symbol statuses (only set when the advisory's vulnerable symbols are known).
SYMBOL_REFERENCED_IN_ENTRY_POINT = "symbol_referenced_in_entry_point"
SYMBOL_REFERENCED = "symbol_referenced"
SYMBOL_NOT_REFERENCED = "symbol_not_referenced"

# PyPI distribution name -> top-level import names, for distributions whose
# import name differs from the normalized distribution name.
_PYPI_IMPORT_NAMES = {
    "pyyaml": ["yaml"],
    "pillow": ["PIL"],
    "beautifulsoup4": ["bs4"],
    "scikit-learn": ["sklearn"],
    "python-dateutil": ["dateutil"],
    "pyjwt": ["jwt"],
    "psycopg2-binary": ["psycopg2"],
    "opencv-python": ["cv2"],
    "protobuf": ["google.protobuf"],
    "python-multipart": ["multipart"],
    "pycryptodome": ["Crypto"],
    "attrs": ["attr", "attrs"],
    "setuptools": ["setuptools", "pkg_resources"],
}

# Maven (groupId, artifactId) -> Java package prefixes. log4j-core is
# mapped to the API package on purpose: applications import
# org.apache.logging.log4j.LogManager (log4j-api), and log4j-core is the
# implementation those calls run through.
_MAVEN_PACKAGES = {
    ("org.apache.logging.log4j", "log4j-core"): ["org.apache.logging.log4j"],
    ("org.apache.logging.log4j", "log4j-api"): ["org.apache.logging.log4j"],
    ("com.fasterxml.jackson.core", "jackson-databind"): ["com.fasterxml.jackson.databind"],
    ("com.fasterxml.jackson.core", "jackson-core"): ["com.fasterxml.jackson.core"],
    ("org.apache.commons", "commons-text"): ["org.apache.commons.text"],
    ("org.apache.commons", "commons-lang3"): ["org.apache.commons.lang3"],
    ("org.apache.commons", "commons-collections4"): ["org.apache.commons.collections4"],
    ("commons-collections", "commons-collections"): ["org.apache.commons.collections"],
    ("org.yaml", "snakeyaml"): ["org.yaml.snakeyaml"],
    ("com.google.guava", "guava"): ["com.google.common"],
    ("org.springframework", "spring-web"): ["org.springframework.web"],
    ("org.springframework", "spring-webmvc"): ["org.springframework.web.servlet"],
    ("org.springframework", "spring-beans"): ["org.springframework.beans"],
    ("org.springframework", "spring-core"): ["org.springframework.core"],
}

_JAVA_IMPORT_RE = re.compile(r"^[ \t]*import\s+(static\s+)?([\w.]+?)(\.\*)?\s*;", re.MULTILINE)
_JAVA_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)
_JAVA_ENTRY_POINT_RE = re.compile(
    r"@(RestController|Controller|RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\b"
)
# `Type<..> name =|;|,|)` - field, local and parameter declarations.
_JAVA_DECL_RE = re.compile(r"\b([A-Z][\w$]*)\s*(?:<[^;(){}]*?>)?\s+([A-Za-z_$][\w$]*)\s*(?=[=;,)])")
_JAVA_CALL_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)\s*\(")
_JAVA_NEW_RE = re.compile(r"\bnew\s+([A-Z][\w$]*)\s*(?:<[^;(){}]*?>)?\s*\(")
_JAVA_BARE_CALL_RE = re.compile(r"(?<![\w$.])([a-z_$][\w$]*)\s*\(")


@dataclass
class _Import:
    module: str
    file_path: str
    line: int
    bound_names: list[str]  # "*" = wildcard import, references can't be resolved


@dataclass
class _SourceIndex:
    imports: list[_Import] = field(default_factory=list)
    # file -> [(line, name)] of every name reference outside import lines
    references: dict[str, list[tuple[int, str]]] = field(default_factory=dict)
    # file -> [(start_line, end_line, label)] entry-point ranges; a file-wide
    # entry point (Java controller) is a single range covering the file
    entry_points: dict[str, list[tuple[int, int, str]]] = field(default_factory=dict)
    # file -> [(line, qualified name)] of references resolved through imports
    qualified: dict[str, list[tuple[int, str]]] = field(default_factory=dict)
    language: str = "python"
    file_count: int = 0


@dataclass
class PackageRef:
    ecosystem: str | None
    namespace: str | None
    name: str


def parse_purl(purl: str | None) -> PackageRef | None:
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("#", 1)[0].split("?", 1)[0].split("@", 1)[0]
    parts = [unquote(p) for p in body.split("/")]
    if len(parts) < 2:
        return None
    return PackageRef(
        ecosystem=parts[0].lower(),
        namespace="/".join(parts[1:-1]) or None,
        name=parts[-1],
    )


def import_names_for(purl: str | None) -> tuple[list[str], str]:
    """Module/package names code would import for `purl`, plus how they were
    derived so the evidence says how sure it is: "table" (known mapping),
    "name-convention" (PyPI import name = normalized distribution name, true
    for most packages) or "heuristic" (Maven groupId used as a package
    prefix — coarse, may match sibling artifacts)."""
    ref = parse_purl(purl)
    if ref is None:
        return [], "unknown"
    if ref.ecosystem == "pypi":
        key = ref.name.lower().replace("_", "-")
        if key in _PYPI_IMPORT_NAMES:
            return _PYPI_IMPORT_NAMES[key], "table"
        return [key.replace("-", "_").replace(".", "_")], "name-convention"
    if ref.ecosystem == "maven":
        mapped = _MAVEN_PACKAGES.get((ref.namespace or "", ref.name))
        if mapped:
            return mapped, "table"
        return ([ref.namespace] if ref.namespace else []), "heuristic"
    return [], "unknown"


class ImportUsageReachabilityEngine(ReachabilityEngine):
    def __init__(
        self,
        sbom: SBOM | None = None,
        routes: list[dict] | None = None,
        symbols: VulnerableSymbolDB | None = None,
    ) -> None:
        """`symbols`: extra vulnerable-symbol metadata; without it only the
        provider's own metadata (`raw["vulnerable_symbols"]`) is used."""
        self.sbom = sbom
        self.routes = routes or []
        self.symbols = symbols
        self._indexes: dict[tuple[str, str], _SourceIndex] = {}

    def analyze(self, finding: Finding, target: Path) -> Finding:
        target = Path(target).resolve()
        ecosystem = purl_type(finding.purl)
        component = self.sbom.find(finding.purl) if self.sbom else None
        usage: dict = {
            "ecosystem": ecosystem,
            "direct": component.direct if component else None,
            "parents": list(component.parents) if component else [],
            "imports": [],
            "references": [],
        }

        if ecosystem == "pypi":
            index = self._index(target, "python")
        elif ecosystem == "maven":
            index = self._index(target, "java")
        else:
            usage["status"] = UNSUPPORTED
            finding.raw["usage"] = usage
            finding.reachability = ReachabilityEvidence(
                reachable=None,
                notes=f"ecosystem {ecosystem or 'unknown'!r} has no usage analyzer; not evaluated",
            )
            return finding

        names, mapping = import_names_for(finding.purl)
        usage["import_names"] = names
        usage["mapping"] = mapping

        if index.file_count == 0:
            usage["status"] = NO_SOURCES
            finding.raw["usage"] = usage
            finding.reachability = ReachabilityEvidence(
                reachable=None, notes=f"no {ecosystem} source files found under target; not evaluated"
            )
            return finding

        matched = [imp for imp in index.imports if _module_matches(imp.module, names)]
        usage["imports"] = [f"{_rel(i.file_path, target)}:{i.line} import {i.module}" for i in matched]

        references: list[str] = []
        in_entry_point: list[str] = []
        for imp in matched:
            for line, label in _references_for(imp, index):
                location = f"{_rel(imp.file_path, target)}:{line} {label}"
                references.append(location)
                entry = _entry_point_at(index, imp.file_path, line)
                if entry is not None:
                    in_entry_point.append(f"{location} (in {entry})")
        usage["references"] = sorted(set(references))

        if in_entry_point:
            usage["status"] = REFERENCED_IN_ENTRY_POINT
            path, notes = sorted(set(in_entry_point)), "package referenced inside an entry point"
        elif references:
            usage["status"] = REFERENCED
            path, notes = usage["references"], "package referenced, but not inside a discovered entry point"
        elif matched:
            usage["status"] = IMPORTED_ONLY
            path, notes = usage["imports"], "package imported, but no reference to the imported names found"
        else:
            usage["status"] = NOT_IMPORTED
            path = []
            notes = f"no import of {', '.join(names) or finding.package_name} found"
            if usage["direct"] is False and usage["parents"]:
                notes += f"; transitive dependency, may still run via {', '.join(usage['parents'])}"
        if mapping == "heuristic":
            notes += f" (import names {names} guessed from package coordinates)"

        reachable = None
        symbols, sources = self._known_symbols(finding)
        if symbols and matched:  # not imported -> package-level evidence already says it all
            hits, in_entry, sites = _symbol_references(index, symbols, target)
            usage["symbols"] = {
                "known": symbols,
                "sources": sources,
                "references": hits,
                "in_entry_point": in_entry,
                "sites": [{"file_path": f, "line": line, "entry_point": e} for f, line, e in sites],
            }
            if in_entry:
                usage["symbol_status"] = SYMBOL_REFERENCED_IN_ENTRY_POINT
                path, reachable = in_entry, True
                notes = "vulnerable symbol referenced inside an entry point (argument values not checked)"
                self._attach_entry_point(finding, sites)
            elif hits:
                usage["symbol_status"] = SYMBOL_REFERENCED
                path = hits
                notes = "vulnerable symbol referenced, but not inside a discovered entry point"
            else:
                usage["symbol_status"] = SYMBOL_NOT_REFERENCED
                notes += (
                    f"; none of the {len(symbols)} known vulnerable symbol(s) is referenced directly"
                    " (the package's own code may still reach them)"
                )

        finding.raw["usage"] = usage
        finding.reachability = ReachabilityEvidence(path=path, reachable=reachable, notes=notes)
        return finding

    def _known_symbols(self, finding: Finding) -> tuple[list[str], list[str]]:
        if self.symbols is not None:
            return self.symbols.symbols_for(finding)
        known = finding.raw.get("vulnerable_symbols") or {}
        return list(known.get("symbols", [])), list(known.get("sources", []))

    def _attach_entry_point(self, finding: Finding, sites: list[tuple[str, int, str | None]]) -> None:
        """Record the first entry-point call site the way the static engines
        do (location, route, user-input source, sink type), so the same
        sandbox and Report 3 correlation can use SCA findings."""
        file_path, line, label = next(s for s in sites if s[2] is not None)
        finding.location = SourceLocation(file_path=file_path, line=line)
        finding.raw["entry_point"] = True
        finding.raw["route"] = label
        if self.symbols is not None:
            finding.sink = finding.sink or self.symbols.sink_type(finding)
        route = next(
            (r for r in self.routes
             if f"{r['method']} {r['path']}" == label and str(Path(r["file_path"]).resolve()) == file_path),
            None,
        )
        if route is not None and route["sources"]:
            source = route["sources"][0]
            field_name = f".{source['field']}" if source.get("field") else ""
            finding.user_input_source = f"{label} :: {source['kind']}:{source['name']}{field_name}"

    def _index(self, target: Path, language: str) -> _SourceIndex:
        key = (str(target), language)
        if key not in self._indexes:
            self._indexes[key] = (
                _index_python(target, self.routes) if language == "python" else _index_java(target)
            )
        return self._indexes[key]


def _module_matches(module: str, names: list[str]) -> bool:
    return any(module == n or module.startswith(n + ".") for n in names)


def _references_for(imp: _Import, index: _SourceIndex) -> list[tuple[int, str]]:
    refs = index.references.get(imp.file_path, [])
    if "*" in imp.bound_names:
        # Wildcard import: which names come from this package is unknown, so
        # count the import itself as a reference rather than under-report.
        return [(imp.line, f"wildcard import {imp.module}.*")]
    wanted = set(imp.bound_names)
    return [(line, f"uses {name}") for line, name in refs if name in wanted and line != imp.line]


def _symbol_references(
    index: _SourceIndex, symbols: list[str], target: Path
) -> tuple[list[str], list[str], list[tuple[str, int, str | None]]]:
    """(labels, entry-point labels, sorted (file, line, entry label) sites)."""
    hits: set[str] = set()
    in_entry: set[str] = set()
    sites: set[tuple[str, int, str | None]] = set()
    for file_path, refs in index.qualified.items():
        for line, ref in refs:
            for symbol in symbols:
                kind = _symbol_match(ref, symbol, index.language)
                if kind is None:
                    continue
                location = f"{_rel(file_path, target)}:{line}"
                label = (
                    f"{location} uses {ref}"
                    if kind == "exact"
                    else f"{location} uses class {ref} (call to {symbol} not resolvable)"
                )
                hits.add(label)
                entry = _entry_point_at(index, file_path, line)
                sites.add((file_path, line, entry))
                if entry is not None:
                    in_entry.add(f"{label} (in {entry})")
                break
    return sorted(hits), sorted(in_entry), sorted(sites, key=lambda s: (s[0], s[1], s[2] or ""))


def _symbol_match(ref: str, symbol: str, language: str) -> str | None:
    if ref == symbol or ref.startswith(symbol + "."):
        return "exact"
    # Python instances aren't typed, so `mod.Class.method` can only be matched
    # as far as the class; Java calls are resolved through declared types.
    owner = symbol.rpartition(".")[0]
    if language == "python" and owner and ref == owner and owner.rpartition(".")[2][:1].isupper():
        return "class"
    return None


def _entry_point_at(index: _SourceIndex, file_path: str, line: int) -> str | None:
    for start, end, label in index.entry_points.get(file_path, []):
        if start <= line <= end:
            return label
    return None


def _rel(file_path: str, target: Path) -> str:
    try:
        return Path(file_path).resolve().relative_to(target).as_posix()
    except ValueError:
        return file_path


def _index_python(target: Path, routes: list[dict]) -> _SourceIndex:
    index = _SourceIndex()
    files = [target] if target.is_file() else sorted(target.rglob("*.py"))
    for py_file in files:
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue
        index.file_count += 1
        file_path = str(py_file.resolve())
        index.qualified[file_path] = _python_qualified(tree)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    bound = alias.asname or alias.name.split(".", 1)[0]
                    index.imports.append(_Import(alias.name, file_path, node.lineno, [bound]))
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                bound = [a.asname or a.name for a in node.names]
                index.imports.append(_Import(node.module, file_path, node.lineno, bound))
            elif isinstance(node, ast.Name):
                index.references.setdefault(file_path, []).append((node.lineno, node.id))

    for route in routes:
        index.entry_points.setdefault(str(Path(route["file_path"]).resolve()), []).append(
            (route["start_line"], route["end_line"], f"{route['method']} {route['path']}")
        )
    return index


def _python_qualified(tree: ast.AST) -> list[tuple[int, str]]:
    """Name/attribute references whose head is an imported name, rewritten to
    the imported module path (`from yaml import load as L; L()` -> `yaml.load`)."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    head = alias.name.split(".", 1)[0]
                    aliases[head] = head
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    refs: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Attribute, ast.Name)):
            continue
        dotted = _dotted(node)
        if dotted is None:
            continue
        head, _, rest = dotted.partition(".")
        if head in aliases:
            refs.append((node.lineno, aliases[head] + (f".{rest}" if rest else "")))
    return refs


def _dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _index_java(target: Path) -> _SourceIndex:
    index = _SourceIndex(language="java")
    files = [target] if target.is_file() else sorted(target.rglob("*.java"))
    for java_file in files:
        try:
            source = java_file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        index.file_count += 1
        file_path = str(java_file.resolve())
        # Blank out comments but keep newlines so line numbers stay correct.
        code = _JAVA_COMMENT_RE.sub(lambda m: "\n" * m.group(0).count("\n"), source)

        import_lines: set[int] = set()
        classes: dict[str, str] = {}  # simple class name -> FQN
        static_members: dict[str, str] = {}  # statically imported member -> owner FQN
        wildcard_packages: list[str] = []
        for match in _JAVA_IMPORT_RE.finditer(code):
            line = code.count("\n", 0, match.start()) + 1
            import_lines.add(line)
            is_static, name, wildcard = match.group(1), match.group(2), match.group(3)
            if wildcard:
                index.imports.append(_Import(name, file_path, line, ["*"]))
                if not is_static:
                    wildcard_packages.append(name)
                continue
            # `import a.b.C;` binds C (package a.b); `import static a.b.C.m;` binds m.
            owner, _, simple = name.rpartition(".")
            module = owner.rpartition(".")[0] if is_static else owner
            index.imports.append(_Import(module, file_path, line, [simple]))
            if is_static:
                static_members[simple] = owner
            else:
                classes[simple] = name

        refs = index.references.setdefault(file_path, [])
        for line_no, text in enumerate(code.splitlines(), start=1):
            if line_no in import_lines:
                continue
            for word in re.findall(r"\b[A-Za-z_]\w*\b", text):
                refs.append((line_no, word))

        index.qualified[file_path] = _java_qualified(code, import_lines, classes, static_members, wildcard_packages)

        if _JAVA_ENTRY_POINT_RE.search(code):
            index.entry_points[file_path] = [(1, code.count("\n") + 1, f"controller {java_file.stem}")]
    return index


def _java_qualified(
    code: str,
    import_lines: set[int],
    classes: dict[str, str],
    static_members: dict[str, str],
    wildcard_packages: list[str],
) -> list[tuple[int, str]]:
    """Class references and method calls resolved to `pkg.Class[.method]`.
    Variable types come from declarations anywhere in the file (scopes are
    not tracked); a class from a wildcard import resolves to every wildcard
    package as a candidate."""

    def resolve(simple: str) -> list[str]:
        if simple in classes:
            return [classes[simple]]
        if simple[:1].isupper():
            return [f"{pkg}.{simple}" for pkg in wildcard_packages]
        return []

    variables: dict[str, str] = {}
    for match in _JAVA_DECL_RE.finditer(code):
        if resolve(match.group(1)):
            variables[match.group(2)] = match.group(1)

    refs: list[tuple[int, str]] = []
    for line_no, text in enumerate(code.splitlines(), start=1):
        if line_no in import_lines:
            continue
        for match in _JAVA_CALL_RE.finditer(text):
            receiver, method = match.groups()
            for owner in resolve(variables.get(receiver, receiver)):
                refs.append((line_no, f"{owner}.{method}"))
        for match in _JAVA_NEW_RE.finditer(text):
            for owner in resolve(match.group(1)):
                refs.append((line_no, f"{owner}.<init>"))
        for match in _JAVA_BARE_CALL_RE.finditer(text):
            if match.group(1) in static_members:
                refs.append((line_no, f"{static_members[match.group(1)]}.{match.group(1)}"))
        for word in set(re.findall(r"\b[A-Z][\w$]*\b", text)):
            for owner in resolve(word):
                refs.append((line_no, owner))
    return refs
