"""Vulnerable-symbol metadata for SCA advisories.

Function-level confirmation needs to know *which* functions/classes of a
package an advisory affects. Most provider output doesn't say, so symbols
come from three places, merged per finding:

1. the provider itself (Snyk `functions`, kept by `SnykAdapter` in
   `raw["vulnerable_symbols"]`);
2. `CURATED` below — a small hand-maintained table of the *public API*
   through which an application reaches the vulnerable code (e.g. log4j's
   `Logger.info`, not the internal `JndiLookup.lookup` that apps never call
   directly), each entry with the advisory it was taken from;
3. a user-supplied JSON file (`sectestgen sca --symbols FILE`), a list of
   `{"advisory": "CVE-...", "purl": "pkg:...", "symbols": [...]}`
   (`purl` optional, version ignored).

An entry may name the advisory's `sink_type` (the five static sink types),
which lets the sandbox validate a vulnerable symbol called inside a route.

Symbols are dotted names: `module.function` / `module.Class` (Python) or
`package.Class.method` / `package.Class` (Java). An empty list means "no
symbol metadata" and the usage engine stays at package/import level.
"""

from __future__ import annotations

import json
from pathlib import Path

from sectestgen.adapters.package_usage import parse_purl
from sectestgen.core.models import Finding

_LOG4J_LOGGER = "org.apache.logging.log4j.Logger"

CURATED: list[dict] = [
    {
        "purl": "pkg:pypi/pyyaml",
        "advisories": ["CVE-2020-14343", "CVE-2020-1747"],
        "symbols": ["yaml.load", "yaml.load_all", "yaml.full_load", "yaml.full_load_all", "yaml.FullLoader"],
        "sink_type": "unsafe_deserialization",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-14343 (FullLoader / full_load)",
    },
    {
        "purl": "pkg:pypi/jinja2",
        "advisories": ["CVE-2019-10906"],
        "symbols": ["jinja2.sandbox.SandboxedEnvironment", "jinja2.sandbox.ImmutableSandboxedEnvironment"],
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-10906 (sandbox str.format_map escape)",
    },
    {
        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core",
        "advisories": ["CVE-2021-44228", "CVE-2021-45046"],
        "symbols": [
            f"{_LOG4J_LOGGER}.{m}" for m in ("trace", "debug", "info", "warn", "error", "fatal", "log", "printf")
        ],
        "reference": "https://logging.apache.org/log4j/2.x/security.html (lookups in logged messages)",
    },
    {
        "purl": "pkg:maven/org.apache.commons/commons-text",
        "advisories": ["CVE-2022-42889"],
        "symbols": [
            "org.apache.commons.text.StringSubstitutor.createInterpolator",
            "org.apache.commons.text.lookup.StringLookupFactory.interpolatorStringLookup",
            "org.apache.commons.text.lookup.StringLookupFactory.scriptStringLookup",
            "org.apache.commons.text.lookup.StringLookupFactory.dnsStringLookup",
            "org.apache.commons.text.lookup.StringLookupFactory.urlStringLookup",
        ],
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2022-42889 (default interpolator lookups)",
    },
    {
        "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind",
        "advisories": ["CVE-2019-12384"],
        "symbols": [
            "com.fasterxml.jackson.databind.ObjectMapper.enableDefaultTyping",
            "com.fasterxml.jackson.databind.ObjectMapper.activateDefaultTyping",
        ],
        "sink_type": "unsafe_deserialization",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-12384 (polymorphic default typing)",
    },
]


class VulnerableSymbolDB:
    def __init__(self, entries: list[dict] | None = None, source: str = "curated") -> None:
        self._entries: list[tuple[tuple | None, set[str], list[str], str]] = []
        self._sink_types: list[tuple[tuple | None, set[str], str]] = []
        self.add(CURATED if entries is None else entries, source)

    def add(self, entries: list[dict], source: str) -> None:
        for entry in entries:
            advisories = entry.get("advisories") or [entry.get("advisory")]
            advisories = {a for a in advisories if a}
            symbols = [s for s in entry.get("symbols", []) if isinstance(s, str) and s]
            if not advisories or not symbols:
                raise ValueError(f"symbol entry needs an advisory and at least one symbol: {entry!r}")
            self._entries.append((_package_key(entry.get("purl")), advisories, symbols, source))
            if entry.get("sink_type"):
                self._sink_types.append((_package_key(entry.get("purl")), advisories, entry["sink_type"]))

    @classmethod
    def with_file(cls, path: Path | None) -> "VulnerableSymbolDB":
        db = cls()
        if path is not None:
            data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
            if not isinstance(data, list):
                raise ValueError(f"{path}: expected a JSON list of symbol entries")
            db.add(data, f"file:{Path(path).name}")
        return db

    def lookup(self, finding: Finding) -> tuple[list[str], list[str]]:
        """(symbols, sources) for the finding's advisory + package."""
        advisories = {a for a in (finding.cve, finding.rule_id) if a}
        package = _package_key(finding.purl)
        symbols: list[str] = []
        sources: list[str] = []
        for key, entry_advisories, entry_symbols, source in self._entries:
            if not advisories & entry_advisories:
                continue
            if key is not None and key != package:
                continue
            symbols.extend(s for s in entry_symbols if s not in symbols)
            if source not in sources:
                sources.append(source)
        return symbols, sources

    def sink_type(self, finding: Finding) -> str | None:
        advisories = {a for a in (finding.cve, finding.rule_id) if a}
        package = _package_key(finding.purl)
        for key, entry_advisories, sink_type in self._sink_types:
            if advisories & entry_advisories and key in (None, package):
                return sink_type
        return None

    def symbols_for(self, finding: Finding) -> tuple[list[str], list[str]]:
        """Provider metadata already on the finding merged with this DB."""
        known = finding.raw.get("vulnerable_symbols") or {}
        symbols = list(known.get("symbols", []))
        sources = list(known.get("sources", []))
        extra, extra_sources = self.lookup(finding)
        symbols.extend(s for s in extra if s not in symbols)
        sources.extend(s for s in extra_sources if s not in sources)
        return symbols, sources


def _package_key(purl: str | None) -> tuple | None:
    ref = parse_purl(purl)
    if ref is None:
        return None
    name = ref.name.lower().replace("_", "-") if ref.ecosystem == "pypi" else ref.name
    return (ref.ecosystem, ref.namespace, name)
