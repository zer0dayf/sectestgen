# SecTestGen

Modular security finding validation and evidence platform for REST API
backends — FastAPI (Python) and Spring Boot (Java).

Two pipelines:

- **Static** — Semgrep / Bandit / (optional) CodeQL findings, correlated with FastAPI
  or Spring user-input sources and sinks, validated with bounded source-to-sink
  reachability analysis and, when safe, a network-isolated Docker sandbox. Produces Report 1.
- **SCA** — CycloneDX SBOM data plus Dependency-Track / Snyk / Grype results, checked
  against actual package imports and (when known) symbol usage. Produces Report 2.

Report 3 merges and de-duplicates both.

Architecture is adapter-based (`sectestgen.core.adapters`): `StaticAnalyzerAdapter`,
`SCAAdapter`, `FrameworkAdapter`, `ReachabilityEngine`, `SandboxExecutor`, `Classifier`,
`Reporter`. New tools/frameworks are added by implementing an interface, without
touching the normalized `Finding` model in `sectestgen.core.models`.

## Status

WP1 (static pipeline) is implemented for **Python/FastAPI and Java/Spring**:

- Semgrep (project rule packs in `rules/semgrep/`: `fastapi_security.yml`,
  `spring_security.yml`) + Bandit (Python).
- Route/user-input discovery: AST-only for FastAPI, tree-sitter-only for
  Spring (`@RestController`/`@Controller`, class-level `@RequestMapping`
  prefixes, `@PathVariable`/`@RequestParam`/`@RequestHeader`/`@CookieValue`/
  `@RequestBody`, ...). No project code is imported, compiled or run.
- Bounded single-function/method source-to-sink reachability for both
  languages, a default classifier, and JSON/HTML Report 1 output.

Evaluated against `fixtures/vulnerable_fastapi/` and
`fixtures/vulnerable_spring/`, all 5 benchmark sink categories
(CWE-78/95/502/22/89) resolve to `REACHABLE` with the correct entry point
and source in both languages, and none of the SAFE counterparts are flagged
by the Java rules.

WP2 (SCA pipeline) is in progress: a CycloneDX SBOM reader, a CycloneDX
`vulnerabilities` adapter (the shape Dependency-Track exports) and a Grype
adapter, de-duplication on purl + CVE, and an import/usage engine for
**Python and Java/Maven** projects that records where a vulnerable package
is imported and referenced (and whether that's inside a FastAPI route or a
Spring controller). Classified into Report 2 (JSON + HTML). Evaluated
against `fixtures/sca_python/` and `fixtures/sca_java/`, all 7 benchmark
advisories match their ground truth. Snyk support is still open.

Import/usage evidence never yields `REACHABLE`/`CONFIRMED` on its own, and
`NOT_OBSERVED` means "no use observed", not "safe".

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

`bandit` comes with the `dev` extra. `semgrep` does too, except on Windows,
which has no native build: there (or wherever the `semgrep` binary is
missing or blocked) `SemgrepAdapter` runs the pinned `semgrep/semgrep`
Docker image instead, offline (`--network none`) with the target mounted
read-only — Docker must be running. `sectestgen sca` reads a pre-generated
Grype report (`--grype`), or runs `grype` itself if it's on `PATH`; without
either it uses only the SBOM's embedded `vulnerabilities`.

## Test

```bash
pytest
```

## CLI

```bash
sectestgen --version

# Report 1 (static) — FastAPI and/or Spring project
sectestgen static path/to/project -o sectestgen-out

# Report 2 (SCA)
sectestgen sca path/to/sbom.cdx.json -s path/to/project --grype grype.json -o sectestgen-out
```
