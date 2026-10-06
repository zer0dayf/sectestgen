# SecTestGen

Modular security finding validation and evidence platform for FastAPI backends and REST APIs.

Two pipelines:

- **Static** — Semgrep / Bandit / (optional) CodeQL findings, correlated with FastAPI
  user-input sources and sinks, validated with bounded source-to-sink reachability
  analysis and, when safe, a network-isolated Docker sandbox. Produces Report 1.
- **SCA** — CycloneDX SBOM data plus Dependency-Track / Snyk / Grype results, checked
  against actual package imports and (when known) symbol usage. Produces Report 2.

Report 3 merges and de-duplicates both.

Architecture is adapter-based (`sectestgen.core.adapters`): `StaticAnalyzerAdapter`,
`SCAAdapter`, `FrameworkAdapter`, `ReachabilityEngine`, `SandboxExecutor`, `Classifier`,
`Reporter`. New tools/frameworks are added by implementing an interface, without
touching the normalized `Finding` model in `sectestgen.core.models`.

## Status

WP1 (static pipeline) is implemented: Semgrep + Bandit adapters, a bounded
AST-based FastAPI route/source discovery adapter, a bounded source-to-sink
reachability engine, a default classifier, and JSON/HTML Report 1 output.
Evaluated against `fixtures/vulnerable_fastapi/`, it correctly correlates
all 5 benchmark sink categories (CWE-78/95/502/22/89) to their FastAPI
entry point and source.

Next increment (WP2, due 2026-10-25): CycloneDX/Dependency-Track/Snyk/Grype
SCA adapters, package/import/symbol-usage checks, Report 2.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

`semgrep` and `bandit` must be importable from this environment (both are
pulled in by the `dev` extra); `sectestgen static` shells out to whichever
copies are first on `PATH`.

## Test

```bash
pytest
```

## CLI

```bash
sectestgen --version
sectestgen static path/to/fastapi/project -o sectestgen-out   # Report 1 (WP1)
sectestgen sca path/to/sbom.json                              # WP2, not implemented yet
```
