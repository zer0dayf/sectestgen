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

Current increment (WP0): normalized evidence schema + adapter interfaces + CLI
skeleton. No analyzer adapters are wired up yet.

Next increment (WP1, due 2026-10-18): Semgrep/Bandit adapters, FastAPI framework
adapter (route/source discovery), bounded reachability engine, Report 1.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Test

```bash
pytest
```

## CLI (stubs for now)

```bash
sectestgen --version
sectestgen static path/to/fastapi/project
sectestgen sca path/to/sbom.json
```
