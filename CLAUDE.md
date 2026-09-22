# SecTestGen — project context

Distilled from the project proposal (kept out of git; the docx is not tracked).
No personal/company names here on purpose — see `.claude/PROGRESS.md` for
current status and next steps before doing anything.

## What this is

Modular security finding validation and evidence platform for FastAPI
backends / REST APIs. Academic senior/graduation project, single-person team,
Scrum-based, ~17 weeks, ~170 person-hours total.

## Two pipelines, three reports

1. **Static** — Semgrep + Bandit + optional CodeQL findings, normalized, then
   correlated with FastAPI user-input sources and sinks. Bounded
   source-to-sink reachability analysis; when safe, validated in a
   network-isolated Docker sandbox. → **Report 1**.
2. **SCA** — CycloneDX SBOM + Dependency-Track/Snyk/Grype results, normalized
   by purl/CVE/severity/fixed-version. Checks whether vulnerable packages are
   imported, referenced, and (when metadata allows) reachable from entry
   points. → **Report 2**.
3. **Report 3** merges and de-duplicates Report 1 + Report 2.

## Architecture — adapter-based, core model never changes when adding a tool

Core lives in `src/sectestgen/core/`:

- `models.py` — the normalized `Finding` (see schema below).
- `adapters.py` — seven interfaces new implementations plug into:
  - `StaticAnalyzerAdapter(target) -> Findings` (Semgrep/Bandit/CodeQL)
  - `SCAAdapter(sbom) -> Findings` (Dependency-Track/Snyk/Grype)
  - `FrameworkAdapter` — route/user-input-source discovery (FastAPI first)
  - `ReachabilityEngine` — bounded AST/import/call analysis; unsupported
    dynamic behavior → `INCONCLUSIVE`, never silently "safe"
  - `SandboxExecutor` — Docker, no network, bounded CPU/mem/PID/time,
    non-destructive marker payloads only
  - `Classifier` — assigns final `Classification` + `Confidence`
  - `Reporter` — HTML + JSON mandatory, SARIF 2.1.0 when data is compatible

New analyzer/framework/SCA-provider/reporter support = implement one
interface. Never bend the core model to fit a new tool.

## Evidence schema (`Finding`)

- `Classification`: `CONFIRMED`, `REACHABLE`, `POTENTIALLY_REACHABLE`,
  `NOT_OBSERVED`, `INCONCLUSIVE`
- `Confidence`: `LOW` / `MEDIUM` / `HIGH`
- `Severity`: `CRITICAL` … `INFO`
- Provenance kept on every finding: tool, rule id or CVE, severity, source
  location, sink, user-input source, reachability path, package/import/symbol
  evidence, generated harness/request, expected vs. observed behavior, logs,
  final classification + confidence. Every classification must be traceable
  back to this evidence.

## Standards to follow

CWE + OWASP for vulnerability classification. CycloneDX as canonical SBOM
format. Package URL (purl) for package identity. CVE/CVSS preserved as
provided. SARIF 2.1.0 for compatible static-analysis interchange. JSON as
canonical internal/export format. PEP 8-compatible, typed interfaces.

## Work package schedule (fixed commitments — treat as deadlines, not estimates)

| WP | Scope | Window |
|----|-------|--------|
| WP0 | Requirements, evidence schema, FastAPI fixtures, modular architecture | 2026-09-14 → 2027-01-11 (ongoing baseline) |
| WP1 | Static pipeline: Semgrep/Bandit/CodeQL adapters, sinks, reachability | 2026-09-14 → 2026-10-04 |
| WP2 | SBOM/SCA pipeline | 2026-09-28 → 2026-10-25 |
| WP3 | Docker validation, classification engine, Report 1/2 + unified Report 3 | 2026-10-12 → 2026-11-15 |
| WP4 | Benchmark evaluation, hardening | 2026-11-02 → 2026-11-29 |
| WP5 | Final release, docs, poster | 2026-11-23 → 2027-01-11 |

Deliverable due dates and live status: `.claude/PROGRESS.md` (that file
changes often, this one shouldn't).

**Explicitly out of scope for the MVP** (don't build these unless asked):
git-diff regression logic, unrestricted exploitation, general whole-program
taint analysis, multiple production framework adapters. The adapter
architecture exists so these can be added later without a rewrite.

## Ethical/legal constraints — hard rules, not suggestions

- Evaluate **only** on local intentionally-vulnerable apps or explicitly
  authorized fixtures (see `fixtures/vulnerable_fastapi/`). Never scan public
  or real targets, never validate real credentials, never build unrestricted
  exploit chains, never auto-submit findings to external systems.
- Docker PoC execution: no external network, bounded CPU/mem/PID/time,
  disposable fixtures, non-destructive marker payloads only.
- `NOT_OBSERVED` / `INCONCLUSIVE` must never be silently treated as "safe" —
  always surface the explicit classification and confidence.

## Repo conventions

- Python `src` layout, package `sectestgen`, installed editable:
  `python3 -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]"`.
- Tests: `pytest` (repo root is on `pythonpath`, so `fixtures.*` imports work
  directly from `tests/`).
- Benchmark fixture: `fixtures/vulnerable_fastapi/` — one `VULNERABLE` +
  one `SAFE` endpoint per sink category, ground truth in
  `fixtures/vulnerable_fastapi/ground_truth.json`.
- Git commits: **no AI/Claude co-author attribution line** (explicit user
  preference).
- Proposal/final-report `.docx` files are intentionally untracked
  (`.gitignore`); this file + `.claude/PROGRESS.md` are the durable
  substitute so a fresh session never needs them re-read.
- GitHub: https://github.com/zer0dayf/sectestgen (`master`).
