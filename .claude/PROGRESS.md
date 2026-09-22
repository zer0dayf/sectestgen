# SecTestGen — Progress Tracker

Bu dosya oturumlar arasında "nerede kaldık"ı takip etmek için var. Proposal ve
final report şablonu .docx dosyaları repo dışında tutuluyor (bkz. `.gitignore`);
deadline/deliverable özeti burada.

## Deliverables (proposal'dan özet)

| ID | Tür | Açıklama | Tarih | Durum |
|----|-----|----------|-------|-------|
| D1 | Document | Draft proposal | 2026-09-21 | done (repo öncesi teslim edildi) |
| D2 | Software | Static MVP: Semgrep/Bandit/CodeQL adapter, source/sink, reachability, Report 1 | 2026-10-18 | in progress |
| D3 | Software | SCA MVP: CycloneDX + Dependency-Track/Snyk/Grype, Report 2 | 2026-11-01 | not started |
| D4 | Software | Docker PoC validation, classification engine, unified Report 3 | 2026-11-15 | not started |
| D5 | Software | Adapter hardening, HTML/JSON/SARIF, dedup, benchmark runner, packaged CLI | 2026-11-29 | not started |
| D6 | Document | Intermediate report, benchmark results | 2026-12-16 | not started |
| D7 | Software | Final release, final report, docs, poster | 2026-12-23 / 2027-01-11 | not started |

## Yapılanlar

- 2026-09-22 — WP0 iskeleti kuruldu: normalize `Finding`/evidence şeması
  (`src/sectestgen/core/models.py`), 7 adapter arayüzü
  (`src/sectestgen/core/adapters.py`: StaticAnalyzerAdapter, SCAAdapter,
  FrameworkAdapter, ReachabilityEngine, SandboxExecutor, Classifier, Reporter),
  stub CLI (`static`/`sca` alt komutları), 4 test, `.venv`.
- 2026-09-22 — GitHub'a pushlandı: https://github.com/zer0dayf/sectestgen (master).
- 2026-09-22 — Proposal/final-report .docx dosyaları repodan çıkarıldı (gitignore),
  commit'lere AI co-author satırı eklenmemesi kararlaştırıldı.

## Yapılacaklar (sıradaki adımlar, WP1 — 2026-10-18)

- [ ] Kasıtlı zafiyetli minimal FastAPI fixture (test hedefi olarak)
- [ ] `StaticAnalyzerAdapter` → Semgrep implementasyonu (JSON çıktısını `Finding`'e çevir)
- [ ] `StaticAnalyzerAdapter` → Bandit implementasyonu
- [ ] `FrameworkAdapter` → FastAPI route/user-input source keşfi
- [ ] Bounded `ReachabilityEngine` (AST/import/call tabanlı, INCONCLUSIVE fallback)
- [ ] `Reporter` → Report 1 (JSON + HTML)

## Notlar / kararlar

- Commit mesajlarına Claude/AI co-author satırı **eklenmiyor** (kullanıcı isteği, 2026-09-22).
- `.docx` dosyaları repo'ya commit edilmiyor; bu dosya onların yerine geçen özet.
