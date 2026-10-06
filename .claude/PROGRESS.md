# SecTestGen — Progress Tracker

Bu dosya oturumlar arasında "nerede kaldık"ı takip etmek için var. Proposal ve
final report şablonu .docx dosyaları repo dışında tutuluyor (bkz. `.gitignore`);
deadline/deliverable özeti burada.

## Deliverables (proposal'dan özet)

| ID | Tür | Açıklama | Tarih | Durum |
|----|-----|----------|-------|-------|
| D1 | Document | Draft proposal | 2026-09-21 | done (repo öncesi teslim edildi) |
| D2 | Software | Static MVP: Semgrep/Bandit/CodeQL adapter, source/sink, reachability, Report 1 | 2026-10-18 | done (CodeQL deferred, see notes) |
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
- 2026-09-22 — Kasıtlı zafiyetli FastAPI fixture'ı yazıldı
  (`fixtures/vulnerable_fastapi/app.py`): proposal'daki 5 sink kategorisinin
  (CWE-78 command execution, CWE-95 dynamic eval, CWE-502 unsafe deserialization,
  CWE-22 path traversal, CWE-89 SQL injection) her biri için bir VULNERABLE + bir
  SAFE endpoint, makine-okunur ground truth (`ground_truth.json`), ve her ikisinin
  de gerçekten çalıştığını/engellendiğini kanıtlayan 17 test
  (`tests/test_vulnerable_fixture.py`, hepsi geçiyor).

- 2026-10-06 — **WP1 implementasyonu tamamlandı** (D2, 2026-10-18 — proposal'daki
  WP1 penceresi 2026-09-14→2026-10-04'tü, bu commit o pencereden sonra ama D2
  teslim tarihinden 12 gün önce girdi):
  - `src/sectestgen/adapters/semgrep_adapter.py`, `bandit_adapter.py` — her ikisi
    de CLI aracını subprocess ile çalıştırıp `Finding`'e normalize ediyor.
  - `rules/semgrep/fastapi_security.yml` — projeye özel Semgrep kural seti (5 sink
    kategorisi: CWE-78/95/502/22/89), `auto` registry yerine varsayılan config —
    deterministik ve offline çalışıyor.
  - `src/sectestgen/adapters/cwe_map.py` — CWE → sink_type ortak eşlemesi
    (Bandit'in kendi CWE etiketi bazen yanlış; örn. B307/eval → CWE-78 diyor,
    bu yüzden Bandit için test_id öncelikli bir override tablosu da var).
  - `src/sectestgen/adapters/fastapi_adapter.py` — sadece AST ile (hiçbir kod
    import/execute edilmeden) route + user-input source keşfi
    (path/query/cookie/header/body, pydantic `BaseModel` alanları dahil).
  - `src/sectestgen/adapters/reachability.py` — bounded, tek-fonksiyon
    taint analizi (doğrudan referans + tek adım `x = <tainted ifade>`
    propagation). Üç sonuç: `True`/`False`/`None`; `None` + route eşleşmesi
    varsa `POTENTIALLY_REACHABLE`, yoksa `INCONCLUSIVE`. `CONFIRMED` hiç
    atanmıyor (sandbox/WP3 kanıtı gerektiriyor, proposal'a uygun).
  - `src/sectestgen/adapters/classifier.py`, `reporter.py` (JSON+HTML),
    `src/sectestgen/pipeline.py` (orkestrasyon) — `cli.py`'deki `static`
    komutu artık gerçek pipeline'ı çalıştırıyor (stub değil).
  - `fixtures/vulnerable_fastapi/` üzerinde doğrulandı: 5 vulnerable endpoint'in
    tamamı doğru route/source ile REACHABLE olarak sınıflandırılıyor.
  - 24 yeni test eklendi (toplam 42, hepsi geçiyor): `test_fastapi_adapter.py`,
    `test_reachability.py`, `test_classifier.py`, `test_reporter.py`,
    `test_cwe_map.py`, `test_semgrep_adapter.py` (tool yoksa skip),
    `test_bandit_adapter.py` (tool yoksa skip).
  - `tests/test_vulnerable_fixture.py` içindeki OS'a özgü (`touch`, Unix shell)
    command-injection testi Windows uyumlu hale getirildi (`os.name` kontrolü).
  - CodeQL adapter'ı bilinçli olarak ertelendi: CLI kurulumu/lisans/query-pack
    gereksinimi WP1 penceresi için orantısız; Semgrep+Bandit zaten proposal'daki
    5 sink kategorisinin tamamını kapsıyor. D2'de "Software" teslimatı olarak
    yeterli; final raporda "sınırlama" olarak not edilmeli (bkz. proposal'daki
    CodeQL "optional" ifadesi).
  - `.venv` içine `semgrep` kurulduğunda bu makinede Windows Application Control
    politikası semgrep'in native binary'sini engelliyor (ortam kısıtlaması);
    bu yüzden `.venv`'e sadece `bandit` kuruldu, `semgrep` sistem genelinde
    (global Python) kurulu olana güveniliyor. `SemgrepAdapter`/`BanditAdapter`
    `PATH`'teki ilk ikiliyi kullanıyor, bu yüzden her iki ortamda da çalışır.

## Yapılacaklar (sıradaki adımlar, WP2 — 2026-10-25)

- [ ] `SCAAdapter` → CycloneDX SBOM okuma
- [ ] `SCAAdapter` → Dependency-Track/Snyk/Grype sonuçlarını normalize et
- [ ] Paket import/sembol kullanım kontrolü (vulnerable paket gerçekten
      kullanılıyor mu)
- [ ] `Reporter` → Report 2 (JSON + HTML)
- [ ] Final raporda (Agile template, Ch4 Backlogs/Planning + Ch5 Design)
      WP0+WP1 için Product Backlog / Sprint Backlog / Sprint Review maddeleri
      ve mimari diyagramlar yazılmalı — henüz yapılmadı.

## Notlar / kararlar

- Commit mesajlarına Claude/AI co-author satırı **eklenmiyor** (kullanıcı isteği, 2026-09-22).
- `.docx` dosyaları repo'ya commit edilmiyor; bu dosya onların yerine geçen özet.
- Final rapor şablonu (Agile template) Ch4'te Product/Sprint Backlog ve Sprint
  Review istiyor; bu proje tek kişilik olduğu için "sprint"ler WP'lerle
  birebir eşleniyor — final rapor yazılırken WP0/WP1 bu bölümün girdisi olarak
  kullanılabilir.
