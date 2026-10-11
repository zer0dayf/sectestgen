# sca_python

SCA benchmark fixture for the Python ecosystem. **Local, offline use only —
never deploy this or expose it to a network.**

`requirements.txt` pins known-vulnerable versions on purpose. `sbom.cdx.json`
(CycloneDX 1.5) and `grype.json` (Grype JSON output shape) are **hand-written
fixture data** matching those pins — they are not the output of a real scan,
and only list the advisories this benchmark scores against.

| Package | Advisory | How the app uses it | Expected |
|---|---|---|---|
| PyYAML 5.3.1 | CVE-2020-14343 | referenced inside `POST /config/parse` | `POTENTIALLY_REACHABLE` / MEDIUM |
| Jinja2 2.10 | CVE-2019-10906 | imported, never referenced | `NOT_OBSERVED` / LOW |
| requests 2.19.1 | CVE-2018-18074 | direct dependency, never imported | `NOT_OBSERVED` / MEDIUM |
| urllib3 1.23 | CVE-2019-11324 | transitive (via requests), never imported | `NOT_OBSERVED` / LOW |

Machine-readable ground truth: `ground_truth.json`.
