# sca_java

SCA benchmark fixture for the Java/Maven ecosystem. **Local, offline use only
— never build, deploy, or expose this to a network.** The sources are only
read as text by sectestgen; they are never compiled or executed.

`pom.xml` pins known-vulnerable versions on purpose. `sbom.cdx.json` is a
CycloneDX 1.5 BOM with an embedded `vulnerabilities` section (the shape
Dependency-Track exports), and `grype.json` / `snyk.json` report two of the
same issues under different ids so de-duplication is exercised (`snyk.json`
also carries Snyk's internal vulnerable function for log4j,
`JndiLookup.lookup`). All are **hand-written fixture data**, not the output of
a real scan.

| Package | Advisory | How the app uses it | Expected |
|---|---|---|---|
| log4j-core 2.14.1 | CVE-2021-44228 | `Logger.info` called in `@RestController` (`GET /greet`) | `REACHABLE` / MEDIUM |
| commons-text 1.9 | CVE-2022-42889 | `StringSubstitutor` used in a helper no controller calls; vulnerable `createInterpolator` not called | `POTENTIALLY_REACHABLE` / LOW |
| jackson-databind 2.9.8 | CVE-2019-12384 | direct dependency, never imported | `NOT_OBSERVED` / MEDIUM |

Vulnerable symbols come from the curated table in
`src/sectestgen/adapters/vulnerable_symbols.py` (and Snyk's `functions_new`).
Machine-readable ground truth: `ground_truth.json`.
