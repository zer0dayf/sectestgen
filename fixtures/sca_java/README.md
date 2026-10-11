# sca_java

SCA benchmark fixture for the Java/Maven ecosystem. **Local, offline use only
— never build, deploy, or expose this to a network.** The sources are only
read as text by sectestgen; they are never compiled or executed.

`pom.xml` pins known-vulnerable versions on purpose. `sbom.cdx.json` is a
CycloneDX 1.5 BOM with an embedded `vulnerabilities` section (the shape
Dependency-Track exports), and `grype.json` reports two of the same issues
under different ids so de-duplication is exercised. Both are **hand-written
fixture data**, not the output of a real scan.

| Package | Advisory | How the app uses it | Expected |
|---|---|---|---|
| log4j-core 2.14.1 | CVE-2021-44228 | referenced in `@RestController` (`GET /greet`) | `POTENTIALLY_REACHABLE` / MEDIUM |
| commons-text 1.9 | CVE-2022-42889 | referenced in a helper no controller calls | `POTENTIALLY_REACHABLE` / LOW |
| jackson-databind 2.9.8 | CVE-2019-12384 | direct dependency, never imported | `NOT_OBSERVED` / MEDIUM |

Machine-readable ground truth: `ground_truth.json`.
