# vulnerable_spring

Intentionally vulnerable Spring Boot application used as the Java benchmark
fixture for sectestgen's static pipeline. **Local, offline use only — never
deploy this or expose it to a network.** The test suite only reads these
sources as text (tree-sitter / Semgrep); nothing is compiled or run.

Each vulnerability class has a `VULNERABLE` endpoint and a `SAFE`
counterpart of the same shape. Ground truth is in `ground_truth.json`.

| Vulnerable endpoint | Safe counterpart | CWE | Sink | Source |
|---|---|---|---|---|
| `GET /api/ping/{host}` | `GET /api/ping-safe/{host}` | CWE-78 | `Runtime.exec` with a concatenated command | path |
| `POST /api/calc` | `POST /api/calc-safe` | CWE-95 | SpEL `parseExpression` | body |
| `GET /api/profile` | `GET /api/profile-safe` | CWE-502 | `ObjectInputStream.readObject` | cookie |
| `GET /api/files` | `GET /api/files-safe` | CWE-22 | `Files.readString(base.resolve(input))` | query |
| `GET /users/search` | `GET /users/search-safe` | CWE-89 | `JdbcTemplate` with concatenated SQL | query |
