# vulnerable_fastapi

Intentionally vulnerable FastAPI application used as a benchmark fixture for
sectestgen's static and sandbox pipelines. **Local, offline use only — never
deploy this or expose it to a network.**

Each vulnerability class has a `VULNERABLE` endpoint and a `SAFE` counterpart
of the same shape, so the reachability engine and benchmark runner have both
positive and negative cases. Ground truth (CWE, sink type, source type) is
machine-readable in `ground_truth.json`.

| Vulnerable endpoint | Safe counterpart | CWE | Sink |
|---|---|---|---|
| `GET /ping/{host}` | `GET /ping-safe/{host}` | CWE-78 | OS command injection |
| `POST /calc` | `POST /calc-safe` | CWE-95 | Dynamic evaluation (`eval`) |
| `GET /profile` (cookie) | `GET /profile-safe` | CWE-502 | Unsafe deserialization (`pickle`) |
| `GET /files` | `GET /files-safe` | CWE-22 | Path traversal |
| `GET /users/search` | `GET /users/search-safe` | CWE-89 | SQL injection |

## Run it manually

```bash
uvicorn fixtures.vulnerable_fastapi.app:app --reload
```

## Run the fixture's own tests

```bash
pytest tests/test_vulnerable_fixture.py -v
```

These tests prove each vulnerable endpoint is actually exploitable and each
safe counterpart actually blocks the same attack — they are the ground truth
the static/reachability adapters (WP1) will be scored against.
