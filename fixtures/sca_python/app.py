"""SCA benchmark fixture (Python): a FastAPI app whose declared dependencies
include known-vulnerable versions, each used to a different degree.

- PyYAML     -> referenced inside a route handler (vulnerable call path exists)
- Jinja2     -> imported, never referenced
- requests   -> declared in requirements.txt, never imported
- urllib3    -> transitive (via requests), never imported

Expected classifications are in ground_truth.json. The SBOM and Grype
report next to this file are hand-written fixture data matching
requirements.txt; they are not output from a real scan.

Local, offline use only. Never deploy this application or expose it to
a network.
"""

from __future__ import annotations

import jinja2  # noqa: F401 - imported on purpose, never referenced
import yaml
from fastapi import Body, FastAPI

app = FastAPI(title="sectestgen SCA fixture (Python)")


@app.post("/config/parse")
def parse_config(document: str = Body(...)) -> dict:
    return {"parsed": yaml.load(document, Loader=yaml.FullLoader)}


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
