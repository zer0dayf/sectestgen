import json
import re
from pathlib import Path

from sectestgen.adapters.fastapi_adapter import FastAPIFrameworkAdapter

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "vulnerable_fastapi"
GROUND_TRUTH = json.loads((FIXTURE / "ground_truth.json").read_text(encoding="utf-8"))

# ground_truth.json uses the bare param name ("/ping/{host}"); the source
# uses FastAPI path-converter syntax ("/ping/{host:path}"). Normalize both
# to the same shorthand before comparing.
_CONVERTER_RE = re.compile(r":[^}]+(?=})")


def _routes_by_path() -> dict[str, dict]:
    routes = list(FastAPIFrameworkAdapter().discover_routes(FIXTURE))
    return {_CONVERTER_RE.sub("", route["path"]): route for route in routes}


def test_discovers_every_route_in_ground_truth():
    routes = _routes_by_path()
    for entry in GROUND_TRUTH:
        assert entry["path"] in routes, f"missing route {entry['path']}"
        assert routes[entry["path"]]["method"] == entry["method"]


def test_source_kind_matches_ground_truth_for_vulnerable_endpoints():
    routes = _routes_by_path()
    for entry in GROUND_TRUTH:
        if not entry["vulnerable"]:
            continue
        route = routes[entry["path"]]
        assert route["sources"], f"no sources discovered for {entry['path']}"
        kinds = {source["kind"] for source in route["sources"]}
        assert entry["source_type"] in kinds


def test_body_source_captures_pydantic_model_field():
    routes = _routes_by_path()
    calc_sources = routes["/calc"]["sources"]
    assert {"name": "payload", "kind": "body", "field": "expression"} in calc_sources
