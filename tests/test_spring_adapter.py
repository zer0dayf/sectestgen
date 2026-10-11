import json
from pathlib import Path

from sectestgen.adapters.spring_adapter import SpringFrameworkAdapter

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "vulnerable_spring"
GROUND_TRUTH = json.loads((FIXTURE / "ground_truth.json").read_text(encoding="utf-8"))


def _routes(target: Path) -> dict[str, dict]:
    return {route["path"]: route for route in SpringFrameworkAdapter().discover_routes(target)}


def _write(tmp_path: Path, source: str) -> Path:
    path = tmp_path / "Ctl.java"
    path.write_text(source, encoding="utf-8")
    return tmp_path


def test_discovers_every_route_in_ground_truth():
    routes = _routes(FIXTURE)

    assert set(routes) == {entry["path"] for entry in GROUND_TRUTH}
    for entry in GROUND_TRUTH:
        route = routes[entry["path"]]
        assert route["method"] == entry["method"], entry["path"]
        assert [s["kind"] for s in route["sources"]] == [entry["source_type"]], entry["path"]
        assert route["framework"] == "spring"


def test_class_level_prefix_is_joined_and_line_range_covers_method():
    route = _routes(FIXTURE)["/api/profile"]

    assert route["function"] == "profile"
    assert route["file_path"].endswith("VulnerableController.java")
    assert route["start_line"] < route["end_line"]
    assert route["sources"][0]["binding"] == "profile"


def test_request_mapping_method_and_multiple_paths(tmp_path):
    target = _write(
        tmp_path,
        """
        @Controller
        @RequestMapping({"/v1", "/v2"})
        class Ctl {
            @RequestMapping(value = "/items", method = {RequestMethod.GET, RequestMethod.POST})
            String items(@RequestParam("q") String query) { return query; }

            @RequestMapping("/any")
            String any() { return "x"; }
        }
        """,
    )
    routes = list(SpringFrameworkAdapter().discover_routes(target))

    pairs = {(r["method"], r["path"]) for r in routes}
    assert pairs == {
        ("GET", "/v1/items"), ("POST", "/v1/items"), ("GET", "/v2/items"), ("POST", "/v2/items"),
        ("ANY", "/v1/any"), ("ANY", "/v2/any"),
    }
    items = next(r for r in routes if r["path"] == "/v1/items")
    assert items["sources"] == [{"name": "query", "kind": "query", "field": None, "binding": "q"}]


def test_unannotated_framework_and_request_parameters(tmp_path):
    target = _write(
        tmp_path,
        """
        @RestController
        class Ctl {
            @PostMapping("/x")
            String x(String plain, Model model, HttpServletRequest request,
                     @RequestHeader("X-Token") String token, Principal principal) {
                return plain;
            }
        }
        """,
    )
    route = next(iter(SpringFrameworkAdapter().discover_routes(target)))

    assert [(s["name"], s["kind"]) for s in route["sources"]] == [
        ("plain", "query"),
        ("request", "request"),
        ("token", "header"),
    ]


def test_ignores_classes_that_are_not_controllers(tmp_path):
    target = _write(
        tmp_path,
        """
        @Service
        class NotACtl {
            @GetMapping("/looks-like-a-route")
            String f(String q) { return q; }
        }
        """,
    )
    assert list(SpringFrameworkAdapter().discover_routes(target)) == []


def test_skips_non_java_and_unparseable_files(tmp_path):
    (tmp_path / "notes.txt").write_text("@RestController", encoding="utf-8")
    (tmp_path / "Broken.java").write_text("@RestController class {{{", encoding="utf-8")

    assert list(SpringFrameworkAdapter().discover_routes(tmp_path)) == []
