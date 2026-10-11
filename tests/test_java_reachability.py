from pathlib import Path

from sectestgen.adapters.classifier import DefaultClassifier
from sectestgen.adapters.java_reachability import JavaReachabilityEngine
from sectestgen.adapters.spring_adapter import SpringFrameworkAdapter
from sectestgen.core.models import Classification, Finding, Pipeline, SourceLocation

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "vulnerable_spring"

SAMPLE = """\
@RestController
public class Ctl {
    private String configured = "ls";

    @GetMapping("/reachable/{host}")
    public String reachable(@PathVariable String host) throws Exception {
        String command = "ping -c 1 " + host;
        Runtime.getRuntime().exec(command);
        return "ok";
    }

    @GetMapping("/literal")
    public String literal(@RequestParam String name) throws Exception {
        Runtime.getRuntime().exec("ls -la");
        return name;
    }

    @GetMapping("/field")
    public String field(@RequestParam String name) throws Exception {
        Runtime.getRuntime().exec(this.configured);
        return name;
    }

    @PostMapping("/multiline")
    public Object multiline(@RequestBody Req req) {
        return new SpelExpressionParser()
            .parseExpression(
                req.expression())
            .getValue();
    }

    @GetMapping("/member-name")
    public String memberName(@RequestParam String name) throws Exception {
        Runtime.getRuntime().exec(this.name);
        return "x";
    }

    String helper(String input) throws Exception {
        Runtime.getRuntime().exec(input);
        return input;
    }
}
"""


def _analyze(tmp_path: Path, line: int) -> Finding:
    java_file = tmp_path / "Ctl.java"
    java_file.write_text(SAMPLE, encoding="utf-8")
    routes = list(SpringFrameworkAdapter().discover_routes(tmp_path))
    finding = Finding(
        id="f",
        pipeline=Pipeline.STATIC,
        tool="semgrep",
        location=SourceLocation(file_path=str(java_file), line=line),
    )
    JavaReachabilityEngine(routes).analyze(finding, tmp_path)
    return DefaultClassifier().classify(finding)


def test_reachable_through_local_variable(tmp_path):
    finding = _analyze(tmp_path, 8)

    assert finding.reachability.reachable is True
    assert finding.classification is Classification.REACHABLE
    assert finding.raw["route"] == "GET /reachable/{host}"
    assert finding.user_input_source == "GET /reachable/{host} :: path:host"
    assert finding.reachability.path == ["path:host", "reachable() line 8"]


def test_not_observed_when_sink_args_are_literal(tmp_path):
    finding = _analyze(tmp_path, 14)

    assert finding.reachability.reachable is False
    assert finding.classification is Classification.NOT_OBSERVED


def test_field_argument_is_unresolved_not_safe(tmp_path):
    finding = _analyze(tmp_path, 20)

    assert finding.reachability.reachable is None
    assert finding.classification is Classification.POTENTIALLY_REACHABLE


def test_multiline_call_reported_on_end_line(tmp_path):
    # Semgrep reports the end line of a multi-line match.
    finding = _analyze(tmp_path, 29)

    assert finding.reachability.reachable is True


def test_member_with_same_name_as_parameter_is_not_taint(tmp_path):
    finding = _analyze(tmp_path, 34)

    assert finding.reachability.reachable is None


def test_sink_outside_route_is_inconclusive(tmp_path):
    finding = _analyze(tmp_path, 39)

    assert finding.raw["entry_point"] is False
    assert finding.classification is Classification.INCONCLUSIVE


def test_all_vulnerable_fixture_sinks_are_reachable():
    # Sink lines of the five VULNERABLE endpoints (see ground_truth.json).
    sinks = {
        "UserController.java": [(28, "GET /users/search")],
        "VulnerableController.java": [
            (44, "GET /api/ping/{host}"),
            (61, "POST /api/calc"),
            (81, "GET /api/profile"),
            (95, "GET /api/files"),
        ],
    }
    routes = list(SpringFrameworkAdapter().discover_routes(FIXTURE))
    engine = JavaReachabilityEngine(routes)
    source_dir = FIXTURE / "src" / "main" / "java" / "com" / "example" / "vulnspring"

    for file_name, entries in sinks.items():
        for line, route in entries:
            finding = Finding(
                id=f"{file_name}:{line}",
                pipeline=Pipeline.STATIC,
                tool="semgrep",
                location=SourceLocation(file_path=str(source_dir / file_name), line=line),
            )
            engine.analyze(finding, FIXTURE)
            assert finding.raw["route"] == route
            assert finding.reachability.reachable is True, (file_name, line, finding.reachability.notes)
