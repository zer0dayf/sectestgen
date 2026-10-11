"""JSON and HTML Reporters for Report 1 (static) and Report 2 (SCA).

JSON is the canonical/machine-readable output; HTML is the human-readable
view. Both consume the same `Finding` list so they can never disagree.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Iterable

from sectestgen.core.adapters import Reporter
from sectestgen.core.models import Finding, Pipeline

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class JSONReporter(Reporter):
    def generate(self, findings: Iterable[Finding], output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        payload = [finding.to_dict() for finding in findings]
        output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return output_path


_STATIC_HEADERS = ["Tool", "Rule", "Severity", "Location", "Sink / Source", "Reachability", "Classification"]
_SCA_HEADERS = ["Tool", "Advisory", "Severity", "Package", "Fixed in", "Usage evidence", "Classification"]
_TITLES = {
    Pipeline.STATIC: ("Report 1 (Static)", "Report 1 (Static Pipeline)"),
    Pipeline.SCA: ("Report 2 (SCA)", "Report 2 (SCA Pipeline)"),
}


class HTMLReporter(Reporter):
    def __init__(self, pipeline: Pipeline = Pipeline.STATIC) -> None:
        self.pipeline = pipeline

    def generate(self, findings: Iterable[Finding], output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        rows = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity.value, 9))
        output_path.write_text(_render(rows, self.pipeline), encoding="utf-8")
        return output_path


def _render(findings: list[Finding], pipeline: Pipeline) -> str:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.classification.value] = counts.get(finding.classification.value, 0) + 1
    summary = " &nbsp;·&nbsp; ".join(f"{k}: {v}" for k, v in sorted(counts.items())) or "no findings"

    render_row = _render_sca_row if pipeline is Pipeline.SCA else _render_row
    headers = _SCA_HEADERS if pipeline is Pipeline.SCA else _STATIC_HEADERS
    header_cells = "".join(f"<th>{h}</th>" for h in headers)
    page_title, heading = _TITLES[pipeline]
    body_rows = "\n".join(render_row(f) for f in findings) or (
        f'<tr><td colspan="{len(headers)}" class="empty">No findings.</td></tr>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SecTestGen — {page_title}</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; background: #fafafa; }}
  h1 {{ margin-bottom: 0.25rem; }}
  .summary {{ color: #444; margin-bottom: 1.5rem; }}
  table {{ border-collapse: collapse; width: 100%; background: #fff; }}
  th, td {{ border: 1px solid #ddd; padding: 0.5rem 0.75rem; text-align: left; vertical-align: top; font-size: 0.9rem; }}
  th {{ background: #222; color: #fff; }}
  tr:nth-child(even) {{ background: #f3f3f3; }}
  .empty {{ text-align: center; color: #777; }}
  code {{ font-size: 0.85em; }}
  .sev-CRITICAL, .sev-HIGH {{ color: #b00020; font-weight: 600; }}
  .sev-MEDIUM {{ color: #a66a00; font-weight: 600; }}
  .sev-LOW, .sev-INFO {{ color: #444; }}
  .cls-REACHABLE {{ color: #b00020; font-weight: 600; }}
  .cls-POTENTIALLY_REACHABLE {{ color: #a66a00; font-weight: 600; }}
  .cls-NOT_OBSERVED {{ color: #1a7f37; }}
  .cls-INCONCLUSIVE {{ color: #555; }}
</style>
</head>
<body>
<h1>SecTestGen — {heading}</h1>
<p class="summary">{len(findings)} finding(s) &nbsp;·&nbsp; {summary}</p>
<table>
<thead>
<tr>{header_cells}</tr>
</thead>
<tbody>
{body_rows}
</tbody>
</table>
</body>
</html>
"""


def _render_row(finding: Finding) -> str:
    loc = finding.location
    location = f"{html.escape(loc.file_path)}:{loc.line}" if loc else "-"
    sink_source = html.escape(
        f"sink={finding.sink or '-'} / source={finding.user_input_source or '-'}"
    )
    notes = html.escape(finding.reachability.notes or "") if finding.reachability else ""
    reachable = finding.reachability.reachable if finding.reachability else None
    reachable_label = {True: "True", False: "False", None: "Unknown"}[reachable]

    return (
        "<tr>"
        f"<td>{html.escape(finding.tool)}</td>"
        f"<td><code>{html.escape(finding.rule_id or finding.title)}</code></td>"
        f"<td class=\"sev-{finding.severity.value}\">{finding.severity.value}</td>"
        f"<td><code>{location}</code></td>"
        f"<td>{sink_source}</td>"
        f"<td>{reachable_label}<br><small>{notes}</small></td>"
        f"<td class=\"cls-{finding.classification.value}\">{finding.classification.value}"
        f"<br><small>confidence: {finding.confidence.value}</small></td>"
        "</tr>"
    )


def _render_sca_row(finding: Finding) -> str:
    usage = finding.raw.get("usage") or {}
    advisory = finding.cve or finding.rule_id or finding.title
    if finding.rule_id and finding.rule_id != advisory:
        advisory = f"{advisory} ({finding.rule_id})"
    also = finding.raw.get("also_reported_by") or []
    tools = ", ".join([finding.tool, *also])
    scope = {True: "direct", False: "transitive", None: "scope unknown"}[usage.get("direct")]
    package = f"{finding.package_name}@{finding.package_version}<br><small><code>{html.escape(finding.purl or '-')}</code> · {scope}</small>"
    evidence_lines = finding.reachability.path if finding.reachability else []
    notes = html.escape(finding.reachability.notes or "") if finding.reachability else ""
    evidence = "<br>".join(f"<code>{html.escape(line)}</code>" for line in evidence_lines)

    return (
        "<tr>"
        f"<td>{html.escape(tools)}</td>"
        f"<td><code>{html.escape(advisory)}</code></td>"
        f"<td class=\"sev-{finding.severity.value}\">{finding.severity.value}</td>"
        f"<td>{package}</td>"
        f"<td>{html.escape(finding.fixed_version or '-')}</td>"
        f"<td>{html.escape(usage.get('status', '-'))}<br><small>{notes}</small>"
        f"{'<br>' + evidence if evidence else ''}</td>"
        f"<td class=\"cls-{finding.classification.value}\">{finding.classification.value}"
        f"<br><small>confidence: {finding.confidence.value}</small></td>"
        "</tr>"
    )
