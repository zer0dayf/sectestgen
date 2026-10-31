"""JSON and HTML Reporters for Report 1 (static), Report 2 (SCA) and the
unified Report 3.

JSON is the canonical/machine-readable output; HTML is the human-readable
view. Both consume the same `Finding` (or `Issue`) list so they can never
disagree.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

from sectestgen.core.adapters import Reporter
from sectestgen.core.models import Finding, Pipeline

if TYPE_CHECKING:
    from sectestgen.unified import Issue

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class JSONReporter(Reporter):
    def generate(self, findings: Iterable[Finding], output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        payload = [finding.to_dict() for finding in findings]
        output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return output_path


_STATIC_HEADERS = ["Tool", "Rule", "Severity", "Location", "Sink / Source", "Reachability", "Runtime", "Classification"]
_SCA_HEADERS = ["Tool", "Advisory", "Severity", "Package", "Fixed in", "Usage evidence", "Runtime", "Classification"]
_ISSUE_HEADERS = ["Issue", "Severity", "Location / route", "Evidence", "Classification"]
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


class JSONIssueReporter:
    """Report 3 (JSON): one entry per de-duplicated issue, members embedded."""

    def generate(self, issues: Iterable[Issue], output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps([i.to_dict() for i in issues], indent=2), encoding="utf-8")
        return output_path


class HTMLIssueReporter:
    def generate(self, issues: Iterable[Issue], output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        issues = list(issues)
        member_count = sum(len(i.members) for i in issues)
        summary = _summary(i.classification.value for i in issues)
        page = _page(
            "Report 3 (Unified)",
            "Report 3 (Unified, de-duplicated)",
            f"{len(issues)} issue(s) from {member_count} finding(s) &nbsp;·&nbsp; {summary}",
            _ISSUE_HEADERS,
            [_render_issue_row(i) for i in issues],
        )
        output_path.write_text(page, encoding="utf-8")
        return output_path


def _summary(values: Iterable[str]) -> str:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return " &nbsp;·&nbsp; ".join(f"{k}: {v}" for k, v in sorted(counts.items())) or "no findings"


def _render(findings: list[Finding], pipeline: Pipeline) -> str:
    render_row = _render_sca_row if pipeline is Pipeline.SCA else _render_row
    headers = _SCA_HEADERS if pipeline is Pipeline.SCA else _STATIC_HEADERS
    page_title, heading = _TITLES[pipeline]
    summary = _summary(f.classification.value for f in findings)
    return _page(page_title, heading, f"{len(findings)} finding(s) &nbsp;·&nbsp; {summary}", headers,
                 [render_row(f) for f in findings])


def _page(page_title: str, heading: str, summary: str, headers: list[str], rows: list[str]) -> str:
    header_cells = "".join(f"<th>{h}</th>" for h in headers)
    body_rows = "\n".join(rows) or f'<tr><td colspan="{len(headers)}" class="empty">No findings.</td></tr>'
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
  .cls-CONFIRMED {{ color: #fff; background: #b00020; font-weight: 700; }}
  .cls-REACHABLE {{ color: #b00020; font-weight: 600; }}
  .cls-POTENTIALLY_REACHABLE {{ color: #a66a00; font-weight: 600; }}
  .cls-NOT_OBSERVED {{ color: #1a7f37; }}
  .cls-INCONCLUSIVE {{ color: #555; }}
  .rt-yes {{ color: #b00020; font-weight: 600; }}
  .rt-no {{ color: #1a7f37; }}
  details pre {{ white-space: pre-wrap; font-size: 0.8em; max-width: 40rem; }}
</style>
</head>
<body>
<h1>SecTestGen — {heading}</h1>
<p class="summary">{summary}</p>
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
        f"<td>{_runtime_cell(finding)}</td>"
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
    status = usage.get("status", "-")
    if usage.get("symbol_status"):
        status = f"{status} / {usage['symbol_status']}"
    symbols = usage.get("symbols") or {}
    if symbols.get("known"):
        evidence += (
            f"<br><small>vulnerable symbols ({html.escape(', '.join(symbols.get('sources', [])))}): "
            f"{html.escape(', '.join(symbols['known']))}</small>"
        )

    return (
        "<tr>"
        f"<td>{html.escape(tools)}</td>"
        f"<td><code>{html.escape(advisory)}</code></td>"
        f"<td class=\"sev-{finding.severity.value}\">{finding.severity.value}</td>"
        f"<td>{package}</td>"
        f"<td>{html.escape(finding.fixed_version or '-')}</td>"
        f"<td>{html.escape(status)}<br><small>{notes}</small>"
        f"{'<br>' + evidence if evidence else ''}</td>"
        f"<td>{_runtime_cell(finding)}</td>"
        f"<td class=\"cls-{finding.classification.value}\">{finding.classification.value}"
        f"<br><small>confidence: {finding.confidence.value}</small></td>"
        "</tr>"
    )


def _runtime_cell(finding: Finding) -> str:
    runtime = finding.runtime
    if runtime is None:
        return "-"
    label, css = {True: ("observed", "rt-yes"), False: ("not observed", "rt-no"), None: ("not validated", "")}[
        runtime.observed
    ]
    parts = [f'<span class="{css}">{label}</span>']
    if runtime.observed_behavior:
        parts.append(f"<small>{html.escape(runtime.observed_behavior)}</small>")
    if runtime.expected_behavior:
        parts.append(f"<small>expected: {html.escape(runtime.expected_behavior)}</small>")
    details = []
    if runtime.request:
        details.append("request: " + json.dumps(runtime.request, indent=1))
    if runtime.logs:
        details.append(runtime.logs)
    if details:
        parts.append(f"<details><summary>evidence</summary><pre>{html.escape(chr(10).join(details))}</pre></details>")
    return "<br>".join(parts)


def _render_issue_row(issue: Issue) -> str:
    data = issue.to_dict()
    where = html.escape(data["location"] or "-")
    if data["route"]:
        where += f"<br><small>{html.escape(data['route'])}</small>"
    evidence = []
    for member in issue.members:
        also = member.raw.get("also_reported_by") or []
        tools = ", ".join([member.tool, *also])
        what = member.cve or member.rule_id or member.title
        note = member.reachability.notes if member.reachability else ""
        runtime = ""
        if member.runtime is not None:
            runtime = {True: " · runtime: observed", False: " · runtime: not observed", None: " · runtime: not validated"}[
                member.runtime.observed
            ]
        evidence.append(
            f"<code>{html.escape(tools)}</code> {html.escape(what or '')} "
            f"<span class=\"cls-{member.classification.value}\">{member.classification.value}</span>"
            f"<br><small>{html.escape(note or '')}{html.escape(runtime)}</small>"
        )
    return (
        "<tr>"
        f"<td>{html.escape(data['title'])}<br><small>{', '.join(data['pipelines'])}</small></td>"
        f"<td class=\"sev-{data['severity']}\">{data['severity']}</td>"
        f"<td><code>{where}</code></td>"
        f"<td>{'<br>'.join(evidence)}</td>"
        f"<td class=\"cls-{data['classification']}\">{data['classification']}"
        f"<br><small>confidence: {data['confidence']}</small></td>"
        "</tr>"
    )
