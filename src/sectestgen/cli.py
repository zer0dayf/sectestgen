"""Entry point for the sectestgen CLI.

Each subcommand maps to a pipeline described in the project proposal:
`static` (Semgrep/Bandit/CodeQL -> reachability -> Report 1) and
`sca` (CycloneDX/Dependency-Track/Grype -> import-usage evidence ->
Report 2).
"""

from __future__ import annotations

import argparse
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from sectestgen.pipeline import PipelineResult, run_sca_pipeline, run_static_pipeline


def _version() -> str:
    try:
        return version("sectestgen")
    except PackageNotFoundError:
        return "0.1.0-dev"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sectestgen",
        description="Modular security finding validation and evidence platform.",
    )
    parser.add_argument("--version", action="version", version=_version())

    subparsers = parser.add_subparsers(dest="command")

    static_parser = subparsers.add_parser(
        "static", help="Static-code finding validation pipeline (Semgrep/Bandit) -> Report 1."
    )
    static_parser.add_argument("target", help="Path to the FastAPI project to analyze.")
    static_parser.add_argument(
        "-o",
        "--output",
        default="sectestgen-out",
        help="Directory to write report1.json / report1.html into (default: ./sectestgen-out).",
    )

    sca_parser = subparsers.add_parser(
        "sca", help="SBOM/dependency exposure validation pipeline (CycloneDX/Grype) -> Report 2."
    )
    sca_parser.add_argument("sbom", help="Path to a CycloneDX JSON SBOM.")
    sca_parser.add_argument(
        "-s",
        "--source",
        help="Project the SBOM describes, searched for imports (default: the SBOM's directory).",
    )
    sca_parser.add_argument(
        "--grype",
        help="Pre-generated Grype JSON report (default: run `grype` from PATH if installed).",
    )
    sca_parser.add_argument(
        "-o",
        "--output",
        default="sectestgen-out",
        help="Directory to write report2.json / report2.html into (default: ./sectestgen-out).",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "static":
        result = run_static_pipeline(Path(args.target), output_dir=Path(args.output))
        _print_summary("static", "Report 1", result)
        return 0
    if args.command == "sca":
        sbom = Path(args.sbom)
        result = run_sca_pipeline(
            sbom,
            Path(args.source) if args.source else sbom.parent,
            output_dir=Path(args.output),
            grype_report=Path(args.grype) if args.grype else None,
        )
        _print_summary("sca", "Report 2", result)
        return 0

    parser.print_help()
    return 0


def _print_summary(label: str, report: str, result: PipelineResult) -> None:
    for error in result.errors:
        print(f"[{label}] error: {error}")
    counts = result.counts_by_classification()
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "no findings"
    print(f"[{label}] {len(result.findings)} finding(s) ({summary})")
    print(f"[{label}] {report}: {result.report_json}, {result.report_html}")


if __name__ == "__main__":
    raise SystemExit(main())
