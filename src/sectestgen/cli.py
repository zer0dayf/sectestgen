"""Entry point for the sectestgen CLI.

Each subcommand maps to a pipeline described in the project proposal:
`static` (Semgrep/Bandit/CodeQL -> reachability -> Report 1) and
`sca` (CycloneDX/Dependency-Track/Grype -> import-usage evidence ->
Report 2).
"""

from __future__ import annotations

import argparse
import subprocess
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from sectestgen import rule_packs
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
    static_parser.add_argument("target", help="Path to the FastAPI/Spring project to analyze.")
    static_parser.add_argument(
        "-o",
        "--output",
        default="sectestgen-out",
        help="Directory to write report1.json / report1.html into (default: ./sectestgen-out).",
    )
    static_parser.add_argument(
        "--rules",
        action="append",
        default=[],
        metavar="PATH",
        help="Extra Semgrep rule file or directory, run alongside the built-in packs "
        "(repeatable; e.g. a local semgrep-rules checkout's java/ folder).",
    )
    static_parser.add_argument(
        "--rule-pack",
        action="append",
        default=[],
        metavar="NAME",
        help="Fetched public rule pack to add (repeatable; 'all' = every fetched pack). "
        "See `sectestgen rules list`.",
    )
    static_parser.add_argument(
        "--semgrep-timeout",
        type=int,
        default=300,
        metavar="SECONDS",
        help="Semgrep run timeout (default: 300); raise it for large projects or many rule packs.",
    )

    rules_parser = subparsers.add_parser("rules", help="Manage public third-party Semgrep rule packs.")
    rules_sub = rules_parser.add_subparsers(dest="rules_command")
    rules_sub.add_parser("list", help="List known rule packs, their license and fetch status.")
    fetch_parser = rules_sub.add_parser("fetch", help="Download or update rule packs (needs git + network).")
    fetch_parser.add_argument("names", nargs="*", metavar="NAME", help="Pack names to fetch.")
    fetch_parser.add_argument("--all", action="store_true", help="Fetch every known pack.")

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
        extra_rules = [Path(p) for p in args.rules]
        if args.rule_pack:
            try:
                extra_rules += rule_packs.resolve(args.rule_pack)
            except rule_packs.RulePackError as exc:
                print(f"[static] error: {exc}")
                return 2
        result = run_static_pipeline(
            Path(args.target),
            output_dir=Path(args.output),
            extra_rules=extra_rules,
            semgrep_timeout=args.semgrep_timeout,
        )
        _print_summary("static", "Report 1", result)
        return 0
    if args.command == "rules":
        return _rules_command(args, parser)
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


def _rules_command(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.rules_command == "list":
        print(f"rule pack cache: {rule_packs.cache_dir()}")
        for pack in rule_packs.PACKS.values():
            status = "fetched" if rule_packs.is_fetched(pack) else "not fetched"
            languages = ", ".join(lang for lang, folders in pack.paths.items() if folders)
            print(f"  {pack.name:<13} {status:<12} {languages:<13} {pack.license:<27} {pack.description}")
        return 0
    if args.rules_command == "fetch":
        names = list(rule_packs.PACKS) if args.all else args.names
        if not names:
            print("[rules] name at least one pack or pass --all (see `sectestgen rules list`)")
            return 2
        failed = False
        for name in names:
            try:
                pack = rule_packs.get_pack(name)
                dest = rule_packs.fetch(pack)
                print(f"[rules] {name}: {dest} ({pack.license})")
            except (rule_packs.RulePackError, OSError, subprocess.SubprocessError) as exc:
                print(f"[rules] {name}: error: {exc}")
                failed = True
        return 1 if failed else 0
    parser.parse_args(["rules", "--help"])
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
