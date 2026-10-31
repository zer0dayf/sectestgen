"""Entry point for the sectestgen CLI.

Each subcommand maps to a pipeline described in the project proposal:
`static` (Semgrep/Bandit/CodeQL -> reachability -> Report 1),
`sca` (CycloneDX/Dependency-Track/Grype/Snyk -> import/symbol-usage evidence ->
Report 2) and `scan` (both, plus the merged and de-duplicated Report 3).
`--validate` adds runtime confirmation in the Docker sandbox, whose image
is built once with `sandbox build`.
"""

from __future__ import annotations

import argparse
import subprocess
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from sectestgen import rule_packs
from sectestgen.pipeline import (
    PipelineResult,
    UnifiedResult,
    run_sca_pipeline,
    run_static_pipeline,
    run_unified_pipeline,
)
from sectestgen.sandbox.executor import DockerSandboxExecutor, SandboxError, SandboxLimits, build_image


def _version() -> str:
    try:
        return version("sectestgen")
    except PackageNotFoundError:
        return "0.1.0-dev"


def _add_output(parser: argparse.ArgumentParser, reports: str) -> None:
    parser.add_argument(
        "-o",
        "--output",
        default="sectestgen-out",
        help=f"Directory to write {reports} into (default: ./sectestgen-out).",
    )


def _add_static_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--rules",
        action="append",
        default=[],
        metavar="PATH",
        help="Extra Semgrep rule file or directory, run alongside the built-in packs "
        "(repeatable; e.g. a local semgrep-rules checkout's java/ folder).",
    )
    parser.add_argument(
        "--rule-pack",
        action="append",
        default=[],
        metavar="NAME",
        help="Fetched public rule pack to add (repeatable; 'all' = every fetched pack). "
        "See `sectestgen rules list`.",
    )
    parser.add_argument(
        "--semgrep-timeout",
        type=int,
        default=300,
        metavar="SECONDS",
        help="Semgrep run timeout (default: 300); raise it for large projects or many rule packs.",
    )


def _add_sca_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--grype",
        help="Pre-generated Grype JSON report (default: run `grype` from PATH if installed).",
    )
    parser.add_argument(
        "--snyk",
        help="Pre-generated `snyk test --json` report (Snyk is never run by sectestgen).",
    )
    parser.add_argument(
        "--symbols",
        help="JSON file of extra vulnerable-symbol metadata "
        '([{"advisory": "CVE-...", "purl": "pkg:...", "symbols": [...]}]).',
    )


def _add_validation_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Confirm supported findings at runtime in the network-isolated Docker sandbox "
        "(build its image first with `sectestgen sandbox build TARGET`).",
    )
    parser.add_argument("--sandbox-image", help="Sandbox image to use instead of the one derived from the target.")
    parser.add_argument(
        "--case-timeout", type=int, default=20, metavar="SECONDS", help="Per-case runtime limit (default: 20)."
    )


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
    _add_output(static_parser, "report1.json / report1.html")
    _add_static_options(static_parser)
    _add_validation_options(static_parser)

    rules_parser = subparsers.add_parser("rules", help="Manage public third-party Semgrep rule packs.")
    rules_sub = rules_parser.add_subparsers(dest="rules_command")
    rules_sub.add_parser("list", help="List known rule packs, their license and fetch status.")
    fetch_parser = rules_sub.add_parser("fetch", help="Download or update rule packs (needs git + network).")
    fetch_parser.add_argument("names", nargs="*", metavar="NAME", help="Pack names to fetch.")
    fetch_parser.add_argument("--all", action="store_true", help="Fetch every known pack.")

    sca_parser = subparsers.add_parser(
        "sca", help="SBOM/dependency exposure validation pipeline (CycloneDX/Grype/Snyk) -> Report 2."
    )
    sca_parser.add_argument("sbom", help="Path to a CycloneDX JSON SBOM.")
    sca_parser.add_argument(
        "-s",
        "--source",
        help="Project the SBOM describes, searched for imports (default: the SBOM's directory).",
    )
    _add_sca_options(sca_parser)
    _add_output(sca_parser, "report2.json / report2.html")
    _add_validation_options(sca_parser)

    scan_parser = subparsers.add_parser(
        "scan", help="Static + SCA pipelines and the unified, de-duplicated Report 3."
    )
    scan_parser.add_argument("target", help="Path to the FastAPI/Spring project to analyze.")
    scan_parser.add_argument("--sbom", help="CycloneDX JSON SBOM of the target (enables the SCA pipeline).")
    _add_sca_options(scan_parser)
    _add_static_options(scan_parser)
    _add_output(scan_parser, "report1/2/3 .json / .html")
    _add_validation_options(scan_parser)

    sandbox_parser = subparsers.add_parser("sandbox", help="Manage the runtime-validation sandbox image.")
    sandbox_sub = sandbox_parser.add_subparsers(dest="sandbox_command")
    build_parser_ = sandbox_sub.add_parser(
        "build", help="Build the sandbox image for a target (needs network for pip; validation does not)."
    )
    build_parser_.add_argument("target", help="Project whose requirements.txt / .python-version to use.")
    build_parser_.add_argument("--requirements", help="Requirements file (default: TARGET/requirements.txt).")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "static":
        extra_rules = _extra_rules(args, "static")
        if extra_rules is None:
            return 2
        result = run_static_pipeline(
            Path(args.target),
            output_dir=Path(args.output),
            extra_rules=extra_rules,
            semgrep_timeout=args.semgrep_timeout,
            **_validation_kwargs(args),
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
            snyk_report=Path(args.snyk) if args.snyk else None,
            symbols_file=Path(args.symbols) if args.symbols else None,
            **_validation_kwargs(args),
        )
        _print_summary("sca", "Report 2", result)
        return 0
    if args.command == "scan":
        extra_rules = _extra_rules(args, "scan")
        if extra_rules is None:
            return 2
        unified = run_unified_pipeline(
            Path(args.target),
            output_dir=Path(args.output),
            sbom=Path(args.sbom) if args.sbom else None,
            grype_report=Path(args.grype) if args.grype else None,
            snyk_report=Path(args.snyk) if args.snyk else None,
            symbols_file=Path(args.symbols) if args.symbols else None,
            extra_rules=extra_rules,
            semgrep_timeout=args.semgrep_timeout,
            **_validation_kwargs(args),
        )
        _print_unified(unified)
        return 0
    if args.command == "sandbox":
        if args.sandbox_command == "build":
            try:
                tag = build_image(Path(args.target), Path(args.requirements) if args.requirements else None)
            except (SandboxError, OSError, subprocess.SubprocessError) as exc:
                print(f"[sandbox] error: {exc}")
                return 1
            print(f"[sandbox] built {tag}")
            return 0
        parser.parse_args(["sandbox", "--help"])
        return 0

    parser.print_help()
    return 0


def _extra_rules(args: argparse.Namespace, label: str) -> list[Path] | None:
    extra_rules = [Path(p) for p in args.rules]
    if args.rule_pack:
        try:
            extra_rules += rule_packs.resolve(args.rule_pack)
        except rule_packs.RulePackError as exc:
            print(f"[{label}] error: {exc}")
            return None
    return extra_rules


def _validation_kwargs(args: argparse.Namespace) -> dict:
    if not args.validate:
        return {}
    sandbox = DockerSandboxExecutor(
        routes=[], image=args.sandbox_image, limits=SandboxLimits(case_timeout=args.case_timeout)
    )
    return {"validate": True, "sandbox": sandbox}


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
    validation = result.validation_counts()
    if any(validation.values()):
        print(f"[{label}] runtime: " + ", ".join(f"{k}={v}" for k, v in validation.items()))
    print(f"[{label}] {report}: {result.report_json}, {result.report_html}")


def _print_unified(result: UnifiedResult) -> None:
    _print_summary("static", "Report 1", result.static)
    if result.sca is not None:
        _print_summary("sca", "Report 2", result.sca)
    counts: dict[str, int] = {}
    for issue in result.issues:
        counts[issue.classification.value] = counts.get(issue.classification.value, 0) + 1
    members = sum(len(i.members) for i in result.issues)
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "no issues"
    print(f"[scan] {len(result.issues)} issue(s) from {members} finding(s) ({summary})")
    print(f"[scan] Report 3: {result.report_json}, {result.report_html}")


if __name__ == "__main__":
    raise SystemExit(main())
