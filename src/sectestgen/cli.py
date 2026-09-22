"""Entry point for the sectestgen CLI.

Each subcommand maps to a pipeline described in the project proposal:
`static` (Semgrep/Bandit/CodeQL -> reachability -> Report 1) and
`sca` (CycloneDX/Dependency-Track/Snyk/Grype -> Report 2). They are stubs
until the corresponding work package (WP1, WP2) is implemented.
"""

from __future__ import annotations

import argparse
from importlib.metadata import PackageNotFoundError, version


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
        "static", help="Static-code finding validation pipeline (Semgrep/Bandit/CodeQL)."
    )
    static_parser.add_argument("target", help="Path to the FastAPI project to analyze.")

    sca_parser = subparsers.add_parser(
        "sca", help="SBOM/dependency exposure validation pipeline."
    )
    sca_parser.add_argument("sbom", help="Path to a CycloneDX SBOM file.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "static":
        print(f"[static] pipeline not implemented yet (WP1). target={args.target}")
        return 0
    if args.command == "sca":
        print(f"[sca] pipeline not implemented yet (WP2). sbom={args.sbom}")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
