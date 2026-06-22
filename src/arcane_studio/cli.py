from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .scanner import Finding, inspect_pkgbuild


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
GREEN = "\033[32m"
MAGENTA = "\033[35m"


def colour(text: str, code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{code}{text}{RESET}"


def severity_icon(severity: str) -> str:
    return {
        "critical": "✖",
        "high": "!",
        "medium": "⚠",
        "low": "•",
        "info": "i",
    }.get(severity, "•")


def severity_colour(severity: str) -> str:
    return {
        "critical": RED,
        "high": RED,
        "medium": YELLOW,
        "low": BLUE,
        "info": GREEN,
    }.get(severity, RESET)


def finding_to_dict(finding: Finding) -> dict:
    return {
        "severity": finding.severity,
        "rule": finding.rule,
        "message": finding.message,
        "line": finding.line,
        "evidence": finding.evidence,
        "advice": finding.advice,
    }


def print_report(report: dict) -> None:
    metadata = report["metadata"]
    findings = report["findings"]
    risk = report["risk"]

    print()
    print(colour("Arcane Guard Report", BOLD + MAGENTA))
    print(colour("━━━━━━━━━━━━━━━━━━━", MAGENTA))
    print()

    pkgname = metadata.get("pkgname", "unknown")
    pkgver = metadata.get("pkgver", "unknown")
    pkgdesc = metadata.get("pkgdesc", "").strip("'\"")

    print(f"{colour('Package:', BOLD)} {pkgname}")
    print(f"{colour('Version:', BOLD)} {pkgver}")

    if pkgdesc:
        print(f"{colour('Description:', BOLD)} {pkgdesc}")

    print(f"{colour('Risk:', BOLD)} {colour(risk.upper(), severity_colour(risk))}")
    print(f"{colour('File:', BOLD)} {report['path']}")

    if report.get("install_script"):
        print(f"{colour('Install script:', BOLD)} {report['install_script']}")

    print()

    if not findings:
        print(colour("✓ No obvious risky patterns found.", GREEN))
        print()
        print(colour("Note:", BOLD), "This does not prove the package is safe. It only means Arcane Guard did not detect obvious red flags.")
        print()
        return

    print(colour("Findings", BOLD))
    print(colour("────────", DIM))

    for finding in findings:
        icon = severity_icon(finding.severity)
        sev = colour(finding.severity.upper(), severity_colour(finding.severity))

        print(f"{icon} {sev} [{finding.rule}] line {finding.line}")
        print(f"  {finding.message}")
        print(colour(f"  Evidence: {finding.evidence}", DIM))
        print(f"  Advice: {finding.advice}")
        print()

    print(colour("Summary", BOLD))
    print(colour("───────", DIM))

    if risk in {"critical", "high"}:
        print("This package contains patterns that should be reviewed carefully before building or installing.")
    elif risk == "medium":
        print("This package has some suspicious or review-worthy patterns, but nothing automatically proves it is malicious.")
    else:
        print("This package has minor review notes only.")

    print()


def command_guard_inspect(args: argparse.Namespace) -> int:
    try:
        report = inspect_pkgbuild(args.path)
    except Exception as error:
        print(f"arcane: error: {error}", file=sys.stderr)
        return 1

    if args.json:
        json_report = {
            "path": report["path"],
            "metadata": report["metadata"],
            "install_script": report["install_script"],
            "risk": report["risk"],
            "findings": [finding_to_dict(f) for f in report["findings"]],
        }
        print(json.dumps(json_report, indent=2))
    else:
        print_report(report)

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arcane",
        description="Arcane Studio: safe customization tools for aesthetic Linux desktops.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"arcane-studio {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command")

    guard = subparsers.add_parser("guard", help="Arcane Guard package/script safety tools")
    guard_subparsers = guard.add_subparsers(dest="guard_command")

    inspect = guard_subparsers.add_parser("inspect", help="Inspect a local PKGBUILD")
    inspect.add_argument("path", help="Path to a PKGBUILD")
    inspect.add_argument("--json", action="store_true", help="Output report as JSON")
    inspect.set_defaults(func=command_guard_inspect)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        raise SystemExit(0)

    raise SystemExit(args.func(args))
