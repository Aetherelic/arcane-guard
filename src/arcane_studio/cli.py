from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .aur import inspect_aur_package
from .directory import inspect_directory
from .scanner import Finding, inspect_pkgbuild
from .script import inspect_script


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
        "context": finding.context,
    }


def report_to_json(report: dict) -> dict:
    data = {
        "kind": report.get("kind", "pkgbuild"),
        "path": report["path"],
        "metadata": report["metadata"],
        "install_script": report["install_script"],
        "risk": report["risk"],
        "score": report.get("score", 0),
        "counts": report.get("counts", {}),
        "findings": [finding_to_dict(f) for f in report["findings"]],
    }

    if "aur_package" in report:
        data["aur_package"] = report["aur_package"]
        data["aur_url"] = report["aur_url"]

    if "scanned_files" in report:
        data["scanned_files"] = report["scanned_files"]
        data["errors"] = report.get("errors", [])

    return data


def format_counts(counts: dict) -> str:
    parts = []

    for severity in ["critical", "high", "medium", "low", "info"]:
        count = counts.get(severity, 0)
        if count:
            parts.append(f"{count} {severity}")

    if not parts:
        return "0 findings"

    return ", ".join(parts)


def print_report(report: dict) -> None:
    metadata = report["metadata"]
    findings: list[Finding] = report["findings"]
    risk = report["risk"]
    kind = report.get("kind", "pkgbuild")
    counts = report.get("counts", {})
    score = report.get("score", 0)

    print()
    print(colour("Arcane Guard Report", BOLD + MAGENTA))
    print(colour("━━━━━━━━━━━━━━━━━━━", MAGENTA))
    print()

    name = metadata.get("pkgname", "unknown")
    version = metadata.get("pkgver", "unknown")
    description = metadata.get("pkgdesc", "").strip("'\"")

    label = "Target" if kind in {"script", "directory"} else "Package"

    print(f"{colour(label + ':', BOLD)} {name}")
    print(f"{colour('Version:', BOLD)} {version}")

    if description:
        print(f"{colour('Description:', BOLD)} {description}")

    print(f"{colour('Type:', BOLD)} {kind}")
    print(f"{colour('Risk:', BOLD)} {colour(risk.upper(), severity_colour(risk))}")
    print(f"{colour('Score:', BOLD)} {score}")
    print(f"{colour('Findings:', BOLD)} {format_counts(counts)}")
    print(f"{colour('File:', BOLD)} {report['path']}")

    if report.get("aur_package"):
        print(f"{colour('AUR package:', BOLD)} {report['aur_package']}")
        print(f"{colour('AUR URL:', BOLD)} {report['aur_url']}")

    if report.get("install_script"):
        print(f"{colour('Install script:', BOLD)} {report['install_script']}")

    if "scanned_files" in report:
        print(f"{colour('Scanned files:', BOLD)} {len(report['scanned_files'])}")

    print()

    if report.get("scanned_files"):
        print(colour("Scanned", BOLD))
        print(colour("───────", DIM))
        for scanned in report["scanned_files"]:
            print(f"• {scanned}")
        print()

    if report.get("errors"):
        print(colour("Errors", BOLD))
        print(colour("──────", DIM))
        for error in report["errors"]:
            print(f"• {error}")
        print()

    if not findings:
        print(colour("✓ No obvious risky patterns found.", GREEN))
        print()
        print(colour("Note:", BOLD), "This does not prove it is safe. It only means Arcane Guard did not detect obvious red flags.")
        print()
        return

    print(colour("Findings", BOLD))
    print(colour("────────", DIM))

    for finding in findings:
        icon = severity_icon(finding.severity)
        sev = colour(finding.severity.upper(), severity_colour(finding.severity))

        print(f"{icon} {sev} [{finding.rule}] line {finding.line} · {finding.context}")
        print(f"  {finding.message}")
        print(colour(f"  Evidence: {finding.evidence}", DIM))
        print(f"  Advice: {finding.advice}")
        print()

    print(colour("Summary", BOLD))
    print(colour("───────", DIM))

    if risk in {"critical", "high"}:
        print("This target contains patterns that should be reviewed carefully before running, building, or installing.")
    elif risk == "medium":
        print("This target has suspicious or review-worthy patterns, but nothing automatically proves it is malicious.")
    else:
        print("This target has minor review notes only.")

    print()


def output_report(report: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report_to_json(report), indent=2))
    else:
        print_report(report)


def command_guard_inspect(args: argparse.Namespace) -> int:
    try:
        report = inspect_pkgbuild(args.path)
    except Exception as error:
        print(f"arcane: error: {error}", file=sys.stderr)
        return 1

    output_report(report, args.json)
    return 0


def command_guard_inspect_aur(args: argparse.Namespace) -> int:
    try:
        report = inspect_aur_package(args.package)
    except Exception as error:
        print(f"arcane: error: {error}", file=sys.stderr)
        return 1

    output_report(report, args.json)
    return 0


def command_guard_inspect_script(args: argparse.Namespace) -> int:
    try:
        report = inspect_script(args.path)
    except Exception as error:
        print(f"arcane: error: {error}", file=sys.stderr)
        return 1

    output_report(report, args.json)
    return 0


def command_guard_inspect_dir(args: argparse.Namespace) -> int:
    try:
        report = inspect_directory(args.path)
    except Exception as error:
        print(f"arcane: error: {error}", file=sys.stderr)
        return 1

    output_report(report, args.json)
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

    inspect_aur = guard_subparsers.add_parser("inspect-aur", help="Inspect a package from the AUR")
    inspect_aur.add_argument("package", help="AUR package name")
    inspect_aur.add_argument("--json", action="store_true", help="Output report as JSON")
    inspect_aur.set_defaults(func=command_guard_inspect_aur)

    inspect_script_parser = guard_subparsers.add_parser("inspect-script", help="Inspect a local shell/install script")
    inspect_script_parser.add_argument("path", help="Path to a script")
    inspect_script_parser.add_argument("--json", action="store_true", help="Output report as JSON")
    inspect_script_parser.set_defaults(func=command_guard_inspect_script)

    inspect_dir_parser = guard_subparsers.add_parser("inspect-dir", help="Inspect a directory for PKGBUILDs and install scripts")
    inspect_dir_parser.add_argument("path", help="Path to a directory")
    inspect_dir_parser.add_argument("--json", action="store_true", help="Output report as JSON")
    inspect_dir_parser.set_defaults(func=command_guard_inspect_dir)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        raise SystemExit(0)

    raise SystemExit(args.func(args))
