from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .aur import inspect_aur_package
from .directory import inspect_directory
from .scanner import Finding, inspect_pkgbuild
from .script import inspect_script
from .themes import list_snapshots, restore_snapshot, snapshot_current, status as themes_status


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
GREEN = "\033[32m"
MAGENTA = "\033[35m"

SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


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

    return ", ".join(parts) if parts else "0 findings"


def should_fail(report: dict, fail_on: str | None) -> bool:
    if not fail_on:
        return False

    risk = report.get("risk", "low")
    return SEVERITY_RANK.get(risk, 0) >= SEVERITY_RANK[fail_on]


def print_guard_report(report: dict) -> None:
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


def output_guard_report(report: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report_to_json(report), indent=2))
    else:
        print_guard_report(report)


def finish_guard_command(report: dict, args: argparse.Namespace) -> int:
    output_guard_report(report, args.json)

    if should_fail(report, args.fail_on):
        if not args.json:
            print(f"arcane: failing because risk is {report['risk']} and --fail-on is {args.fail_on}", file=sys.stderr)
        return 2

    return 0


def command_guard_inspect(args: argparse.Namespace) -> int:
    try:
        report = inspect_pkgbuild(args.path)
    except Exception as error:
        print(f"arcane: error: {error}", file=sys.stderr)
        return 1

    return finish_guard_command(report, args)


def command_guard_inspect_aur(args: argparse.Namespace) -> int:
    try:
        report = inspect_aur_package(args.package)
    except Exception as error:
        print(f"arcane: error: {error}", file=sys.stderr)
        return 1

    return finish_guard_command(report, args)


def command_guard_inspect_script(args: argparse.Namespace) -> int:
    try:
        report = inspect_script(args.path)
    except Exception as error:
        print(f"arcane: error: {error}", file=sys.stderr)
        return 1

    return finish_guard_command(report, args)


def command_guard_inspect_dir(args: argparse.Namespace) -> int:
    try:
        report = inspect_directory(args.path)
    except Exception as error:
        print(f"arcane: error: {error}", file=sys.stderr)
        return 1

    return finish_guard_command(report, args)


def command_themes_status(args: argparse.Namespace) -> int:
    report = themes_status()

    print()
    print(colour("Arcane Themes Status", BOLD + MAGENTA))
    print(colour("━━━━━━━━━━━━━━━━━━━━", MAGENTA))
    print()
    print(f"{colour('State dir:', BOLD)} {report['state_dir']}")
    print(f"{colour('Snapshot dir:', BOLD)} {report['snapshot_dir']}")
    print()
    print(colour("Managed targets", BOLD))
    print(colour("───────────────", DIM))

    for target in report["targets"]:
        icon = "✓" if target["exists"] else "·"
        print(f"{icon} {target['path']} [{target['kind']}]")

    print()
    return 0


def command_themes_snapshot(args: argparse.Namespace) -> int:
    try:
        result = snapshot_current(args.name)
    except Exception as error:
        print(f"arcane: error: {error}", file=sys.stderr)
        return 1

    print()
    print(colour("Arcane Themes Snapshot", BOLD + MAGENTA))
    print(colour("━━━━━━━━━━━━━━━━━━━━━━", MAGENTA))
    print()
    print(f"{colour('Snapshot:', BOLD)} {result['snapshot']}")
    print(f"{colour('Path:', BOLD)} {result['path']}")
    print()
    print(f"{colour('Copied:', BOLD)} {len(result['copied'])}")

    for item in result["copied"]:
        print(f"✓ {item['path']} [{item['kind']}]")

    if result["skipped"]:
        print()
        print(f"{colour('Skipped:', BOLD)} {len(result['skipped'])}")
        for item in result["skipped"]:
            print(f"· {item['path']} [{item['reason']}]")

    print()
    return 0


def command_themes_list(args: argparse.Namespace) -> int:
    snapshots = list_snapshots()

    print()
    print(colour("Arcane Themes Snapshots", BOLD + MAGENTA))
    print(colour("━━━━━━━━━━━━━━━━━━━━━━", MAGENTA))
    print()

    if not snapshots:
        print("No snapshots found.")
        print()
        return 0

    for snapshot in snapshots:
        print(f"{colour(snapshot['name'], BOLD)}")
        print(f"  Created: {snapshot['created_at']}")
        print(f"  Copied:  {snapshot['copied_count']}")
        print(f"  Skipped: {snapshot['skipped_count']}")
        print(f"  Path:    {snapshot['path']}")
        print()

    return 0


def command_themes_restore(args: argparse.Namespace) -> int:
    try:
        result = restore_snapshot(args.snapshot, apply=args.yes)
    except Exception as error:
        print(f"arcane: error: {error}", file=sys.stderr)
        return 1

    print()
    print(colour("Arcane Themes Restore", BOLD + MAGENTA))
    print(colour("━━━━━━━━━━━━━━━━━━━━━", MAGENTA))
    print()
    print(f"{colour('Snapshot:', BOLD)} {result['snapshot']}")
    print(f"{colour('Snapshot path:', BOLD)} {result['snapshot_path']}")
    print(f"{colour('Mode:', BOLD)} {'apply' if result['apply'] else 'dry-run'}")
    print()

    if result["planned"]:
        print(colour("Restore plan", BOLD))
        print(colour("────────────", DIM))
        for item in result["planned"]:
            marker = "overwrite" if item["exists_now"] else "create"
            print(f"• {item['path']} [{item['kind']}] → {marker}")
        print()
    else:
        print("Nothing to restore.")
        print()

    if result["missing"]:
        print(colour("Missing from snapshot", BOLD))
        print(colour("─────────────────────", DIM))
        for item in result["missing"]:
            print(f"• {item['path']} [{item['reason']}]")
        print()

    if result["apply"]:
        if result["safety_snapshot"]:
            print(colour("Safety snapshot created before restore:", BOLD))
            print(f"  {result['safety_snapshot']['snapshot']}")
            print(f"  {result['safety_snapshot']['path']}")
            print()

        print(colour("Restored", BOLD))
        print(colour("────────", DIM))
        for item in result["restored"]:
            print(f"✓ {item['path']} [{item['kind']}]")
        print()
    else:
        print(colour("Dry-run only.", BOLD))
        print("Re-run with --yes to restore this snapshot.")
        print()

    return 0


def add_guard_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="Output report as JSON")
    parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        help="Exit with code 2 if risk is at least this severity",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arcane",
        description="Arcane Studio: safe customization tools for aesthetic Linux desktops.",
    )

    parser.add_argument("--version", action="version", version=f"arcane-studio {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    guard = subparsers.add_parser("guard", help="Arcane Guard package/script safety tools")
    guard_subparsers = guard.add_subparsers(dest="guard_command")

    inspect = guard_subparsers.add_parser("inspect", help="Inspect a local PKGBUILD")
    inspect.add_argument("path", help="Path to a PKGBUILD")
    add_guard_common_args(inspect)
    inspect.set_defaults(func=command_guard_inspect)

    inspect_aur = guard_subparsers.add_parser("inspect-aur", help="Inspect a package from the AUR")
    inspect_aur.add_argument("package", help="AUR package name")
    add_guard_common_args(inspect_aur)
    inspect_aur.set_defaults(func=command_guard_inspect_aur)

    inspect_script_parser = guard_subparsers.add_parser("inspect-script", help="Inspect a local shell/install script")
    inspect_script_parser.add_argument("path", help="Path to a script")
    add_guard_common_args(inspect_script_parser)
    inspect_script_parser.set_defaults(func=command_guard_inspect_script)

    inspect_dir_parser = guard_subparsers.add_parser("inspect-dir", help="Inspect a directory for PKGBUILDs and install scripts")
    inspect_dir_parser.add_argument("path", help="Path to a directory")
    add_guard_common_args(inspect_dir_parser)
    inspect_dir_parser.set_defaults(func=command_guard_inspect_dir)

    themes = subparsers.add_parser("themes", help="Arcane Themes rice/theme management tools")
    themes_subparsers = themes.add_subparsers(dest="themes_command")

    themes_status_parser = themes_subparsers.add_parser("status", help="Show managed theme targets")
    themes_status_parser.set_defaults(func=command_themes_status)

    themes_snapshot_parser = themes_subparsers.add_parser("snapshot", help="Snapshot current rice/theme configs")
    themes_snapshot_parser.add_argument("--name", help="Optional snapshot name")
    themes_snapshot_parser.set_defaults(func=command_themes_snapshot)

    themes_list_parser = themes_subparsers.add_parser("list", help="List Arcane Themes snapshots")
    themes_list_parser.set_defaults(func=command_themes_list)

    themes_restore_parser = themes_subparsers.add_parser("restore", help="Restore an Arcane Themes snapshot")
    themes_restore_parser.add_argument("snapshot", help="Snapshot name to restore")
    themes_restore_parser.add_argument("--yes", action="store_true", help="Actually restore files. Without this, Arcane Themes only shows a dry-run.")
    themes_restore_parser.set_defaults(func=command_themes_restore)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        raise SystemExit(0)

    raise SystemExit(args.func(args))
