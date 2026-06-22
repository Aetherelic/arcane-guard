from __future__ import annotations

from pathlib import Path
import os

from .scanner import Finding, finding_counts, inspect_pkgbuild, risk_level, risk_score
from .script import inspect_script


SKIP_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    "target",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}

SCRIPT_NAMES = {
    "install.sh",
    "setup.sh",
    "bootstrap.sh",
    "build.sh",
    "configure.sh",
    "post-install.sh",
    "post_install.sh",
    "pre-install.sh",
    "pre_install.sh",
    "rice.sh",
    "apply.sh",
    "theme.sh",
}


def is_probably_text(path: Path) -> bool:
    try:
        data = path.read_bytes()[:2048]
    except OSError:
        return False

    return b"\x00" not in data


def has_shell_shebang(path: Path) -> bool:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return False

    if not lines:
        return False

    first_line = lines[0]
    return first_line.startswith("#!") and any(shell in first_line for shell in ["sh", "bash", "zsh", "fish"])


def is_script_candidate(path: Path) -> bool:
    name = path.name.lower()

    if name in SCRIPT_NAMES:
        return True

    if name.endswith(".sh"):
        return True

    if name.startswith("install") or name.startswith("setup") or name.startswith("bootstrap"):
        return is_probably_text(path)

    return has_shell_shebang(path)


def discover_targets(root: Path) -> list[tuple[str, Path]]:
    targets: list[tuple[str, Path]] = []

    for current_root, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        current = Path(current_root)

        for filename in filenames:
            path = current / filename

            if filename == "PKGBUILD":
                targets.append(("pkgbuild", path))
                continue

            if is_script_candidate(path):
                targets.append(("script", path))

    return targets


def inspect_directory(path: str) -> dict:
    root = Path(path).expanduser().resolve()

    if not root.exists():
        raise FileNotFoundError(f"No such directory: {root}")

    if not root.is_dir():
        raise NotADirectoryError(f"Expected a directory, got file: {root}")

    targets = discover_targets(root)
    findings: list[Finding] = []
    scanned_files: list[str] = []
    errors: list[str] = []

    for kind, target in targets:
        try:
            if kind == "pkgbuild":
                report = inspect_pkgbuild(str(target))
            else:
                report = inspect_script(str(target))
        except Exception as error:
            errors.append(f"{target}: {error}")
            continue

        scanned_files.append(str(target))

        try:
            relative = str(target.relative_to(root))
        except ValueError:
            relative = str(target)

        for finding in report["findings"]:
            findings.append(
                Finding(
                    severity=finding.severity,
                    rule=finding.rule,
                    message=finding.message,
                    line=finding.line,
                    evidence=finding.evidence,
                    advice=finding.advice,
                    context=f"{relative}:{finding.context}",
                )
            )

    return {
        "kind": "directory",
        "path": str(root),
        "metadata": {
            "pkgname": root.name,
            "pkgver": "directory",
            "pkgdesc": "Directory safety inspection",
        },
        "install_script": None,
        "risk": risk_level(findings),
        "score": risk_score(findings),
        "counts": finding_counts(findings),
        "findings": findings,
        "scanned_files": scanned_files,
        "errors": errors,
    }
