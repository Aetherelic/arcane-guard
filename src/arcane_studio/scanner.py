from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re


@dataclass
class Finding:
    severity: str
    rule: str
    message: str
    line: int
    evidence: str
    advice: str


SEVERITY_WEIGHT = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


RULES = [
    (
        "critical",
        "pipe-to-shell",
        "Downloads code and pipes it directly into a shell.",
        re.compile(r"(curl|wget|fetch).*(\|\s*(sh|bash|zsh|fish))", re.I),
        "Avoid running remote scripts directly. Download, inspect, then execute only if trusted.",
    ),
    (
        "critical",
        "dangerous-rm",
        "Potentially dangerous recursive deletion command.",
        re.compile(r"rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-rf|-fr)\s+(/|\$HOME|~|\${HOME})", re.I),
        "Check that deletion targets are scoped to $srcdir, $pkgdir, or a temporary build directory.",
    ),
    (
        "high",
        "sudo-in-build",
        "Uses sudo inside package/build logic.",
        re.compile(r"\bsudo\b", re.I),
        "PKGBUILDs should not need sudo. makepkg handles privilege separation.",
    ),
    (
        "high",
        "privilege-change",
        "Attempts to switch user or escalate privileges.",
        re.compile(r"\b(su|doas|pkexec)\b", re.I),
        "Privilege escalation inside package scripts is risky and should be reviewed carefully.",
    ),
    (
        "high",
        "setuid-or-capability",
        "Sets special permissions or Linux capabilities.",
        re.compile(r"(chmod\s+u\+s|chmod\s+4[0-7]{3}|setcap\s+)", re.I),
        "Setuid/capability changes can increase security risk. Verify why they are needed.",
    ),
    (
        "medium",
        "chmod-777",
        "Uses chmod 777.",
        re.compile(r"chmod\s+777", re.I),
        "World-writable files are usually a bad sign. Prefer specific permissions.",
    ),
    (
        "medium",
        "systemd-action",
        "Starts/enables/disables services during package logic.",
        re.compile(r"\bsystemctl\s+(enable|start|disable|stop|restart)", re.I),
        "Packages should generally not start services automatically without user consent.",
    ),
    (
        "medium",
        "eval-usage",
        "Uses eval.",
        re.compile(r"\beval\b", re.I),
        "eval can hide what code actually runs. Review this line carefully.",
    ),
    (
        "medium",
        "binary-download",
        "References a prebuilt binary/archive format.",
        re.compile(r"\.(AppImage|deb|rpm|bin|run|exe|msi|dmg|pkg|tar\.gz|tgz|zip|7z|rar)(['\")\s]|$)", re.I),
        "Prebuilt binaries are not automatically unsafe, but they reduce source transparency.",
    ),
    (
        "medium",
        "install-script-reference",
        "References an install script.",
        re.compile(r"^\s*install\s*=", re.I),
        "Review the referenced .install file as well as the PKGBUILD.",
    ),
    (
        "low",
        "network-command",
        "Uses a network command inside the file.",
        re.compile(r"\b(curl|wget|git\s+clone|ssh|scp|rsync)\b", re.I),
        "Network access is normal in source arrays, but suspicious inside build/package functions.",
    ),
]


PKGBUILD_KEYS = [
    "pkgname",
    "pkgver",
    "pkgrel",
    "pkgdesc",
    "arch",
    "url",
    "license",
    "depends",
    "makedepends",
    "source",
    "install",
]


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def extract_simple_metadata(text: str) -> dict[str, str]:
    metadata = {}

    for key in PKGBUILD_KEYS:
        pattern = re.compile(rf"^\s*{re.escape(key)}\s*=\s*(.+)$", re.M)
        match = pattern.search(text)
        if match:
            metadata[key] = match.group(1).strip()

    return metadata


def scan_text(text: str) -> list[Finding]:
    findings = []

    for index, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        for severity, rule, message, pattern, advice in RULES:
            if pattern.search(stripped):
                findings.append(
                    Finding(
                        severity=severity,
                        rule=rule,
                        message=message,
                        line=index,
                        evidence=stripped,
                        advice=advice,
                    )
                )

    return findings


def find_install_script(pkgbuild_path: Path, metadata: dict[str, str]) -> Path | None:
    raw_install = metadata.get("install")
    if not raw_install:
        return None

    cleaned = raw_install.strip().strip("'\"")
    candidate = pkgbuild_path.parent / cleaned

    if candidate.exists() and candidate.is_file():
        return candidate

    return None


def risk_level(findings: list[Finding]) -> str:
    if not findings:
        return "low"

    highest = max(SEVERITY_WEIGHT[f.severity] for f in findings)

    if highest >= SEVERITY_WEIGHT["critical"]:
        return "critical"
    if highest >= SEVERITY_WEIGHT["high"]:
        return "high"
    if highest >= SEVERITY_WEIGHT["medium"]:
        return "medium"

    return "low"


def inspect_pkgbuild(path: str) -> dict:
    pkgbuild_path = Path(path).expanduser().resolve()

    if not pkgbuild_path.exists():
        raise FileNotFoundError(f"No such file: {pkgbuild_path}")

    if not pkgbuild_path.is_file():
        raise IsADirectoryError(f"Expected a file, got directory: {pkgbuild_path}")

    text = read_text(pkgbuild_path)
    metadata = extract_simple_metadata(text)
    findings = scan_text(text)

    install_script = find_install_script(pkgbuild_path, metadata)

    if install_script:
        install_findings = scan_text(read_text(install_script))
        findings.extend(
            Finding(
                severity=f.severity,
                rule=f"install:{f.rule}",
                message=f.message,
                line=f.line,
                evidence=f.evidence,
                advice=f.advice,
            )
            for f in install_findings
        )

    return {
        "path": str(pkgbuild_path),
        "metadata": metadata,
        "install_script": str(install_script) if install_script else None,
        "risk": risk_level(findings),
        "findings": findings,
    }
