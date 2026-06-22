from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from collections import Counter
import re


@dataclass
class Finding:
    severity: str
    rule: str
    message: str
    line: int
    evidence: str
    advice: str
    context: str = "unknown"


SEVERITY_WEIGHT = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 5,
    "critical": 8,
}


COMMAND_RULES: list[tuple[str, str, str, re.Pattern[str], str]] = [
    (
        "critical",
        "pipe-to-shell",
        "Downloads code and pipes it directly into a shell.",
        re.compile(r"(curl|wget|fetch).*(\|\s*(sh|bash|zsh|fish))", re.I),
        "Avoid running remote scripts directly. Download, inspect, then execute only if trusted.",
    ),
    (
        "critical",
        "dangerous-cd-home-then-rm",
        "Changes into the home directory and then recursively deletes the current directory.",
        re.compile(
            r"\bcd\s+['\"]?(?:~|\$HOME|\$\{HOME\})['\"]?\s*&&\s*rm\b"
            r"(?=[^#\n]*(?:-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|--recursive))"
            r"(?=[^#\n]*(?:-[a-zA-Z]*f|--force))",
            re.I,
        ),
        "This can delete the user's home directory. Stop and review the script carefully.",
    ),
    (
        "critical",
        "dangerous-rm",
        "Potentially dangerous recursive deletion command.",
        re.compile(
            r"\brm\b"
            r"(?=[^#\n]*(?:-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|--recursive))"
            r"(?=[^#\n]*(?:-[a-zA-Z]*f|--force))"
            r"[^#\n]*(?:['\"]?(?:/|~|\$HOME|\$\{HOME\}|\.)['\"]?)(?:\s|$|[;&|])",
            re.I,
        ),
        "Check that deletion targets are scoped to $srcdir, $pkgdir, or a temporary build directory.",
    ),
    (
        "critical",
        "dangerous-find-delete-home",
        "Uses find -delete against a home or root-like target.",
        re.compile(r"\bfind\s+['\"]?(?:~|\$HOME|\$\{HOME\}|/)['\"]?[^#\n]*\s-delete\b", re.I),
        "find -delete can remove many files quickly. Verify the target is not a user or system directory.",
    ),
    (
        "high",
        "dangerous-find-delete-current",
        "Uses find -delete against the current directory.",
        re.compile(r"\bfind\s+['\"]?\.['\"]?[^#\n]*\s-delete\b", re.I),
        "find . -delete may be legitimate in build directories, but it can be destructive in install scripts.",
    ),
    (
        "high",
        "sudo-in-command",
        "Uses sudo inside executable logic.",
        re.compile(r"(^|[;&|({\s])sudo(\s|$)", re.I),
        "Package/build scripts should not need sudo. makepkg handles privilege separation.",
    ),
    (
        "high",
        "privilege-change",
        "Attempts to switch user or escalate privileges.",
        re.compile(r"(^|[;&|({\s])(su|doas|pkexec)(\s|$)", re.I),
        "Privilege escalation inside scripts is risky and should be reviewed carefully.",
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
        "Starts/enables/disables services during executable logic.",
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
        "binary-reference",
        "References a prebuilt binary/archive format.",
        re.compile(r"\.(AppImage|deb|rpm|bin|run|exe|msi|dmg|pkg|tar\.gz|tgz|zip|7z|rar)(['\")\s]|$)", re.I),
        "Prebuilt binaries are not automatically unsafe, but they reduce source transparency.",
    ),
    (
        "low",
        "network-command",
        "Uses a network command.",
        re.compile(r"\b(curl|wget|git\s+clone|ssh|scp|rsync)\b", re.I),
        "Network access is normal in source arrays, but suspicious inside executable logic.",
    ),
]


METADATA_RULES: list[tuple[str, str, str, re.Pattern[str], str]] = [
    (
        "medium",
        "binary-source",
        "Source references a prebuilt binary/archive format.",
        re.compile(r"^\s*source(_[a-zA-Z0-9_]+)?=.*\.(AppImage|deb|rpm|bin|run|exe|msi|dmg|pkg|tar\.gz|tgz|zip|7z|rar)", re.I),
        "Prebuilt binary packages are common for -bin AUR packages, but they reduce source transparency.",
    ),
    (
        "medium",
        "install-script-reference",
        "References an install script.",
        re.compile(r"^\s*install\s*=", re.I),
        "Review the referenced .install file as well as the PKGBUILD.",
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


PKGBUILD_FUNCTION_RE = re.compile(
    r"^\s*(pkgver|prepare|build|check|package)\s*\(\)\s*\{"
)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def extract_simple_metadata(text: str) -> dict[str, str]:
    metadata: dict[str, str] = {}

    for key in PKGBUILD_KEYS:
        pattern = re.compile(rf"^\s*{re.escape(key)}\s*=\s*(.+)$", re.M)
        match = pattern.search(text)
        if match:
            metadata[key] = match.group(1).strip()

    return metadata


def scan_line_with_rules(
    line: str,
    line_number: int,
    rules: list[tuple[str, str, str, re.Pattern[str], str]],
    context: str,
) -> list[Finding]:
    findings: list[Finding] = []

    stripped = line.strip()

    if not stripped or stripped.startswith("#"):
        return findings

    for severity, rule, message, pattern, advice in rules:
        if pattern.search(stripped):
            findings.append(
                Finding(
                    severity=severity,
                    rule=rule,
                    message=message,
                    line=line_number,
                    evidence=stripped,
                    advice=advice,
                    context=context,
                )
            )

    return findings


def scan_text(text: str) -> list[Finding]:
    findings: list[Finding] = []

    for index, line in enumerate(text.splitlines(), start=1):
        findings.extend(
            scan_line_with_rules(
                line=line,
                line_number=index,
                rules=COMMAND_RULES,
                context="script",
            )
        )

    return findings


def scan_pkgbuild_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    in_function = False
    brace_depth = 0
    current_function = "metadata"

    for index, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()

        function_match = PKGBUILD_FUNCTION_RE.match(line)
        if function_match:
            in_function = True
            current_function = function_match.group(1)
            brace_depth = line.count("{") - line.count("}")
            findings.extend(
                scan_line_with_rules(
                    line=line,
                    line_number=index,
                    rules=COMMAND_RULES,
                    context=current_function,
                )
            )
            continue

        if in_function:
            findings.extend(
                scan_line_with_rules(
                    line=line,
                    line_number=index,
                    rules=COMMAND_RULES,
                    context=current_function,
                )
            )

            brace_depth += line.count("{") - line.count("}")

            if brace_depth <= 0:
                in_function = False
                current_function = "metadata"

            continue

        findings.extend(
            scan_line_with_rules(
                line=line,
                line_number=index,
                rules=METADATA_RULES,
                context="metadata",
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


def risk_score(findings: list[Finding]) -> int:
    return sum(SEVERITY_WEIGHT[f.severity] for f in findings)


def finding_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.severity for f in findings)

    return {
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "info": counts.get("info", 0),
        "total": len(findings),
    }


def inspect_pkgbuild(path: str) -> dict:
    pkgbuild_path = Path(path).expanduser().resolve()

    if not pkgbuild_path.exists():
        raise FileNotFoundError(f"No such file: {pkgbuild_path}")

    if not pkgbuild_path.is_file():
        raise IsADirectoryError(f"Expected a file, got directory: {pkgbuild_path}")

    text = read_text(pkgbuild_path)
    metadata = extract_simple_metadata(text)
    findings = scan_pkgbuild_text(text)

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
                context="install-script",
            )
            for f in install_findings
        )

    return {
        "kind": "pkgbuild",
        "path": str(pkgbuild_path),
        "metadata": metadata,
        "install_script": str(install_script) if install_script else None,
        "risk": risk_level(findings),
        "score": risk_score(findings),
        "counts": finding_counts(findings),
        "findings": findings,
    }
