from __future__ import annotations

from pathlib import Path

from .scanner import finding_counts, read_text, risk_level, risk_score, scan_text


def inspect_script(path: str) -> dict:
    script_path = Path(path).expanduser().resolve()

    if not script_path.exists():
        raise FileNotFoundError(f"No such file: {script_path}")

    if not script_path.is_file():
        raise IsADirectoryError(f"Expected a file, got directory: {script_path}")

    text = read_text(script_path)
    findings = scan_text(text)

    return {
        "kind": "script",
        "path": str(script_path),
        "metadata": {
            "pkgname": script_path.name,
            "pkgver": "script",
            "pkgdesc": "Generic install/script inspection",
        },
        "install_script": None,
        "risk": risk_level(findings),
        "score": risk_score(findings),
        "counts": finding_counts(findings),
        "findings": findings,
    }
