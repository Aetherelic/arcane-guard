from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile

from .scanner import inspect_pkgbuild


AUR_BASE_URL = "https://aur.archlinux.org"


def validate_package_name(name: str) -> None:
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@._+-")

    if not name:
        raise ValueError("Package name cannot be empty")

    if any(char not in allowed for char in name):
        raise ValueError(f"Invalid AUR package name: {name}")


def inspect_aur_package(name: str) -> dict:
    validate_package_name(name)

    if not shutil.which("git"):
        raise RuntimeError("git is required for AUR inspection")

    with tempfile.TemporaryDirectory(prefix="arcane-aur-") as temp_dir:
        target = Path(temp_dir) / name
        url = f"{AUR_BASE_URL}/{name}.git"

        result = subprocess.run(
            ["git", "clone", "--depth", "1", url, str(target)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        if result.returncode != 0:
            stderr = result.stderr.strip() or "unknown git clone error"
            raise RuntimeError(f"Failed to clone AUR package '{name}': {stderr}")

        pkgbuild = target / "PKGBUILD"

        if not pkgbuild.exists():
            raise FileNotFoundError(f"AUR package '{name}' does not contain a PKGBUILD")

        report = inspect_pkgbuild(str(pkgbuild))
        report["kind"] = "aur"
        report["aur_package"] = name
        report["aur_url"] = url

        return report
