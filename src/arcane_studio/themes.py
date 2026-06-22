from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from datetime import datetime
import json
import shutil


APP_STATE_DIR = Path.home() / ".local" / "state" / "arcane-studio"
THEMES_STATE_DIR = APP_STATE_DIR / "themes"
SNAPSHOT_DIR = THEMES_STATE_DIR / "snapshots"


THEME_TARGETS = [
    ".config/hypr",
    ".config/quickshell",
    ".config/waybar",
    ".config/rofi",
    ".config/kitty",
    ".config/swaync",
    ".config/starship.toml",
    ".config/fastfetch",
]


@dataclass
class ThemeTarget:
    relative_path: str
    source: Path
    exists: bool
    kind: str


def get_targets() -> list[ThemeTarget]:
    targets: list[ThemeTarget] = []

    for relative in THEME_TARGETS:
        source = Path.home() / relative
        kind = "missing"

        if source.is_dir():
            kind = "directory"
        elif source.is_file():
            kind = "file"

        targets.append(
            ThemeTarget(
                relative_path=relative,
                source=source,
                exists=source.exists(),
                kind=kind,
            )
        )

    return targets


def ensure_state_dirs() -> None:
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)


def make_snapshot_name() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def snapshot_current(name: str | None = None) -> dict:
    ensure_state_dirs()

    snapshot_name = name or make_snapshot_name()
    destination = SNAPSHOT_DIR / snapshot_name

    if destination.exists():
        raise FileExistsError(f"Snapshot already exists: {snapshot_name}")

    files_root = destination / "files"
    files_root.mkdir(parents=True)

    copied: list[dict] = []
    skipped: list[dict] = []

    for target in get_targets():
        if not target.exists:
            skipped.append(
                {
                    "path": target.relative_path,
                    "reason": "missing",
                }
            )
            continue

        target_destination = files_root / target.relative_path
        target_destination.parent.mkdir(parents=True, exist_ok=True)

        if target.source.is_dir():
            shutil.copytree(target.source, target_destination, symlinks=True)
        else:
            shutil.copy2(target.source, target_destination)

        copied.append(
            {
                "path": target.relative_path,
                "kind": target.kind,
            }
        )

    manifest = {
        "name": snapshot_name,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "type": "arcane-themes-snapshot",
        "copied": copied,
        "skipped": skipped,
    }

    (destination / "manifest.json").write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )

    return {
        "snapshot": snapshot_name,
        "path": str(destination),
        "copied": copied,
        "skipped": skipped,
    }


def list_snapshots() -> list[dict]:
    ensure_state_dirs()

    snapshots: list[dict] = []

    for item in sorted(SNAPSHOT_DIR.iterdir(), reverse=True):
        if not item.is_dir():
            continue

        manifest_path = item / "manifest.json"

        if manifest_path.exists():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                manifest = {}
        else:
            manifest = {}

        snapshots.append(
            {
                "name": item.name,
                "path": str(item),
                "created_at": manifest.get("created_at", "unknown"),
                "copied_count": len(manifest.get("copied", [])),
                "skipped_count": len(manifest.get("skipped", [])),
            }
        )

    return snapshots


def status() -> dict:
    targets = get_targets()

    return {
        "state_dir": str(THEMES_STATE_DIR),
        "snapshot_dir": str(SNAPSHOT_DIR),
        "targets": [
            {
                "path": target.relative_path,
                "source": str(target.source),
                "exists": target.exists,
                "kind": target.kind,
            }
            for target in targets
        ],
    }
