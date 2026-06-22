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


def get_snapshot(name: str) -> Path:
    ensure_state_dirs()

    if "/" in name or "\\" in name or name.strip() in {"", ".", ".."}:
        raise ValueError(f"Invalid snapshot name: {name}")

    snapshot = SNAPSHOT_DIR / name

    if not snapshot.exists() or not snapshot.is_dir():
        raise FileNotFoundError(f"No such snapshot: {name}")

    manifest = snapshot / "manifest.json"
    files = snapshot / "files"

    if not manifest.exists() or not files.exists():
        raise FileNotFoundError(f"Snapshot is incomplete or invalid: {name}")

    return snapshot


def load_snapshot_manifest(snapshot: Path) -> dict:
    manifest_path = snapshot / "manifest.json"
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def restore_snapshot(name: str, apply: bool = False) -> dict:
    snapshot = get_snapshot(name)
    manifest = load_snapshot_manifest(snapshot)
    files_root = snapshot / "files"

    planned: list[dict] = []
    restored: list[dict] = []
    missing: list[dict] = []

    for item in manifest.get("copied", []):
        relative = item["path"]
        source = files_root / relative
        destination = Path.home() / relative

        if not source.exists():
            missing.append({"path": relative, "reason": "missing-from-snapshot"})
            continue

        planned.append(
            {
                "path": relative,
                "kind": item.get("kind", "unknown"),
                "source": str(source),
                "destination": str(destination),
                "exists_now": destination.exists(),
            }
        )

    safety_snapshot = None

    if apply and planned:
        safety_snapshot = snapshot_current(name=f"pre-restore-{make_snapshot_name()}")

        for item in planned:
            source = Path(item["source"])
            destination = Path(item["destination"])
            destination.parent.mkdir(parents=True, exist_ok=True)

            if destination.exists() or destination.is_symlink():
                if destination.is_dir() and not destination.is_symlink():
                    shutil.rmtree(destination)
                else:
                    destination.unlink()

            if source.is_dir():
                shutil.copytree(source, destination, symlinks=True)
            else:
                shutil.copy2(source, destination)

            restored.append(
                {
                    "path": item["path"],
                    "kind": item["kind"],
                }
            )

    return {
        "snapshot": name,
        "snapshot_path": str(snapshot),
        "apply": apply,
        "planned": planned,
        "restored": restored,
        "missing": missing,
        "safety_snapshot": safety_snapshot,
    }
