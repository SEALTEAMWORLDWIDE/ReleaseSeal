#!/usr/bin/env python3
"""Regression tests for public application-release metadata rendering."""

from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import Optional


class PrepareApplicationReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source_root = pathlib.Path(__file__).resolve().parent.parent
        cls.script = cls.source_root / "tools/prepare_app_release.py"
        cls.database_bytes = (cls.source_root / "database/ReleaseSealDatabase.json").read_bytes()
        cls.database = json.loads(cls.database_bytes)
        cls.database_sha256 = hashlib.sha256(cls.database_bytes).hexdigest()
        cls.certificate_sha256 = next(
            entry["hash"]
            for entry in cls.database["trustedCertificates"]
            if entry["label"] == "SEAL TEAM WORLDWIDE"
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="releaseseal-public-render-test.")
        self.root = pathlib.Path(self.temporary.name)
        for name in ("README.md", "CHANGELOG.md"):
            shutil.copy2(self.source_root / name, self.root / name)
        for name in ("docs", "database", "release-notes", "tools"):
            shutil.copytree(self.source_root / name, self.root / name)
        self.manifest = self.root / "verification.txt"
        self.release_copy = self.root / "release-copy.json"
        self.write_manifest()
        self.release_copy.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "summary": "This release exercises generated public metadata.",
                    "changes": ["Added one reviewed change", "Updated one reviewed record"],
                },
                indent=2,
            ) + "\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_manifest(self, database_version: Optional[str] = None) -> None:
        version = database_version or self.database["metadata"]["databaseVersion"]
        self.manifest.write_text(
            "\n".join(
                [
                    "ReleaseSeal release verification",
                    "Application version: 9.8.7",
                    "Application build: 654",
                    f"Database version: {version}",
                    f"Database SHA-256: {self.database_sha256}",
                    "Public database commit: 0000000000000000000000000000000000000000",
                    "DMG filename: ReleaseSeal-9.8.7-654.dmg",
                    "DMG SHA-256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    f"Signing certificate SHA-256: {self.certificate_sha256}",
                    "",
                ]
            ),
            encoding="utf-8",
        )

    def run_renderer(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(self.script),
                "--manifest",
                str(self.manifest),
                "--release-copy",
                str(self.release_copy),
                "--root",
                str(self.root),
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_renders_all_release_metadata_from_manifest(self) -> None:
        completed = self.run_renderer()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        release = json.loads((self.root / "docs/release.json").read_text(encoding="utf-8"))
        self.assertEqual(release["version"], "9.8.7")
        self.assertEqual(release["build"], "654")
        self.assertEqual(release["sha256"], "a" * 64)
        self.assertEqual(release["databaseSHA256"], self.database_sha256)
        notes = (self.root / "release-notes/v9.8.7-654.md").read_text(encoding="utf-8")
        self.assertIn("ReleaseSeal 9.8.7 (654)", notes)
        self.assertIn("DMG SHA-256: `" + "a" * 64 + "`", notes)
        self.assertIn("## 9.8.7 (654)", (self.root / "CHANGELOG.md").read_text(encoding="utf-8"))
        self.assertIn("<small>v9.8.7</small>", (self.root / "docs/index.html").read_text(encoding="utf-8"))

    def test_rejects_stale_database_version(self) -> None:
        self.write_manifest(database_version="2000.01.01.1")
        completed = self.run_renderer()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("database version does not match", completed.stderr)

    def test_rejects_missing_document_marker_without_writing_release(self) -> None:
        readme = self.root / "README.md"
        readme.write_text(
            readme.read_text(encoding="utf-8").replace(
                "<!-- RELEASESEAL_CURRENT_RELEASE_END -->",
                "",
            ),
            encoding="utf-8",
        )
        completed = self.run_renderer()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("markers are missing or ambiguous", completed.stderr)
        release = json.loads((self.root / "docs/release.json").read_text(encoding="utf-8"))
        self.assertNotEqual(release["version"], "9.8.7")


if __name__ == "__main__":
    unittest.main()
