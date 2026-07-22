#!/usr/bin/env python3
"""Check published release metadata and its relationship to the current database."""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys


def fail(message: str) -> None:
    raise SystemExit(f"Release metadata validation failed: {message}")


def database_version_key(value: str) -> tuple[int, int, int, int]:
    match = re.fullmatch(r"(\d{4})\.(\d{2})\.(\d{2})\.(\d+)", value)
    if match is None:
        fail(f"invalid database version: {value}")
    return tuple(int(part) for part in match.groups())


def validate_changelog(root: pathlib.Path, release: dict[str, str]) -> None:
    changelog_path = root / "CHANGELOG.md"
    changelog = changelog_path.read_text(encoding="utf-8")
    if not changelog.startswith("# Changelog\n"):
        fail("CHANGELOG.md does not begin with the expected title")

    headings = re.findall(
        r"^## ([0-9A-Za-z.+-]+) \(([0-9.]+)\)$",
        changelog,
        flags=re.MULTILINE,
    )
    if not headings:
        fail("CHANGELOG.md does not contain any version headings")
    expected = (release["version"], release["build"])
    if headings[0] != expected:
        fail(
            "CHANGELOG.md latest entry does not match the current release: "
            f"expected {expected[0]} ({expected[1]})"
        )
    if len(headings) != len(set(headings)):
        fail("CHANGELOG.md contains a duplicate version and build heading")

    changelog_releases = set(headings)
    for notes_path in (root / "release-notes").glob("*.md"):
        match = re.fullmatch(
            r"v([0-9A-Za-z.+-]+)-([0-9.]+)\.md",
            notes_path.name,
        )
        if match is None:
            fail(f"unsupported release-notes filename: {notes_path.name}")
        notes_release = (match.group(1), match.group(2))
        if notes_release not in changelog_releases:
            fail(
                "CHANGELOG.md is missing the release-notes entry for "
                f"{notes_release[0]} ({notes_release[1]})"
            )


def main() -> int:
    root = pathlib.Path(__file__).resolve().parent.parent
    release = json.loads((root / "docs/release.json").read_text(encoding="utf-8"))
    required = {
        "version", "build", "tag", "filename", "sha256", "certificateSHA256",
        "databaseVersion", "databaseSHA256", "downloadURL",
    }
    if set(release) != required:
        fail("docs/release.json fields are incomplete or unsupported")
    for key, value in release.items():
        if not isinstance(value, str) or not value or "\n" in value or "\r" in value:
            fail(f"docs/release.json field {key} is invalid")
    if release["tag"] != f"v{release['version']}-{release['build']}":
        fail("tag does not match version and build")
    if release["filename"] != f"ReleaseSeal-{release['version']}-{release['build']}.dmg":
        fail("filename does not match version and build")
    for field in ("sha256", "certificateSHA256", "databaseSHA256"):
        if re.fullmatch(r"[0-9a-f]{64}", release[field]) is None:
            fail(f"{field} must be a lowercase SHA-256")

    database_path = root / "database/ReleaseSealDatabase.json"
    database_bytes = database_path.read_bytes()
    database = json.loads(database_bytes)
    current_database_version = database.get("metadata", {}).get("databaseVersion")
    if not isinstance(current_database_version, str):
        fail("current public database version is missing")
    release_database_key = database_version_key(release["databaseVersion"])
    current_database_key = database_version_key(current_database_version)
    if release_database_key > current_database_key:
        fail("published release metadata refers to a database newer than the public database")
    if release_database_key == current_database_key:
        if hashlib.sha256(database_bytes).hexdigest() != release["databaseSHA256"]:
            fail("databaseSHA256 does not match the current public database bytes")
    if not any(entry.get("hash") == release["certificateSHA256"] for entry in database["trustedCertificates"]):
        fail("release signing certificate is not recognized in the public database")

    validate_changelog(root, release)

    notes_path = root / "release-notes" / f"{release['tag']}.md"
    documents = {
        "README.md": (root / "README.md").read_text(encoding="utf-8"),
        str(notes_path.relative_to(root)): notes_path.read_text(encoding="utf-8"),
        "docs/index.html": (root / "docs/index.html").read_text(encoding="utf-8"),
    }
    required_values = (
        release["version"], release["build"], release["filename"],
        release["sha256"], release["databaseVersion"],
    )
    for name, content in documents.items():
        for value in required_values:
            if value not in content:
                fail(f"{name} does not contain current value: {value}")
    for name in ("README.md", str(notes_path.relative_to(root))):
        if release["certificateSHA256"] not in documents[name]:
            fail(f"{name} does not contain the complete signing certificate SHA-256")
    certificate_short = release["certificateSHA256"][:16] + "…" + release["certificateSHA256"][-7:]
    if certificate_short not in documents["docs/index.html"]:
        fail("docs/index.html does not contain the expected shortened certificate SHA-256")
    header_version = f"<small>v{release['version']}</small>"
    if header_version not in documents["docs/index.html"]:
        fail("docs/index.html header does not match the current application version")

    print("Release metadata validation passed.")
    print(f"Release: {release['version']} ({release['build']})")
    print(f"Tag: {release['tag']}")
    if release_database_key < current_database_key:
        print(
            "Note: the public database is newer than the database bundled with "
            "the currently documented release."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
