#!/usr/bin/env python3
"""Render public release metadata from a verified signing manifest and reviewed copy."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate_database import ValidationFailure, load_and_validate  # noqa: E402


class PreparationFailure(Exception):
    pass


def fail(message: str) -> None:
    raise PreparationFailure(message)


def atomic_write(path: Path, text: str) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists():
            os.chmod(temporary, path.stat().st_mode)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def safe_string(value: object, field: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        fail(f"{field} must be a non-empty string of at most {maximum} characters")
    if any(ord(character) < 32 and character not in "\n\t" for character in value):
        fail(f"{field} contains a control character")
    if "\r" in value or "\u2013" in value or "\u2014" in value:
        fail(f"{field} contains unsupported line endings or dash characters")
    return value.strip()


def read_manifest(path: Path) -> dict[str, str]:
    required = {
        "Application version",
        "Application build",
        "Database version",
        "Database SHA-256",
        "Public database commit",
        "DMG filename",
        "DMG SHA-256",
        "Signing certificate SHA-256",
    }
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if ": " not in line:
            continue
        key, value = line.split(": ", 1)
        if key in values:
            fail(f"verification manifest contains duplicate field: {key}")
        values[key] = safe_string(value, f"manifest field {key}", 2048)
    missing = required - values.keys()
    if missing:
        fail("verification manifest is missing: " + ", ".join(sorted(missing)))
    return values


def read_release_copy(path: Path) -> tuple[str, list[str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"release copy is invalid: {error}")
    if set(data) != {"schemaVersion", "summary", "changes"} or data["schemaVersion"] != 1:
        fail("release copy must contain schemaVersion 1, summary, and changes")
    summary = safe_string(data["summary"], "release copy summary")
    changes_value = data["changes"]
    if not isinstance(changes_value, list) or not changes_value or len(changes_value) > 50:
        fail("release copy changes must contain between 1 and 50 entries")
    changes = [safe_string(value, f"release copy change {index + 1}", 1000) for index, value in enumerate(changes_value)]
    return summary, changes


def replace_region(text: str, start: str, end: str, replacement: str, name: str) -> str:
    if text.count(start) != 1 or text.count(end) != 1:
        fail(f"{name} markers are missing or ambiguous")
    before, remainder = text.split(start, 1)
    _, after = remainder.split(end, 1)
    return before + start + "\n" + replacement.rstrip() + "\n" + end + after


def update_changelog(text: str, version: str, build: str, changes: list[str]) -> str:
    heading = f"## {version} ({build})"
    entry = heading + "\n\n" + "\n".join(f"- {change}" for change in changes) + "\n"
    pattern = re.compile(r"^## ([0-9A-Za-z.+-]+) \(([0-9.]+)\)$", re.MULTILINE)
    headings = list(pattern.finditer(text))
    matching = [match for match in headings if match.group(0) == heading]
    if len(matching) > 1:
        fail("CHANGELOG.md contains duplicate target release headings")
    if matching:
        match = matching[0]
        if match != headings[0]:
            fail("target release already exists below the newest changelog entry")
        end = headings[1].start() if len(headings) > 1 else len(text)
        return text[:match.start()] + entry + "\n" + text[end:].lstrip("\n")
    prefix = "# Changelog\n\n"
    if not text.startswith(prefix):
        fail("CHANGELOG.md does not begin with the expected title")
    return prefix + entry + "\n" + text[len(prefix):]


def release_notes(
    version: str,
    build: str,
    summary: str,
    changes: list[str],
    filename: str,
    dmg_sha256: str,
    certificate_sha256: str,
    database_version: str,
    database_sha256: str,
) -> str:
    bullets = "\n".join(f"- {change}." if not change.endswith((".", "!", "?")) else f"- {change}" for change in changes)
    return f"""# ReleaseSeal {version} ({build})

{summary}

ReleaseSeal performs scans locally and does not execute inspected software. A recognized identity or exact-artifact match is evidence about the inspected bytes and signature state, not a malware-free guarantee.

## Changes

{bullets}

## Verification

- DMG: `{filename}`
- DMG SHA-256: `{dmg_sha256}`
- Signing certificate SHA-256: `{certificate_sha256}`
- Database version: `{database_version}`
- Database SHA-256: `{database_sha256}`

Download the DMG, checksum, verification manifest, and public certificate from this release. GitHub-generated source archives contain the public database, website, documentation, and validation tools, not the private Swift application source.
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--release-copy", required=True, type=Path)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    arguments = parser.parse_args()
    root = arguments.root.resolve()

    try:
        manifest = read_manifest(arguments.manifest)
        summary, changes = read_release_copy(arguments.release_copy)
        version = manifest["Application version"]
        build = manifest["Application build"]
        filename = manifest["DMG filename"]
        dmg_sha256 = manifest["DMG SHA-256"]
        certificate_sha256 = manifest["Signing certificate SHA-256"]
        database_version = manifest["Database version"]
        database_sha256 = manifest["Database SHA-256"]

        if re.fullmatch(r"[0-9A-Za-z.+-]+", version) is None:
            fail("application version is invalid")
        if re.fullmatch(r"[0-9]+", build) is None:
            fail("application build is invalid")
        if filename != f"ReleaseSeal-{version}-{build}.dmg":
            fail("DMG filename does not match version and build")
        for label, digest in (
            ("DMG SHA-256", dmg_sha256),
            ("certificate SHA-256", certificate_sha256),
            ("database SHA-256", database_sha256),
        ):
            if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                fail(f"{label} is invalid")
        if re.fullmatch(r"[0-9a-f]{40}", manifest["Public database commit"]) is None:
            fail("public database commit is invalid")

        try:
            database, database_bytes, _ = load_and_validate(root / "database/ReleaseSealDatabase.json")
        except ValidationFailure as error:
            fail(f"public database is invalid: {error}")
        if database["metadata"]["databaseVersion"] != database_version:
            fail("signed release database version does not match the public database")
        if hashlib.sha256(database_bytes).hexdigest() != database_sha256:
            fail("signed release database bytes do not match the public database")
        if not any(entry.get("hash") == certificate_sha256 for entry in database["trustedCertificates"]):
            fail("release signing certificate is not recognized by the public database")

        tag = f"v{version}-{build}"
        release = {
            "version": version,
            "build": build,
            "tag": tag,
            "filename": filename,
            "sha256": dmg_sha256,
            "certificateSHA256": certificate_sha256,
            "databaseVersion": database_version,
            "databaseSHA256": database_sha256,
            "downloadURL": "https://github.com/SEALTEAMWORLDWIDE/ReleaseSeal/releases/latest",
        }

        readme_path = root / "README.md"
        readme = readme_path.read_text(encoding="utf-8")
        readme_region = f"""- ReleaseSeal: `{version} ({build})`
- macOS: `12 or later`
- Architectures: `arm64 and x86_64 (Universal 2)`
- Database: `{database_version}`
- Database SHA-256: `{database_sha256}`
- Signing certificate SHA-256: `{certificate_sha256}`

The current release DMG SHA-256 is:

```text
{dmg_sha256}  {filename}
```

Always compare this value with the checksum attached to the corresponding GitHub Release. A later release will have a different filename and digest."""
        readme = replace_region(
            readme,
            "<!-- RELEASESEAL_CURRENT_RELEASE_START -->",
            "<!-- RELEASESEAL_CURRENT_RELEASE_END -->",
            readme_region,
            "README current-release",
        )

        website_path = root / "docs/index.html"
        website = website_path.read_text(encoding="utf-8")
        website = replace_region(
            website,
            "<!-- RELEASESEAL_HEADER_VERSION_START -->",
            "<!-- RELEASESEAL_HEADER_VERSION_END -->",
            f"        <small>v{html.escape(version)}</small>",
            "website header-version",
        )
        certificate_short = certificate_sha256[:16] + "…" + certificate_sha256[-7:]
        database_short = database_sha256[:12] + "…" + database_sha256[-8:]
        verification_html = f"""      <div class="verify-grid">
        <div class="terminal">
          <div class="terminal-title">ReleaseSeal {html.escape(version)} ({html.escape(build)})</div>
          <pre><code>$ shasum -a 256 {html.escape(filename)}
{dmg_sha256}</code></pre>
        </div>
        <dl class="release-facts">
          <div><dt>Signing identity</dt><dd>SEAL TEAM WORLDWIDE</dd></div>
          <div><dt>Certificate SHA-256</dt><dd>{certificate_short}</dd></div>
          <div><dt>Database version</dt><dd>{html.escape(database_version)}</dd></div>
          <div><dt>Database SHA-256</dt><dd>{database_short}</dd></div>
        </dl>
      </div>"""
        website = replace_region(
            website,
            "<!-- RELEASESEAL_VERIFICATION_START -->",
            "<!-- RELEASESEAL_VERIFICATION_END -->",
            verification_html,
            "website release-verification",
        )

        changelog_path = root / "CHANGELOG.md"
        changelog = update_changelog(
            changelog_path.read_text(encoding="utf-8"),
            version,
            build,
            changes,
        )
        notes_path = root / "release-notes" / f"{tag}.md"
        notes = release_notes(
            version,
            build,
            summary,
            changes,
            filename,
            dmg_sha256,
            certificate_sha256,
            database_version,
            database_sha256,
        )

        atomic_write(root / "docs/release.json", json.dumps(release, indent=2) + "\n")
        atomic_write(readme_path, readme)
        atomic_write(website_path, website)
        atomic_write(changelog_path, changelog)
        atomic_write(notes_path, notes)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, PreparationFailure) as error:
        print(f"Application release preparation failed: {error}", file=sys.stderr)
        return 1

    print(f"Prepared public metadata for ReleaseSeal {version} ({build}).")
    print(f"Release notes: {notes_path}")
    print("Review every generated diff before committing or publishing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
