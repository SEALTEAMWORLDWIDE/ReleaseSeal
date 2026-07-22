#!/usr/bin/env python3
"""Generate the reviewed human-readable database summary."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate_database import ValidationFailure, load_and_validate  # noqa: E402


def certificate_sort_key(entry: dict) -> tuple[str, str, str]:
    """Sort signer rows by identity rather than Apple's repeated certificate prefix."""
    label = entry["label"].strip()
    normalized = label.casefold()
    for prefix in (
        "developer id application: ",
        "developer id installer: ",
        "3rd party mac developer application: ",
        "3rd party mac developer installer: ",
    ):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
            break
    if normalized.startswith("the "):
        normalized = normalized[4:]
    if normalized.startswith("team "):
        normalized = normalized[5:]
    if normalized.startswith("https://"):
        normalized = normalized[8:]
    if normalized.startswith("www."):
        normalized = normalized[4:]
    if label == "Software Signing" and "/O=Apple Inc." in entry.get("subject", ""):
        normalized = "apple software signing"
    return normalized, entry["type"], entry["hash"]


def render(database: dict, raw: bytes) -> str:
    metadata = database["metadata"]
    lines = [
        "# ReleaseSeal database summary",
        "",
        "This file is generated from `ReleaseSealDatabase.json`. The JSON database is authoritative.",
        "",
        f"- Database version: `{metadata['databaseVersion']}`",
        f"- Release date: `{metadata['releaseDate']}`",
        f"- Database SHA-256: `{hashlib.sha256(raw).hexdigest()}`",
        f"- Trusted certificate entries: `{len(database['trustedCertificates'])}`",
        f"- Tracked file entries: `{len(database['trustedHelpers'])}`",
        f"- Exact verified artifacts: `{len(database['verifiedArtifacts'])}`",
        f"- Compromised or revoked entries: `{len(database['compromised'])}`",
        "",
        "A recognized certificate or exact artifact is evidence of an expected identity or exact byte match. It is not a malware-free guarantee.",
        "",
        "## Mac App Store signatures",
        "",
        "ReleaseSeal also recognizes valid Apple-anchored Mac App Store signatures directly from macOS signing evidence. Mac App Store recognition is built into the scanner, so those signatures are not certificate allowlist entries and are not included in the trusted-certificate count above.",
        "",
        "## Recognized release signers",
        "",
        "| Label | Certificate pin | Expires |",
        "| --- | --- | --- |",
    ]
    for entry in sorted(database["trustedCertificates"], key=certificate_sort_key):
        expires = entry.get("expires", "Not recorded")[:10]
        label = entry["label"].replace("|", "\\|")
        lines.append(f"| {label} | `{entry['type']}` `{entry['hash']}` | {expires} |")

    lines.extend(["", "## Tracked files", ""])
    for entry in database["trustedHelpers"]:
        sensitivity = "case-sensitive" if entry["caseSensitive"] else "case-insensitive"
        lines.append(
            f"- {entry['label']}: filename `{entry['fileName']}` ({sensitivity}), "
            f"kind `{entry['expectedKind']}`, size `{entry['minimumSize']}-{entry['maximumSize']}` bytes"
        )
        for digest in entry["sha256"]:
            lines.append(f"  - `sha256:{digest}`")

    lines.extend(["", "## Exact verified artifacts", ""])
    if database["verifiedArtifacts"]:
        for entry in database["verifiedArtifacts"]:
            lines.append(f"- {entry['label']}: `{entry['type']}:{entry['hash']}`")
    else:
        lines.append("No exact artifacts are currently listed.")

    lines.extend(
        [
            "",
            "## Compromised evidence",
            "",
            f"The database currently contains {len(database['compromised'])} compromised or revoked hashes.",
            "Individual entries remain in the JSON database so tools can consume them without turning this summary into a wall of text.",
            "",
            "## Provenance note",
            "",
            "Some JSON entries include a `source` field describing the maintainer's local verification sample or submitted corpus. Those paths are provenance labels only. This repository does not host, link to, or distribute those samples.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default="database/ReleaseSealDatabase.json")
    parser.add_argument("--output", default="database/SUMMARY.md")
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    try:
        database, raw, _ = load_and_validate(Path(arguments.database))
    except ValidationFailure as error:
        print(f"Summary generation failed: {error}", file=sys.stderr)
        return 1
    expected = render(database, raw)
    output = Path(arguments.output)
    if arguments.check:
        try:
            current = output.read_text(encoding="utf-8")
        except OSError:
            current = ""
        if current != expected:
            print(f"Generated summary is stale: {output}", file=sys.stderr)
            return 1
        print("Database summary is current.")
        return 0
    output.write_text(expected, encoding="utf-8")
    print(f"Wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
