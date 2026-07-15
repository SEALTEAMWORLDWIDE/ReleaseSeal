#!/usr/bin/env python3
"""Validate the public ReleaseSeal evidence database using only Python 3."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any

MAX_DATABASE_BYTES = 8 * 1024 * 1024
HEX_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}
CERTIFICATE_TYPES = {
    "root-sha256",
    "leaf-sha256",
}
ARTIFACT_TYPES = {
    "dmg-sha256",
    "pkg-sha256",
    "zip-sha256",
}
COMPROMISED_TYPES = {
    "cert-sha1",
    "cert-sha256",
    "cert-root-sha1",
    "cert-leaf-sha1",
    "cert-root-sha256",
    "cert-leaf-sha256",
    "dmg-md5",
    "dmg-sha1",
    "dmg-sha256",
    "pkg-md5",
    "pkg-sha1",
    "pkg-sha256",
    "zip-md5",
    "zip-sha1",
    "zip-sha256",
}
FORBIDDEN_DIRECTIONAL_CODEPOINTS = {
    0x061C,
    0x200E,
    0x200F,
    0x202A,
    0x202B,
    0x202C,
    0x202D,
    0x202E,
    0x2066,
    0x2067,
    0x2068,
    0x2069,
}
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
VERSION_RE = re.compile(r"^\d{4}\.\d{2}\.\d{2}\.\d+$")
ISO_DATE_TIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$"
)


class ValidationFailure(Exception):
    pass


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationFailure(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def require_object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationFailure(f"{context} must be an object")
    return value


def require_list(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValidationFailure(f"{context} must be an array")
    return value


def require_exact_keys(value: dict[str, Any], required: set[str], optional: set[str], context: str) -> None:
    missing = required - value.keys()
    extra = value.keys() - required - optional
    if missing:
        raise ValidationFailure(f"{context} is missing: {', '.join(sorted(missing))}")
    if extra:
        raise ValidationFailure(f"{context} has unsupported fields: {', '.join(sorted(extra))}")


def require_safe_string(value: Any, context: str, *, allow_empty: bool = False, max_length: int = 4096) -> str:
    if not isinstance(value, str):
        raise ValidationFailure(f"{context} must be a string")
    if not allow_empty and not value.strip():
        raise ValidationFailure(f"{context} must not be empty")
    if len(value) > max_length:
        raise ValidationFailure(f"{context} exceeds {max_length} characters")
    for character in value:
        codepoint = ord(character)
        if codepoint in FORBIDDEN_DIRECTIONAL_CODEPOINTS:
            raise ValidationFailure(f"{context} contains a directional control character")
        category = unicodedata.category(character)
        if category == "Cc" and character not in "\n\t":
            raise ValidationFailure(f"{context} contains a control character")
    return value


def require_hash(value: Any, algorithm: str, context: str) -> str:
    text = require_safe_string(value, context, max_length=64)
    expected = HEX_LENGTHS[algorithm]
    if re.fullmatch(rf"[0-9a-f]{{{expected}}}", text) is None:
        raise ValidationFailure(f"{context} must be {expected} lowercase hexadecimal characters")
    return text


def hash_algorithm(entry_type: str) -> str:
    if entry_type.endswith("sha256"):
        return "sha256"
    if entry_type.endswith("sha1"):
        return "sha1"
    if entry_type.endswith("md5"):
        return "md5"
    raise ValidationFailure(f"unsupported hash type: {entry_type}")


def validate_database(data: dict[str, Any]) -> dict[str, int]:
    require_exact_keys(
        data,
        {"schemaVersion", "metadata", "trustedCertificates", "trustedHelpers", "verifiedArtifacts", "compromised"},
        set(),
        "database",
    )
    if data["schemaVersion"] != 2:
        raise ValidationFailure("schemaVersion must be 2")

    metadata = require_object(data["metadata"], "metadata")
    require_exact_keys(metadata, {"name", "databaseVersion", "releaseDate", "notes"}, set(), "metadata")
    require_safe_string(metadata["name"], "metadata.name", max_length=200)
    version = require_safe_string(metadata["databaseVersion"], "metadata.databaseVersion", max_length=32)
    release_date = require_safe_string(metadata["releaseDate"], "metadata.releaseDate", max_length=10)
    require_safe_string(metadata["notes"], "metadata.notes", max_length=1000)
    if VERSION_RE.fullmatch(version) is None:
        raise ValidationFailure("metadata.databaseVersion must use YYYY.MM.DD.REVISION")
    if DATE_RE.fullmatch(release_date) is None:
        raise ValidationFailure("metadata.releaseDate must use YYYY-MM-DD")
    try:
        datetime.date.fromisoformat(release_date)
    except ValueError as error:
        raise ValidationFailure("metadata.releaseDate is not a valid date") from error

    certificate_keys: set[tuple[str, str]] = set()
    certificates = require_list(data["trustedCertificates"], "trustedCertificates")
    for index, raw in enumerate(certificates):
        context = f"trustedCertificates[{index}]"
        entry = require_object(raw, context)
        require_exact_keys(
            entry,
            {"type", "hash", "label", "subject", "expires", "source"},
            {"notes"},
            context,
        )
        entry_type = require_safe_string(entry["type"], f"{context}.type", max_length=32)
        if entry_type not in CERTIFICATE_TYPES:
            raise ValidationFailure(f"{context}.type is unsupported: {entry_type}")
        digest = require_hash(entry["hash"], "sha256", f"{context}.hash")
        require_safe_string(entry["label"], f"{context}.label", max_length=300)
        for field in ("subject", "source"):
            require_safe_string(entry[field], f"{context}.{field}", max_length=2000)
        if "notes" in entry:
            require_safe_string(entry["notes"], f"{context}.notes", max_length=2000)
        expires = require_safe_string(entry["expires"], f"{context}.expires", max_length=40)
        if ISO_DATE_TIME_RE.fullmatch(expires) is None:
            raise ValidationFailure(f"{context}.expires must use UTC ISO 8601 format")
        try:
            datetime.datetime.fromisoformat(expires.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValidationFailure(f"{context}.expires is not a valid timestamp") from error
        key = (entry_type, digest)
        if key in certificate_keys:
            raise ValidationFailure(f"duplicate trusted certificate at {context}")
        certificate_keys.add(key)

    helper_hashes: set[str] = set()
    helper_identifiers: set[str] = set()
    helper_file_names: set[str] = set()
    helpers = require_list(data["trustedHelpers"], "trustedHelpers")
    for index, raw in enumerate(helpers):
        context = f"trustedHelpers[{index}]"
        entry = require_object(raw, context)
        require_exact_keys(
            entry,
            {
                "identifier", "fileName", "caseSensitive", "label", "expectedKind",
                "minimumSize", "maximumSize", "heuristicProfile",
                "heuristicMaximumSize", "sha256", "source",
            },
            {"notes"},
            context,
        )
        identifier = require_safe_string(entry["identifier"], f"{context}.identifier", max_length=128)
        if re.fullmatch(r"[a-z0-9][a-z0-9._-]*", identifier) is None:
            raise ValidationFailure(f"{context}.identifier must be a lowercase stable identifier")
        file_name = require_safe_string(entry["fileName"], f"{context}.fileName", max_length=255)
        if file_name in {".", ".."} or "/" in file_name or ":" in file_name:
            raise ValidationFailure(f"{context}.fileName must be one safe filename")
        if type(entry["caseSensitive"]) is not bool:
            raise ValidationFailure(f"{context}.caseSensitive must be true or false")
        require_safe_string(entry["label"], f"{context}.label", max_length=512)
        expected_kind = require_safe_string(entry["expectedKind"], f"{context}.expectedKind", max_length=32)
        if expected_kind not in {"text-script", "plain-text", "mach-o", "regular-file"}:
            raise ValidationFailure(f"{context}.expectedKind is unsupported")
        heuristic = require_safe_string(entry["heuristicProfile"], f"{context}.heuristicProfile", max_length=32)
        if heuristic not in {"none", "shell-script-risk"}:
            raise ValidationFailure(f"{context}.heuristicProfile is unsupported")
        if heuristic == "shell-script-risk" and expected_kind not in {"text-script", "plain-text"}:
            raise ValidationFailure(f"{context} shell-script heuristics require a text kind")
        for field in ("minimumSize", "maximumSize", "heuristicMaximumSize"):
            if type(entry[field]) is not int or entry[field] < 0:
                raise ValidationFailure(f"{context}.{field} must be a non-negative integer")
        if entry["minimumSize"] > entry["maximumSize"]:
            raise ValidationFailure(f"{context} minimumSize exceeds maximumSize")
        if entry["maximumSize"] > 100 * 1024 * 1024:
            raise ValidationFailure(f"{context}.maximumSize exceeds the 100 MiB policy limit")
        if entry["heuristicMaximumSize"] > entry["maximumSize"]:
            raise ValidationFailure(f"{context}.heuristicMaximumSize exceeds maximumSize")
        hashes = require_list(entry["sha256"], f"{context}.sha256")
        if not hashes or len(hashes) > 256:
            raise ValidationFailure(f"{context}.sha256 must contain 1 to 256 hashes")
        normalized_hashes = [require_hash(value, "sha256", f"{context}.sha256") for value in hashes]
        if len(set(normalized_hashes)) != len(normalized_hashes):
            raise ValidationFailure(f"{context}.sha256 contains a duplicate")
        require_safe_string(entry["source"], f"{context}.source", max_length=4096)
        if "notes" in entry:
            require_safe_string(entry["notes"], f"{context}.notes", max_length=8192)
        identifier_key = identifier.lower()
        file_name_key = file_name.lower()
        if identifier_key in helper_identifiers or file_name_key in helper_file_names:
            raise ValidationFailure(f"duplicate trusted helper identity or filename at {context}")
        if any(digest in helper_hashes for digest in normalized_hashes):
            raise ValidationFailure(f"duplicate trusted helper hash at {context}")
        helper_identifiers.add(identifier_key)
        helper_file_names.add(file_name_key)
        helper_hashes.update(normalized_hashes)

    verified_keys: set[tuple[str, str]] = set()
    artifacts = require_list(data["verifiedArtifacts"], "verifiedArtifacts")
    for index, raw in enumerate(artifacts):
        context = f"verifiedArtifacts[{index}]"
        entry = require_object(raw, context)
        require_exact_keys(
            entry,
            {"type", "hash", "label", "verifiedAt", "source"},
            {"notes"},
            context,
        )
        entry_type = require_safe_string(entry["type"], f"{context}.type", max_length=32)
        if entry_type not in ARTIFACT_TYPES:
            raise ValidationFailure(f"{context}.type is unsupported: {entry_type}")
        digest = require_hash(entry["hash"], "sha256", f"{context}.hash")
        require_safe_string(entry["label"], f"{context}.label", max_length=500)
        date = require_safe_string(entry["verifiedAt"], f"{context}.verifiedAt", max_length=10)
        if DATE_RE.fullmatch(date) is None:
            raise ValidationFailure(f"{context}.verifiedAt must use YYYY-MM-DD")
        try:
            datetime.date.fromisoformat(date)
        except ValueError as error:
            raise ValidationFailure(f"{context}.verifiedAt is not a valid date") from error
        require_safe_string(entry["source"], f"{context}.source", max_length=2000)
        if "notes" in entry:
            require_safe_string(entry["notes"], f"{context}.notes", max_length=2000)
        key = (entry_type, digest)
        if key in verified_keys:
            raise ValidationFailure(f"duplicate verified artifact at {context}")
        verified_keys.add(key)

    compromised_keys: set[tuple[str, str]] = set()
    compromised_artifact_sha256: set[tuple[str, str]] = set()
    compromised = require_list(data["compromised"], "compromised")
    for index, raw in enumerate(compromised):
        context = f"compromised[{index}]"
        entry = require_object(raw, context)
        require_exact_keys(entry, {"type", "hash", "status", "label"}, {"source"}, context)
        entry_type = require_safe_string(entry["type"], f"{context}.type", max_length=32)
        if entry_type not in COMPROMISED_TYPES:
            raise ValidationFailure(f"{context}.type is unsupported: {entry_type}")
        digest = require_hash(entry["hash"], hash_algorithm(entry_type), f"{context}.hash")
        status = require_safe_string(entry["status"], f"{context}.status", max_length=32)
        if status not in {"compromised", "revoked"}:
            raise ValidationFailure(f"{context}.status must be compromised or revoked")
        require_safe_string(entry["label"], f"{context}.label", max_length=2000)
        if "source" in entry:
            require_safe_string(entry["source"], f"{context}.source", max_length=2000)
        key = (entry_type, digest)
        if key in compromised_keys:
            raise ValidationFailure(f"duplicate compromised entry at {context}")
        compromised_keys.add(key)
        if entry_type in ARTIFACT_TYPES:
            compromised_artifact_sha256.add(key)

    overlap = verified_keys & compromised_artifact_sha256
    if overlap:
        kind, digest = sorted(overlap)[0]
        raise ValidationFailure(f"artifact is both verified and compromised: {kind} {digest}")

    return {
        "trustedCertificates": len(certificates),
        "trustedHelpers": len(helpers),
        "verifiedArtifacts": len(artifacts),
        "compromised": len(compromised),
    }


def load_and_validate(path: Path) -> tuple[dict[str, Any], bytes, dict[str, int]]:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ValidationFailure(f"cannot read database: {error}") from error
    if size > MAX_DATABASE_BYTES:
        raise ValidationFailure(f"database exceeds {MAX_DATABASE_BYTES} bytes")
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValidationFailure("database is not valid UTF-8") from error
    try:
        data = json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except (json.JSONDecodeError, ValidationFailure) as error:
        raise ValidationFailure(f"invalid JSON: {error}") from error
    database = require_object(data, "database")
    counts = validate_database(database)
    return database, raw, counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", nargs="?", default="database/ReleaseSealDatabase.json")
    parser.add_argument("--json", action="store_true", dest="json_output", help="emit machine-readable results")
    arguments = parser.parse_args()
    path = Path(arguments.database)
    try:
        database, raw, counts = load_and_validate(path)
    except (OSError, ValidationFailure) as error:
        if arguments.json_output:
            print(json.dumps({"valid": False, "error": str(error)}, sort_keys=True))
        else:
            print(f"Database validation failed: {error}", file=sys.stderr)
        return 1

    result = {
        "valid": True,
        "databaseVersion": database["metadata"]["databaseVersion"],
        "releaseDate": database["metadata"]["releaseDate"],
        "sha256": hashlib.sha256(raw).hexdigest(),
        "counts": counts,
    }
    if arguments.json_output:
        print(json.dumps(result, sort_keys=True))
    else:
        tracked_file_label = "entry" if counts["trustedHelpers"] == 1 else "entries"
        artifact_label = "artifact" if counts["verifiedArtifacts"] == 1 else "artifacts"
        print("Database validation passed.")
        print(f"Version: {result['databaseVersion']}")
        print(f"Release date: {result['releaseDate']}")
        print(f"SHA-256: {result['sha256']}")
        print(
            "Entries: "
            f"{counts['trustedCertificates']} certificates, "
            f"{counts['trustedHelpers']} tracked-file {tracked_file_label}, "
            f"{counts['verifiedArtifacts']} verified {artifact_label}, "
            f"{counts['compromised']} compromised hashes"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
