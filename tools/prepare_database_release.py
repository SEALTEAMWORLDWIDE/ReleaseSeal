#!/usr/bin/env python3
"""Update reviewed database metadata for a new public database release."""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate_database import ValidationFailure, load_and_validate  # noqa: E402


def atomic_write(path: Path, data: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, path.stat().st_mode)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default="database/ReleaseSealDatabase.json")
    parser.add_argument("--date", help="UTC release date in YYYY-MM-DD format")
    arguments = parser.parse_args()
    path = Path(arguments.database)
    try:
        database, original, _ = load_and_validate(path)
    except ValidationFailure as error:
        print(f"Database preparation failed: {error}", file=sys.stderr)
        return 1

    date_text = arguments.date or datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_text) is None:
        print("Database preparation failed: --date must use YYYY-MM-DD.", file=sys.stderr)
        return 2
    try:
        datetime.date.fromisoformat(date_text)
    except ValueError as error:
        print(f"Database preparation failed: {error}", file=sys.stderr)
        return 2

    metadata = database["metadata"]
    old_version = metadata["databaseVersion"]
    match = re.fullmatch(r"(\d{4}\.\d{2}\.\d{2})\.(\d+)", old_version)
    if match is None:
        print("Database preparation failed: current database version is invalid.", file=sys.stderr)
        return 1
    prefix = date_text.replace("-", ".")
    revision = int(match.group(2)) + 1 if match.group(1) == prefix else 1
    new_version = f"{prefix}.{revision}"
    metadata["databaseVersion"] = new_version
    metadata["releaseDate"] = date_text
    updated = (json.dumps(database, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if updated == original:
        print("Database preparation stopped: metadata did not change.", file=sys.stderr)
        return 1
    atomic_write(path, updated)
    print(f"Database version: {old_version} -> {new_version}")
    print("Review the complete database diff before committing it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

