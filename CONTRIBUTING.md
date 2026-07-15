# Contributing evidence

ReleaseSeal accepts narrowly scoped defensive evidence contributions. A submission is a review candidate, not an automatic trust decision.

## Never submit release files

Do not upload or link to copyrighted releases, cracks, patchers, serials, keys, malware samples, or other distributable payloads. Submit only metadata and reproducible evidence that the project can legally and safely review.

## Recognized certificate candidates

Include:

- Proposed label and release-group name
- Pin type: `root-sha256` or `leaf-sha256`
- Lowercase SHA-256 certificate fingerprint
- Complete certificate subject and expiration date
- Whether the certificate is self-signed or part of a chain
- The artifact layer where it was observed, such as DMG or app bundle
- Redacted command output that another reviewer can reproduce
- A non-sensitive explanation of how provenance was established

For a candidate JSON object, ReleaseSeal users can run:

```sh
releaseseal --candidate-json /path/to/item
```

Review and remove private paths before posting the output.

## Exact verified artifact candidates

Exact artifact entries support DMG, PKG, and ZIP SHA-256 hashes. Include the proposed label, lowercase SHA-256, artifact type, verification date, and a concise provenance explanation. Raw app directories are intentionally not accepted as exact artifacts.

## Tracked file candidates

Tracked-file records currently describe a specifically named file found at the root of a mounted DMG. Include:

- A stable lowercase identifier
- Exact filename and whether matching should be case-sensitive
- Display label
- Expected kind: text script, plain text, Mach-O, or regular file
- Minimum and maximum expected byte size
- Lowercase SHA-256 of every independently verified version
- Whether the bounded shell-script risk profile should apply to unrecognized variants
- Safe provenance and notes explaining why the file should receive a dedicated check

Do not submit the tracked file itself. A new hash or relaxed policy is accepted only after independent review. Database policy can identify and inspect a tracked file, but cannot make arbitrary new application behavior execute.

## Compromised evidence

Include the hash type, lowercase hash, proposed label, evidence source, and whether the entry should be `compromised` or `revoked`. MD5 and SHA-1 artifact hashes are accepted when stronger historical evidence is unavailable, but new evidence should use SHA-256 whenever possible.

Never attach the malicious file.

## Pull requests

1. Edit only the necessary JSON entries.
2. Do not manually change database version or release date metadata unless a maintainer requests it.
3. Run `python3 tools/validate_database.py`.
4. Run `python3 tools/render_database_summary.py` and include the generated summary change.
5. Explain provenance and review limitations in the pull request.

Maintainers prepare release metadata after the evidence change is accepted. Duplicate, conflicting, malformed, or insufficiently sourced entries will be rejected.
