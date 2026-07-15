# ReleaseSeal

ReleaseSeal is an offline defensive macOS inspection tool for comparing release evidence with a reviewed database. It checks signed DMG, PKG, ZIP, and app artifacts, exact artifact hashes, tracked files, certificate identities, code-signing integrity, and known compromised hashes.

ReleaseSeal does not execute inspected software. It does not claim that a matching item is malware-free. A match means that the observed evidence matches a reviewed database entry or an Apple-anchored signature class described by the report.

[Download the latest official release](https://github.com/SEALTEAMWORLDWIDE/ReleaseSeal/releases/latest) | [Project website](https://sealteamworldwide.github.io/ReleaseSeal/) | [Database summary](database/SUMMARY.md)

## Public repository scope

This repository provides:

- Official ReleaseSeal binary releases and verification material
- The public ReleaseSeal evidence database
- Database validation and contribution tools
- Public documentation, policies, and the project website
- Issue and pull request workflows for evidence submissions

The Swift GUI and application source are currently maintained in a private repository. GitHub's automatically generated source archives for this repository contain the public database, website, documentation, and validation tools. They do not contain the private application source.

## Current release

- ReleaseSeal: `1.0.0 (14)`
- macOS: `12 or later`
- Architectures: `arm64 and x86_64 (Universal 2)`
- Database: `2026.07.15.1`
- Database SHA-256: `dffe4c70a7d4fea1de42bbd4c5212157cd844174700675633417530ce02800d8`
- Signing certificate SHA-256: `5b3320483fc794488cc7caa4c3b6eca9178b7350a20fb38190b106742206b333`

The initial release DMG SHA-256 is:

```text
1acd19b68511b8922eda8c61a5d16aaa12f1ee680da251e80cc083f38d12b0b8  ReleaseSeal-1.0.0-14.dmg
```

Always compare this value with the checksum attached to the corresponding GitHub Release. A later release will have a different filename and digest.

## Verify ReleaseSeal

Compare the downloaded DMG with the SHA-256 published for that specific ReleaseSeal build:

```sh
shasum -a 256 "/path/to/ReleaseSeal.dmg"
```

Validate the DMG signature and calculate the embedded certificate fingerprint:

```sh
calculate_sha256() {
  (
    codesign --verify --verbose=4 "$1" || exit 1

    temp_root="${TMPDIR:-/tmp}"
    temp_root="${temp_root%/}"
    workdir="$(mktemp -d "$temp_root/releaseseal-cert.XXXXXX")" || exit 1
    cleanup() {
      case "$workdir" in
        "$temp_root"/releaseseal-cert.*) rm -rf -- "$workdir" ;;
      esac
    }
    trap cleanup EXIT
    trap 'exit 130' HUP INT TERM

    codesign -d --extract-certificates="$workdir/cert" "$1" || exit 1
    set -- "$workdir"/cert*
    if [ ! -e "$1" ]; then
      printf '%s\n' "No embedded signing certificates were extracted." >&2
      exit 1
    fi
    shasum -a 256 "$@"
  )
}; calculate_sha256 "/path/to/ReleaseSeal.dmg"
```

Compare the complete certificate SHA-256 with the independently published `SEAL TEAM WORLDWIDE` fingerprint. A matching certificate name is not sufficient. After copying the app to Applications, verify the app bundle and its sealed resources:

```sh
codesign --verify --deep --strict --verbose=2 "/Applications/ReleaseSeal.app"
```

## Command-line tool

ReleaseSeal includes the `releaseseal` command-line tool. Choose **ReleaseSeal > Install Command Line Tool** to create `/usr/local/bin/releaseseal`. The installer refuses to replace a regular file at that path. The bundled binary can also be run directly:

```sh
"/Applications/ReleaseSeal.app/Contents/MacOS/releaseseal" "/path/to/release.dmg"
```

Common commands:

```sh
releaseseal "/path/to/release.dmg"
releaseseal --deep --verbose "/path/to/release.dmg"
releaseseal --json "/path/to/release.dmg"
releaseseal --candidate-json "/path/to/release.dmg"
releaseseal --version
releaseseal --help
```

Exit statuses are 0 for recognized identity and integrity evidence, 1 for review, 2 for invalid or compromised evidence, and 3 for an incomplete scan or command error. Run `releaseseal --help` for the complete option list.

## What the verdicts mean

- Seal of Approval: reviewed identity or exact-artifact evidence matched and the applicable outer integrity checks passed.
- Seal is broken: signed content failed an integrity check. The report identifies the affected evidence where possible.
- Unknown Waters: the observed evidence was valid but was not recognized, or no verifiable identity was available.
- Known Bad Catch: a certificate or artifact hash matched a compromised or revoked database entry.

Outer signed-container evidence matters. For example, a recognized, valid signed DMG confirms the bytes of the DMG as signed even when a modified app inside it retains broken inner signing evidence. ReleaseSeal still reports the inner state so users can understand both layers.

## Privacy and network behavior

ReleaseSeal performs scans locally and does not upload inspected artifacts or contact an update service. The GUI shortens home-directory paths in its visible reports. Before sharing an exported report, review it for filenames or paths that you consider private.

## Database

The canonical database is [`database/ReleaseSealDatabase.json`](database/ReleaseSealDatabase.json). The application bundles an exact, digest-pinned copy from a reviewed public commit.

Tracked-file behavior is data-driven. The current database schema stores these policies under `trustedHelpers`. Each record defines one root-level filename, case sensitivity, display label, expected file kind, accepted size range, optional bounded heuristic profile, accepted SHA-256 hashes, and provenance. The current database tracks `Open Gatekeeper friendly`, but the scanner does not reserve that name in application code.

Validate it with the Python 3 standard library:

```sh
python3 tools/validate_database.py
python3 tools/render_database_summary.py --check
```

A recognized certificate is evidence of signer identity, not a guarantee about every action taken before signing. An exact verified-artifact hash is stronger byte-for-byte evidence for that one artifact. Compromised evidence takes precedence over positive evidence.

The `source` fields record maintainer provenance labels. They do not mean the referenced samples are distributed by this repository.

## Contributions

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening an issue or pull request. Do not upload copyrighted releases, cracks, serials, keys, patchers, malware samples, or links to obtain them. Submit only hashes, certificate metadata, reproducible inspection output, and other non-infringing evidence.

## Security

For sensitive vulnerabilities in ReleaseSeal itself, use GitHub's private vulnerability reporting feature. See [SECURITY.md](SECURITY.md). Do not submit live malware or private signing keys.

## Licensing

Different parts of this repository use different terms. See [LICENSE.md](LICENSE.md) and [BINARY-LICENSE.md](BINARY-LICENSE.md). ReleaseSeal names, logos, and other branding are not granted for reuse except as needed to identify the unmodified official product.
