# Security policy

## Reporting a vulnerability

Use GitHub private vulnerability reporting for sensitive flaws in ReleaseSeal, its database verification, its packaging, or its release process. Please include the affected version, impact, reproduction steps, and the smallest safe proof needed to demonstrate the problem.

For non-sensitive correctness problems, open a normal issue.

Do not post or attach:

- Live malware or weaponized proof-of-concept code
- Copyrighted releases, cracks, patchers, license keys, or serials
- Private signing keys, passwords, tokens, or personal information
- Links whose primary purpose is obtaining pirated or malicious material

Hashes, certificate fingerprints, redacted command output, and safe synthetic test cases are welcome.

## Scope and expectations

ReleaseSeal is a defensive evidence inspection tool. It does not execute inspected software and is not a replacement for malware analysis. A recognized signature or artifact match does not prove that an artifact is malware-free.

The project may publicly credit a reporter with permission. Response and remediation times are best-effort because this is a free community project.

## Verifying official releases

Official releases are published through this repository's GitHub Releases section with a SHA-256 checksum, verification manifest, and public signing certificate. Compare all verification details before first launch. The project website and README also identify the current release.

