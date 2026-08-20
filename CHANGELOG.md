# Changelog

## 1.3.0 (29)

- Strengthened app-bundle integrity validation with recursive verification of nested code and sealed resources
- Preserved Deep Scan as a separate internal signer inventory while applying recursive integrity verification to every app scan
- Hardened human-readable reports against misleading line breaks and control characters in hostile filenames
- Added 10 confirmed malicious SHA-256 hashes covering DMG and PKG artifacts
- Expanded the evidence database to 54 certificate records, 1 tracked-file policy, 1 exact verified artifact, and 112 compromised hashes

## 1.2.0 (28)

- Added a gold OUTER SEAL VERIFIED indicator when the selected artifact is authenticated by a recognized valid signature or exact verified-artifact hash
- Added structured outer-seal information to command-line, exported, and JSON output
- Updated machine-readable scan output to schema version 2
- Clarified outer and nested disk-image evidence in summary output
- Improved already-mounted disk-image guidance
- Corrected clipped summary tooltips
- Added five reviewed certificate records for Image-Line, Blackmagic Design, and Parallels Desktop
- Expanded the evidence database to 54 certificate records, 1 tracked-file policy, 1 exact verified artifact, and 102 compromised hashes

## 1.1.1 (27)

- Added DMG, ISO, PKG, ZIP, and app inspection updates introduced after the initial public release
- Added ISO targets, nested ISO inspection, exact ISO artifact hashes, and drag-and-drop support
- Added controlled post-scan mounting, quarantine handling, mounted-image recovery, and license-gated DMG support
- Added an additional code-signing evidence layer for PKG files
- Added mounting preferences without weakening invalid, compromised, or incomplete-scan safety blocks
- Added bounded resource handling, cancellation improvements, and structured post-scan policy conditions
- Expanded the evidence database to 49 certificate records, 1 tracked-file policy, 1 exact verified artifact, and 102 compromised hashes
- Corrected the installation DMG layout so hidden metadata does not displace the visible icons
- Updated the interface, tooltips, Deep Scan artwork, help content, and public website screenshots

## 1.0.0 (14)

- Initial public ReleaseSeal distribution
- Offline GUI and command-line scanning for DMG, PKG, ZIP, and app artifacts
- Layered signature, tracked-file, exact-artifact, and compromised-hash evidence
- Optional deep internal signer reporting
- Public evidence database with validation and contribution workflows
- Built-in local help guide and command-line installation support
