# Changelog

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
