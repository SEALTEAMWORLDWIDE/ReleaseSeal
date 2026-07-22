#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
    echo "Public tree audit failed: $1" >&2
    exit 1
}

python3 tools/validate_database.py
python3 tools/render_database_summary.py --check
python3 tools/validate_release_metadata.py

if find . -path './release-staging' -prune -o -type f \( \
    -name '.DS_Store' -o -name '._*' -o -name '*.p12' -o -name '*.pfx' -o \
    -name '*.key' -o -name '*.pem' -o -name '*.mobileprovision' -o \
    -name '*.dmg' -o -name '*.iso' -o -name '*.pkg' -o -name '*.zip' -o -name '*.app' \
\) -print -quit | /usr/bin/grep -q .; then
    find . -type f \( \
        -name '.DS_Store' -o -name '._*' -o -name '*.p12' -o -name '*.pfx' -o \
        -name '*.key' -o -name '*.pem' -o -name '*.mobileprovision' -o \
        -name '*.dmg' -o -name '*.iso' -o -name '*.pkg' -o -name '*.zip' -o -name '*.app' \
    \) -print >&2
    fail "generated release output or private signing material is present."
fi

if /usr/bin/grep -RIlE \
    '/Users/[^/]+/|/home/[^/]+/|cert-root-project|ReleaseSeal-PVT|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' \
    --exclude-dir=.git --exclude-dir=release-staging --exclude='audit_public_tree.sh' . >/dev/null 2>&1; then
    /usr/bin/grep -RInE \
        '/Users/[^/]+/|/home/[^/]+/|cert-root-project|ReleaseSeal-PVT|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' \
        --exclude-dir=.git --exclude-dir=release-staging --exclude='audit_public_tree.sh' . >&2 || true
    fail "personal path, private repository name, or private key marker was found."
fi

if /usr/bin/grep -RIl $'\xE2\x80\x93\|\xE2\x80\x94' \
    --exclude-dir=.git --exclude-dir=release-staging . >/dev/null 2>&1; then
    /usr/bin/grep -RIn $'\xE2\x80\x93\|\xE2\x80\x94' --exclude-dir=.git --exclude-dir=release-staging . >&2 || true
    fail "an en dash or em dash was found."
fi

python3 - "$ROOT" <<'PY'
import html.parser
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])

class LinkParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if name in {"href", "src"} and value:
                self.links.append(value)

index = root / "docs/index.html"
parser = LinkParser()
parser.feed(index.read_text(encoding="utf-8"))
for link in parser.links:
    if link.startswith(("https://", "http://", "#", "mailto:")):
        continue
    target = (index.parent / link.split("#", 1)[0]).resolve()
    if not target.is_relative_to(index.parent.resolve()) or not target.exists():
        raise SystemExit(f"Public tree audit failed: broken local website link: {link}")

release = json.loads((root / "docs/release.json").read_text(encoding="utf-8"))
notes = root / "release-notes" / f"{release['tag']}.md"
if not notes.is_file():
    raise SystemExit(f"Public tree audit failed: missing release notes: {notes}")
PY

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git diff --check
    git diff --cached --check
fi

echo "Public tree audit passed."
