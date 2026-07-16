#!/usr/bin/env bash
# Deterministically build or verify the distributable agent-skill archive.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SOURCE="$ROOT/skills/stellar-agent-wallet"
ARCHIVE="$ROOT/skills/stellar-agent-wallet.zip"
MODE="build"
if [ "$#" -gt 1 ]; then
  echo "usage: $0 [--check]" >&2
  exit 2
fi
if [ "$#" -eq 1 ]; then
  if [ "$1" != "--check" ]; then
    echo "usage: $0 [--check]" >&2
    exit 2
  fi
  MODE="check"
fi

for command in zip unzip zipinfo shasum python3; do
  command -v "$command" >/dev/null || {
    echo "required command not found: $command" >&2
    exit 2
  }
done

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if find "$SOURCE" -type l -o -name '.DS_Store' -o -name 'Thumbs.db' -o -name '__MACOSX' | grep -q .; then
  echo "skill source contains a symlink or platform-junk entry" >&2
  exit 1
fi

python3 - "$SOURCE" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1]).resolve()
missing = []
for document in root.rglob("*.md"):
    text = document.read_text(encoding="utf-8")
    for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", text):
        target = target.strip().split("#", 1)[0]
        if not target or "://" in target or target.startswith(("mailto:", "/")):
            continue
        resolved = (document.parent / target).resolve()
        if root not in (resolved, *resolved.parents) or not resolved.exists():
            missing.append(f"{document.relative_to(root)} -> {target}")
if missing:
    print("broken relative skill links:\n" + "\n".join(missing), file=sys.stderr)
    raise SystemExit(1)
PY

build_archive() {
  local output=$1 stage=$2
  mkdir -p "$stage/stellar-agent-wallet"
  cp -R "$SOURCE/." "$stage/stellar-agent-wallet/"
  find "$stage/stellar-agent-wallet" -exec touch -t 198001010000 {} +
  (
    cd "$stage"
    find stellar-agent-wallet -type f -print | LC_ALL=C sort | zip -X -q "$output" -@
  )
}

build_archive "$TMP/first.zip" "$TMP/stage-one"
build_archive "$TMP/second.zip" "$TMP/stage-two"
if [ "$(shasum -a 256 "$TMP/first.zip" | awk '{print $1}')" != \
     "$(shasum -a 256 "$TMP/second.zip" | awk '{print $1}')" ]; then
  echo "two clean skill builds produced different SHA-256 values" >&2
  exit 1
fi

mkdir "$TMP/extracted"
unzip -q "$TMP/first.zip" -d "$TMP/extracted"
if [ "$(find "$TMP/extracted" -mindepth 1 -maxdepth 1 -print)" != \
     "$TMP/extracted/stellar-agent-wallet" ]; then
  echo "skill archive must contain exactly one root directory" >&2
  exit 1
fi
diff -r "$SOURCE" "$TMP/extracted/stellar-agent-wallet" >/dev/null || {
  echo "skill archive does not have exact source byte parity" >&2
  exit 1
}
if zipinfo -1 "$TMP/first.zip" | grep -E '(^|/)(\.DS_Store|Thumbs\.db|__MACOSX)(/|$)' >/dev/null; then
  echo "skill archive contains platform junk" >&2
  exit 1
fi

if [ "$MODE" = "check" ]; then
  cmp -s "$TMP/first.zip" "$ARCHIVE" || {
    echo "skill archive is stale; run .github/scripts/package-skill.sh" >&2
    exit 1
  }
  echo "skill archive is deterministic and matches source"
else
  mv "$TMP/first.zip" "$ARCHIVE"
  echo "built skills/stellar-agent-wallet.zip ($(shasum -a 256 "$ARCHIVE" | awk '{print $1}'))"
fi
