#!/usr/bin/env bash
# Executes the two binaries from the exact archive that will be distributed.
# Before anything runs, both names must be regular files with one link each,
# not symbolic links, and must hold equal bytes. The marker check then runs
# under each name.
#
# Usage: verify-archive.sh <archive-dir> <version> <target> <on|off>
set -euo pipefail
if [ "$#" -ne 4 ]; then
  echo 'usage: verify-archive.sh <archive-dir> <version> <target> <on|off>' >&2
  exit 2
fi
archive_dir=$1
version=$2
target=$3
expected=$4
stem="stellar-agent-$version-$target"
mkdir -p target/tmp
unpack=$(mktemp -d target/tmp/archive.XXXXXX)
trap 'rm -rf "$unpack"' EXIT
suffix=
if [ "$target" = x86_64-pc-windows-msvc ]; then
  7z x "$archive_dir/$stem.zip" "-o$unpack" >/dev/null
  suffix=.exe
else
  tar -xJf "$archive_dir/$stem.tar.xz" -C "$unpack"
fi
for binary in stellar-agent stellar-agent-mcp; do
  path="$unpack/$stem/$binary$suffix"
  if [ -L "$path" ] || [ ! -f "$path" ]; then
    echo "archive: $binary$suffix is not a regular file" >&2
    exit 1
  fi
  if [ -z "$(find "$path" -prune -links 1)" ]; then
    echo "archive: $binary$suffix has more than one link" >&2
    exit 1
  fi
done
if ! cmp -s "$unpack/$stem/stellar-agent$suffix" "$unpack/$stem/stellar-agent-mcp$suffix"; then
  echo "archive: stellar-agent$suffix and stellar-agent-mcp$suffix differ" >&2
  exit 1
fi
for binary in stellar-agent stellar-agent-mcp; do
  bash .github/scripts/check-binary-marker.sh "$unpack/$stem/$binary$suffix" "$expected"
done
