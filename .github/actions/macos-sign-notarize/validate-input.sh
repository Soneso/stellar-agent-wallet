#!/bin/bash
# Validates the unsigned archive a build job produced and unpacks it for
# signing.
#
# Usage: validate-input.sh <tar> <out-dir> <arch>
#
# validate-unsigned-archive.py checks the members and the Mach-O headers and
# writes the two binaries into <out-dir>. lipo must then report exactly
# <arch> for each binary. The script runs no file from the archive.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <tar> <out-dir> <arch>" >&2
  exit 2
fi
TAR=$1
OUT=$2
ARCH=$3
SCRIPT_DIR=${BASH_SOURCE[0]%/*}

/usr/bin/python3 "$SCRIPT_DIR/../../scripts/validate-unsigned-archive.py" "$TAR" "$OUT" "$ARCH"
for bin in stellar-agent stellar-agent-mcp; do
  archs="$(/usr/bin/lipo -archs "$OUT/$bin")"
  if [ "$archs" != "$ARCH" ]; then
    echo "$bin: lipo reports '$archs', expected exactly '$ARCH'" >&2
    exit 1
  fi
done
echo "lipo reports $ARCH for both binaries"
