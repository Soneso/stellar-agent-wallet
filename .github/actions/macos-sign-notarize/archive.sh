#!/bin/bash
# Packs the signed binaries into the release archive
# stellar-agent-<VERSION>-<TARGET>.tar.xz under RUNNER_TEMP. The archive holds
# one directory of that name with README.md and LICENSE from the checked-out
# tree and both binaries, the layout of every other release archive, which
# the cargo-binstall bin-dir template relies on. Writes the archive path to
# GITHUB_OUTPUT as "archive". Every tool runs by absolute path.
set -euo pipefail

# shellcheck source=SCRIPTDIR/common.sh
. "${BASH_SOURCE[0]%/*}/common.sh"

require_target
require_version
for var in BINARY_DIR GITHUB_WORKSPACE GITHUB_OUTPUT; do
  if [ -z "${!var:-}" ]; then
    fail "required variable $var is empty"
  fi
done

STAGE_ROOT="$RUNNER_TEMP/release-archive"
NAME="stellar-agent-${VERSION}-${TARGET}"
STAGING_DIR="$STAGE_ROOT/$NAME"
ARCHIVE="$STAGE_ROOT/$NAME.tar.xz"

/bin/mkdir "$STAGE_ROOT"
/bin/mkdir "$STAGING_DIR"
/bin/cp "$GITHUB_WORKSPACE/README.md" "$GITHUB_WORKSPACE/LICENSE" "$STAGING_DIR/"
/bin/cp "$BINARY_DIR/stellar-agent" "$BINARY_DIR/stellar-agent-mcp" "$STAGING_DIR/"
/bin/chmod 0644 "$STAGING_DIR/README.md" "$STAGING_DIR/LICENSE"
/bin/chmod 0755 "$STAGING_DIR/stellar-agent" "$STAGING_DIR/stellar-agent-mcp"
COPYFILE_DISABLE=1 /usr/bin/tar --create --xz --file "$ARCHIVE" -C "$STAGE_ROOT" "$NAME"

echo "archive=$ARCHIVE" >>"$GITHUB_OUTPUT"
echo "Packed $ARCHIVE"
