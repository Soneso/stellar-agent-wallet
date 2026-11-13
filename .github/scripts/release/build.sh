#!/usr/bin/env bash
# Builds the release executable stellar-agent for one target into
# target/<target>/release, using cross for aarch64-unknown-linux-gnu and cargo
# for every other target. It then copies the executable to stellar-agent-mcp
# in the same directory, with the target's executable suffix, and requires
# equal bytes. copy_alias of copy-alias.sh makes the copy through a new
# mktemp file and a rename that follows no link at the destination. The cross image pin
# and libudev pre-build hook live in Cross.toml. The command names no
# toolchain, so the toolchain the caller installed builds.
#
# Usage: build.sh <target>
set -euo pipefail
# The environment guard is the first action, before the argument checks, so
# every caller is checked at the last point before cargo. It inspects the
# checkout this script belongs to, where cargo builds after the cd below.
python3 "$(dirname "${BASH_SOURCE[0]}")/../check-feature-discipline.py" --env-guard "$(dirname "${BASH_SOURCE[0]}")/../../.."

if [ "$#" -ne 1 ]; then
  echo "usage: build.sh <target>" >&2
  exit 2
fi
TARGET=$1
case "$TARGET" in
  '' | -* | *[!A-Za-z0-9_.-]*)
    echo "build.sh: invalid target '$TARGET'" >&2
    exit 2
    ;;
esac

cd "$(dirname "${BASH_SOURCE[0]}")/../../.."

if [ "$TARGET" = "aarch64-unknown-linux-gnu" ]; then
  cross build --release --locked --target "$TARGET" --bin stellar-agent
else
  cargo build --release --locked --target "$TARGET" --bin stellar-agent
fi

suffix=
case "$TARGET" in
  *-windows-*) suffix=.exe ;;
esac
release="target/$TARGET/release"
# shellcheck source=SCRIPTDIR/copy-alias.sh
. .github/scripts/release/copy-alias.sh
copy_alias "$release/stellar-agent$suffix" "$release/stellar-agent-mcp$suffix"
cmp "$release/stellar-agent$suffix" "$release/stellar-agent-mcp$suffix"
