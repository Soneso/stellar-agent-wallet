#!/usr/bin/env bash
# Builds the release binaries stellar-agent and stellar-agent-mcp for one
# target into target/<target>/release, using cross for
# aarch64-unknown-linux-gnu and cargo for every other target. The cross image
# pin and libudev pre-build hook live in Cross.toml. The command names no
# toolchain, so the toolchain the caller installed builds.
#
# Usage: build.sh <target>
#
# check-workflow-invariants.py requires the cargo build and cross build lines
# below to equal those of the build job in release.yml.
set -euo pipefail

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
  cross build --release --locked --target "$TARGET" --bin stellar-agent --bin stellar-agent-mcp
else
  cargo build --release --locked --target "$TARGET" --bin stellar-agent --bin stellar-agent-mcp
fi
