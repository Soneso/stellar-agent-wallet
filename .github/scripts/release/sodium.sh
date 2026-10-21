#!/usr/bin/env bash
# Prefetches the prebuilt libsodium archive of the MSVC build into
# $RUNNER_TEMP/sodium-dist and writes SODIUM_DIST_DIR to $GITHUB_ENV.
# stellar-baselib links libsodium. On MSVC its build script fetches the
# archive from download.libsodium.org over plain HTTP with no retry, which is
# flaky from Windows runners. This script fetches the same archive over HTTPS
# with retries, and the build script consumes the local copy. The build
# script still verifies the archive's minisign signature against its pinned
# upstream key, so integrity does not rest on this download.
#
# check-workflow-invariants.py requires the body below to equal, line for
# line, the run block of the release build job's step that writes
# SODIUM_DIST_DIR.
set -euo pipefail
DIST_DIR="$RUNNER_TEMP/sodium-dist"
mkdir -p "$DIST_DIR"
BASE="https://download.libsodium.org/libsodium/releases"
for f in libsodium-1.0.22-stable-msvc.zip libsodium-1.0.22-stable-msvc.zip.minisig \
         LATEST.tar.gz LATEST.tar.gz.minisig; do
  curl --fail --silent --show-error --location --retry 5 --retry-all-errors \
    --output "$DIST_DIR/$f" "$BASE/$f"
done
echo "SODIUM_DIST_DIR=$DIST_DIR" >> "$GITHUB_ENV"
