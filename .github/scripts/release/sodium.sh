#!/usr/bin/env bash
# Prefetches libsodium into $RUNNER_TEMP/sodium-dist. On MSVC the build
# script of libsodium-sys-stable fetches the prebuilt archive over plain HTTP
# with no retry, which is flaky from Windows runners; this script fetches it
# over HTTPS with retries, and the build script consumes the local copy.
# The build script reads both the prebuilt MSVC archive and the LATEST.tar.gz
# source archive, plus their .minisig files, from this directory. It verifies
# each archive against the minisign key embedded in the pinned
# libsodium-sys-stable; an invalid signature fails the build. Upstream replaces
# the stable archives in place, so this script pins no digest and logs the
# SHA-256 of the prebuilt MSVC archive.
#
# The build jobs of release.yml and release-rehearsal.yml run this script by
# path, once each, and check-workflow-invariants.py requires their build step
# to follow the Perl and sodium setup steps immediately.
set -euo pipefail
DIST_DIR="$RUNNER_TEMP/sodium-dist"
mkdir -p "$DIST_DIR"
BASE="https://download.libsodium.org/libsodium/releases"
for f in libsodium-1.0.22-stable-msvc.zip libsodium-1.0.22-stable-msvc.zip.minisig \
         LATEST.tar.gz LATEST.tar.gz.minisig; do
  curl --fail --silent --show-error --location --retry 5 --retry-all-errors \
    --output "$DIST_DIR/$f" "$BASE/$f"
done
actual=$(sha256sum < "$DIST_DIR/libsodium-1.0.22-stable-msvc.zip")
echo "sodium: libsodium-1.0.22-stable-msvc.zip SHA-256 ${actual%% *}"
echo "SODIUM_DIST_DIR=$DIST_DIR" >> "$GITHUB_ENV"
