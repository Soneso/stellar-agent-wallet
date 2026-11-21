#!/usr/bin/env bash
# Prefetches libsodium into $RUNNER_TEMP/sodium-dist. On MSVC the build
# script of libsodium-sys-stable fetches the prebuilt archive over plain HTTP
# with no retry, which is flaky from Windows runners; this script fetches it
# over HTTPS with retries, and the build script consumes the local copy. The
# linked MSVC bytes are pinned by digest and checked by the build script's
# minisign key.
# The build script also reads LATEST.tar.gz and its signature from this
# directory. That source archive stays unpinned because upstream replaces
# it at each stable release and the MSVC build links only the prebuilt archive.
# An upstream rebuild of the prebuilt archive fails the Windows leg until
# the digest pin is reviewed. Only a matching digest exports SODIUM_DIST_DIR.
#
# The build jobs of release.yml and release-rehearsal.yml run this script by
# path, once each, and check-workflow-invariants.py requires their build step
# to follow the Perl and sodium setup steps immediately.
set -euo pipefail
SODIUM_MSVC_SHA256=e5c4112f60cf993d1dab5216e5bed5e20dc1e561041be98c57a260d6e67521d1
DIST_DIR="$RUNNER_TEMP/sodium-dist"
mkdir -p "$DIST_DIR"
BASE="https://download.libsodium.org/libsodium/releases"
for f in libsodium-1.0.22-stable-msvc.zip libsodium-1.0.22-stable-msvc.zip.minisig \
         LATEST.tar.gz LATEST.tar.gz.minisig; do
  curl --fail --silent --show-error --location --retry 5 --retry-all-errors \
    --output "$DIST_DIR/$f" "$BASE/$f"
done
actual=$(sha256sum < "$DIST_DIR/libsodium-1.0.22-stable-msvc.zip")
if [ "${actual%% *}" != "$SODIUM_MSVC_SHA256" ]; then
  echo 'sodium: MSVC archive SHA-256 differs from the pinned digest' >&2
  echo "sodium: expected $SODIUM_MSVC_SHA256" >&2
  echo "sodium: actual   ${actual%% *}" >&2
  exit 1
fi
echo "SODIUM_DIST_DIR=$DIST_DIR" >> "$GITHUB_ENV"
