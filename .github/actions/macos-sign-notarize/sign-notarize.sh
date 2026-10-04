#!/bin/bash
# Signs stellar-agent and stellar-agent-mcp in BINARY_DIR with the Developer
# ID Application identity (hardened runtime, secure timestamp), verifies both
# signatures, and submits them to Apple's notary service, which must accept
# them. Bare executables cannot carry a stapled ticket, so Gatekeeper checks
# notarization online on first run.
#
# Inputs come from the environment: BINARY_DIR, TARGET, VERSION, P12_B64,
# P12_PASSWORD, ASC_KEY_B64, ASC_KEY_ID, ASC_ISSUER_ID, and RUNNER_TEMP. The
# script refuses invalid inputs before it touches a secret and echoes no
# secret. It deletes each decoded key file right after its last use, and the
# exit trap removes the keychain and any key file left. Every tool runs by
# absolute path. Runs on the macOS /bin/bash (3.2).
set -euo pipefail

# shellcheck source=SCRIPTDIR/common.sh
. "${BASH_SOURCE[0]%/*}/common.sh"

require_target
require_version
for var in BINARY_DIR P12_B64 P12_PASSWORD ASC_KEY_B64 ASC_KEY_ID ASC_ISSUER_ID; do
  if [ -z "${!var:-}" ]; then
    fail "required input $var is empty"
  fi
done
for bin in stellar-agent stellar-agent-mcp; do
  if [ ! -f "$BINARY_DIR/$bin" ] || [ -L "$BINARY_DIR/$bin" ]; then
    fail "$BINARY_DIR/$bin is not a regular file"
  fi
done

trap remove_signing_files EXIT

umask 077
KEYCHAIN_PW="$(/usr/bin/python3 -c 'import secrets; print(secrets.token_hex(24))')"

printf '%s' "$P12_B64" | /usr/bin/base64 -d >"$P12"
/usr/bin/security create-keychain -p "$KEYCHAIN_PW" "$KEYCHAIN"
/usr/bin/security set-keychain-settings -lut 1800 "$KEYCHAIN"
/usr/bin/security unlock-keychain -p "$KEYCHAIN_PW" "$KEYCHAIN"
/usr/bin/security import "$P12" -k "$KEYCHAIN" -P "$P12_PASSWORD" -T /usr/bin/codesign
/bin/rm -f "$P12"
/usr/bin/security set-key-partition-list -S apple-tool:,apple: -s -k "$KEYCHAIN_PW" "$KEYCHAIN" >/dev/null
/usr/bin/security list-keychains -d user -s "$KEYCHAIN" login.keychain

IDENTITY="$(/usr/bin/security find-identity -v -p codesigning "$KEYCHAIN" |
  /usr/bin/awk -F'"' '/Developer ID Application/{print $2; exit}')"
if [ -z "$IDENTITY" ]; then
  fail "no Developer ID Application identity in the imported keychain"
fi

for bin in stellar-agent stellar-agent-mcp; do
  /usr/bin/codesign --force --options runtime --timestamp \
    --keychain "$KEYCHAIN" --sign "$IDENTITY" "$BINARY_DIR/$bin"
  /usr/bin/codesign --verify --strict --verbose=2 "$BINARY_DIR/$bin"
done

/usr/bin/zip -j "$SUBMIT_ZIP" "$BINARY_DIR/stellar-agent" "$BINARY_DIR/stellar-agent-mcp"
printf '%s' "$ASC_KEY_B64" | /usr/bin/base64 -d >"$ASC_KEY"
OUT="$(/usr/bin/xcrun notarytool submit "$SUBMIT_ZIP" \
  --key "$ASC_KEY" --key-id "$ASC_KEY_ID" --issuer "$ASC_ISSUER_ID" \
  --wait --timeout 30m --output-format json)"
printf '%s\n' "$OUT"
STATUS="$(printf '%s' "$OUT" | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')"
SUBMISSION_ID="$(printf '%s' "$OUT" | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
if [ "$STATUS" != "Accepted" ]; then
  /usr/bin/xcrun notarytool log "$SUBMISSION_ID" \
    --key "$ASC_KEY" --key-id "$ASC_KEY_ID" --issuer "$ASC_ISSUER_ID" || true
  /bin/rm -f "$ASC_KEY"
  fail "notarization status: $STATUS"
fi
/bin/rm -f "$ASC_KEY" "$SUBMIT_ZIP"

for bin in stellar-agent stellar-agent-mcp; do
  /usr/bin/codesign --verify --strict --verbose=2 "$BINARY_DIR/$bin"
done
