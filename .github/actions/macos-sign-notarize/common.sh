#!/bin/bash
# Shared by the scripts of this action, which source it: the input checks,
# and the paths of the signing keychain and the decoded key files that
# sign-notarize.sh creates and remove_signing_files deletes.

fail() {
  echo "$*" >&2
  exit 1
}

require_target() {
  case "${TARGET:-}" in
    aarch64-apple-darwin | x86_64-apple-darwin) ;;
    *) fail "unsupported target: ${TARGET:-<unset>}" ;;
  esac
}

require_version() {
  local version_re='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'
  if ! [[ "${VERSION:-}" =~ $version_re ]]; then
    fail "release version '${VERSION:-}' does not match $version_re"
  fi
}

KEYCHAIN="${RUNNER_TEMP:?RUNNER_TEMP is not set}/notary.keychain-db"
P12="$RUNNER_TEMP/developer_id.p12"
ASC_KEY="$RUNNER_TEMP/asc_api_key.p8"
SUBMIT_ZIP="$RUNNER_TEMP/notarize-${TARGET:-unknown}.zip"

# Removes the keychain and every decoded key file, and succeeds when nothing
# is left.
remove_signing_files() {
  /bin/rm -f "$P12" "$ASC_KEY" "$SUBMIT_ZIP"
  /usr/bin/security delete-keychain "$KEYCHAIN" 2>/dev/null || true
}
