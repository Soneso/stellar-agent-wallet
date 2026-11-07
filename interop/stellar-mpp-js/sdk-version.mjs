// The harness requires SDK 16.4.1 or a later 16.x release without suffixes.
// SDK 15 cannot decode protocol 30 ledger headers.
// SDK 17 changes the server's XDR union interface and breaks verification.
export const SDK_MINIMUM = '16.4.1'

// Decides whether the loaded `@stellar/stellar-sdk` version is one the
// harness may run with.
//
// Returns `true` when `version` is a canonical `major.minor.patch` string
// for 16.4.1 or a later 16.x release, and otherwise a refusal message naming
// the version, for the caller to print. A canonical component is `0` or a
// number without a leading zero, and nothing follows the patch.
export function sdkVersionAcceptable(version) {
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(version ?? '')
  if (!match) {
    return `@stellar/stellar-sdk version ${JSON.stringify(version ?? '')} is not a semver version`
  }
  const [major, minor, patch] = match.slice(1).map(Number)
  if (major !== 16 || minor < 4 || (minor === 4 && patch < 1)) {
    return `@stellar/stellar-sdk ${version} is outside the supported range, ${SDK_MINIMUM} or a later 16.x release`
  }
  return true
}
