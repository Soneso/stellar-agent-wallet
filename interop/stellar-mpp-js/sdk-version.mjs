// The released `@stellar/mpp` 0.7.1 runs with the SDK's 16 line: the 15 line
// ends at 15.1.0, whose XDR cannot decode a protocol 30 ledger header, and 17
// changes the XDR union interface the server calls, so its verification fails
// with `txEnvelope.switch is not a function`.  The harness therefore runs
// only on 16.4.1, the version the fixture's provenance records, or a later
// 16.x release.
export const SDK_MINIMUM = '16.4.1'

// Decides whether the loaded `@stellar/stellar-sdk` version is one the
// harness may run with.
//
// Returns `true` when `version` is 16.4.1 or a later 16.x release, and
// otherwise a refusal message naming the version, for the caller to print.
export function sdkVersionAcceptable(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/.exec(version ?? '')
  if (!match) {
    return `@stellar/stellar-sdk version ${JSON.stringify(version ?? '')} is not a semver version`
  }
  const [major, minor, patch] = match.slice(1).map(Number)
  if (major !== 16 || minor < 4 || (minor === 4 && patch < 1)) {
    return `@stellar/stellar-sdk ${version} is outside the supported range, ${SDK_MINIMUM} or a later 16.x release`
  }
  return true
}
