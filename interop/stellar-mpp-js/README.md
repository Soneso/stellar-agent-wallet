# Stellar MPP JavaScript interoperability harness

This frozen harness checks the wallet's wire fixtures against the released
Stellar TypeScript SDK. It is not a runtime dependency of any wallet crate.

Pins:

- `@stellar/mpp@0.7.1`, upstream tag `v0.7.1` at
  `9f2f8254421e09906dfb7e983e2491a273120adf`
- `@stellar/stellar-sdk@16.4.1`
- `mppx@0.8.19`
- `viem@2.57.2`, satisfying `mppx`'s `viem >=2.54.0` peer requirement
- Node `24.5.0`
- pnpm `10.33.0`

`@stellar/mpp@0.7.1` declares the peer ranges `@stellar/stellar-sdk: ^15.1.0`
and `mppx: ^0.6.29`. Neither pin satisfies its range, and no `@stellar/mpp`
release accepts a newer SDK or `mppx`.

The SDK 15 line ends at 15.1.0, whose XDR cannot decode a protocol 30 ledger
header. On a protocol 30 network the released server then fails its payment
verification and answers HTTP 402. SDK 16.4.1 decodes the header. SDK 17
changes the XDR union interface that `@stellar/mpp` 0.7.1 calls, and its
server then fails verification with `txEnvelope.switch is not a function`.
The check reads the version of the installed `@stellar/stellar-sdk` from
its package manifest and refuses any release outside the 16 line at or
after 16.4.1, naming the version it found, so a bump the peer rules let
through fails here instead of at charge time.

The `mppx` 0.6 line carries the advisories GHSA-727h-3vm5-qwq6 and
GHSA-vc9j-9wph-qghj, which 0.8.2 fixes.

Two rules under `pnpm.peerDependencyRules.allowedVersions` in `package.json`
accept the pins as peers of `@stellar/mpp` 0.7.1 only:
`"@stellar/mpp@0.7.1>@stellar/stellar-sdk": "16.4.1"` and
`"@stellar/mpp@0.7.1>mppx": "0.8.19"`. pnpm reports a pairing outside both
the declared peer range and these two rules as an unmet peer.
The setting `strict-peer-dependencies=true` in `.npmrc` makes `pnpm install`
fail on an unmet peer.

With `mppx@0.8.19` the released server emits the fixture's challenge,
credential, and receipt bytes. It answers a credential that fails its
verification with HTTP 402 and a fresh challenge. `mppx` 0.9 reports an error
that `@stellar/mpp` raises during verification as an internal error with HTTP
500, so the pin stays on the 0.8 line.

The committed fixture records these pins as its generation environment, and
the check compares its whole content, provenance included.

The harness carries no pnpm overrides: `@stellar/stellar-sdk@16.4.1` pins
`axios` 1.20.0 and does not depend on `toml`.

The upstream packages are MIT or Apache-2.0 licensed as recorded in the frozen
lockfile package metadata. The fixture is generated solely through their public
challenge, credential, receipt, and sponsored-server APIs.

Run from the repository root:

```sh
.github/scripts/test-mpp-interop.sh
```
