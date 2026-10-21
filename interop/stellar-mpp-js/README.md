# Stellar MPP JavaScript interoperability harness

This frozen harness checks the wallet's wire fixtures against the released
Stellar TypeScript SDK. It is not a runtime dependency of any wallet crate.

Pins:

- `@stellar/mpp@0.7.1`, upstream tag `v0.7.1` at
  `9f2f8254421e09906dfb7e983e2491a273120adf`
- `@stellar/stellar-sdk@15.1.0`
- `mppx@0.8.19`
- `viem@2.57.2`, satisfying `mppx`'s `viem >=2.54.0` peer requirement
- Node `24.5.0`
- pnpm `10.33.0`

`@stellar/mpp@0.7.1` declares the peer ranges `@stellar/stellar-sdk: ^15.1.0`
and `mppx: ^0.6.29`. The SDK pin satisfies its range. The `mppx` pin does not,
and pnpm reports the unmet peer when it resolves the lockfile. The `mppx` 0.6
line carries the advisories GHSA-727h-3vm5-qwq6 and GHSA-vc9j-9wph-qghj, which
0.8.2 fixes, and no `@stellar/mpp` release accepts a newer `mppx`.

With `mppx@0.8.19` the released server emits the fixture's challenge,
credential, and receipt bytes. It answers a credential that fails its
verification with HTTP 402 and a fresh challenge. `mppx` 0.9 reports an error
that `@stellar/mpp` raises during verification as an internal error with HTTP
500, so the pin stays on the 0.8 line.

The committed fixture records these pins as its generation environment, and
the check compares its whole content, provenance included.

The pnpm overrides in `package.json` lift `axios` to `1.20.0` and `toml` to
`4.3.0`, newer than the versions `@stellar/stellar-sdk@15.1.0` requires, because
the released server's peer ranges keep the harness on SDK 15.

The upstream packages are MIT or Apache-2.0 licensed as recorded in the frozen
lockfile package metadata. The fixture is generated solely through their public
challenge, credential, receipt, and sponsored-server APIs.

Run from the repository root:

```sh
.github/scripts/test-mpp-interop.sh
```
