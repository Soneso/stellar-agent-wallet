# Stellar MPP JavaScript interoperability harness

This frozen harness checks the wallet's wire fixtures against the released
Stellar TypeScript SDK. It is not a runtime dependency of any wallet crate.

Pins:

- `@stellar/mpp@0.7.1`, upstream tag `v0.7.1` at
  `9f2f8254421e09906dfb7e983e2491a273120adf`
- `@stellar/stellar-sdk@15.1.0`
- `mppx@0.6.31`
- `viem@2.57.2`, satisfying `mppx`'s `viem >=2.51.0` peer requirement
- Node `24.5.0`
- pnpm `10.33.0`

`@stellar/mpp@0.7.1` declares the peer ranges `@stellar/stellar-sdk: ^15.1.0`
and `mppx: ^0.6.29`, and the pins satisfy both. The committed fixture records
these pins as its generation environment, and the check compares its whole
content, provenance included.

The pnpm overrides in `package.json` lift `axios` to `1.20.0` and `toml` to
`4.3.0`, newer than the versions `@stellar/stellar-sdk@15.1.0` requires, because
the released server's peer ranges keep the harness on SDK 15. The two advisories
that remain affect `mppx` 0.6.x and are fixed only in 0.8, outside the server's
`^0.6.29` range.

The upstream packages are MIT or Apache-2.0 licensed as recorded in the frozen
lockfile package metadata. The fixture is generated solely through their public
challenge, credential, receipt, and sponsored-server APIs.

Run from the repository root:

```sh
.github/scripts/test-mpp-interop.sh
```
