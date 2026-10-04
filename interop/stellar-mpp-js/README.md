# Stellar MPP JavaScript interoperability harness

This frozen harness checks the wallet's wire fixtures against the released
Stellar TypeScript SDK. It is not a runtime dependency of any wallet crate.

Pins:

- `@stellar/mpp@0.7.1`, upstream tag `v0.7.1` at
  `9f2f8254421e09906dfb7e983e2491a273120adf`
- `@stellar/stellar-sdk@17.2.1`
- `mppx@0.13.1`
- `viem@2.57.2`, satisfying `mppx`'s `viem >=2.57.1` peer requirement
- Node `24.5.0`
- pnpm `10.33.0`

The committed fixture records its original generation environment:
`@stellar/stellar-sdk@15.1.0` and `mppx@0.6.31`.
The current harness verifies its wire data using the pins above.
`@stellar/mpp@0.7.1` declares peer ranges `@stellar/stellar-sdk: ^15.1.0`
and `mppx: ^0.6.29`; the current pins fall outside those ranges.
Passing this harness demonstrates compatibility for the exercised cases.

The upstream packages are MIT or Apache-2.0 licensed as recorded in the frozen
lockfile package metadata. The fixture is generated solely through their public
challenge, credential, receipt, and sponsored-server APIs.

Run from the repository root:

```sh
.github/scripts/test-mpp-interop.sh
```
