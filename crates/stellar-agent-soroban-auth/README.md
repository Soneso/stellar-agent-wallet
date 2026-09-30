# stellar-agent-soroban-auth

Internal support crate for the stellar-agent-wallet.

This leaf crate builds the `HashIdPreimage` that a Soroban address-credentialled authorization entry is signed over and hashes it into the 32-byte signature payload. It maps each `SorobanCredentials` arm to its preimage: `Address` credentials use envelope type 9 (`SorobanAuthorization`) and CAP-71 `AddressV2` credentials use envelope type 10 (`SorobanAuthorizationWithAddress`), which also binds the credential's address.

It is published as part of the stellar-agent-wallet workspace to complete the dependency graph on crates.io and is not designed for standalone use.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
