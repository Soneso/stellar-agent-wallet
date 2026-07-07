# stellar-agent-windows-identity

Internal support crate for the stellar-agent-wallet.

This small Windows-only helper contains the Win32 FFI required to read the current process token's user account SID and exposes a safe, string-returning API. It isolates that unsafe code from `stellar-agent-core`, which forbids unsafe code. The SID binds approval attestations to the OS user that created them, so an attestation blob minted by one user cannot be replayed by another user on the same machine.

It is published as part of the stellar-agent-wallet workspace to complete the dependency graph on crates.io and is not designed for standalone use.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
