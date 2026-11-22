# stellar-agent-toolsets-install

Toolset install and uninstall with cryptographic provenance for the stellar-agent-wallet.

This crate installs and uninstalls toolsets. An install runs under a chain of checks, in this order:

- A trust-set check: the publisher key must be in the local trust set.
- Constant-time SHA-256 comparison of the package bytes against the signed shasum.
- ed25519 verification of the publisher signature over a canonical, domain-separated, length-prefixed preimage.
- Safe tar extraction with type-first checks, lexical containment, no-follow writes, an ASCII-only entry-name gate, and size bounds.
- A parse-and-validate step via `stellar-agent-toolsets`.
- An attestation gate for key-touching capabilities that fires after the identity cross-check and before the atomic rename.
- An atomic pin record written on success.

Uninstall reads no pin record: the pin file's presence marks the toolset as installed. It removes the directory named by the validated package name and refuses a symlinked directory, so a record that does not verify can still be removed.

Runtime tool registration, capability enforcement, and the first-invoke gate belong to the separate runtime layer; this crate does not perform them, and there is no hosted or on-chain registry.

It is part of the stellar-agent-wallet workspace and is driven by the wallet's toolset install flows rather than directly by most users.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
