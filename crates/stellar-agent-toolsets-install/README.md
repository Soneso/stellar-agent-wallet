# stellar-agent-toolsets-install

Toolset install and uninstall with cryptographic provenance for the stellar-agent-wallet.

This crate installs and uninstalls toolsets under a chain of checks: constant-time SHA-256 comparison of the package bytes against the signed shasum; ed25519 verification of the publisher signature over a canonical, domain-separated, length-prefixed preimage, with the signer required to be in the local trust set; safe tar extraction with type-first checks, lexical containment, no-follow writes, an ASCII-only entry-name gate, and size bounds; a parse-and-validate step via `stellar-agent-toolsets`; an attestation gate for key-touching capabilities that fires after the identity cross-check and before the atomic rename; and an atomic pin record written on success. Uninstall reconstructs the directory path from the validated pin and removes it without following symlinks.

Runtime tool registration, capability enforcement, and the first-invoke gate belong to the separate runtime layer; this crate does not perform them, and there is no hosted or on-chain registry.

It is part of the stellar-agent-wallet workspace and is driven by the wallet's toolset install flows rather than directly by most users.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
