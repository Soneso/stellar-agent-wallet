# stellar-agent-sep5

SEP-5 / BIP-44 HD-path ed25519 key derivation for Stellar.

This crate performs deterministic derivation of ed25519 Stellar keypairs along the BIP-44 path `m/44'/148'/index'` using SLIP-0010 hardened child-key derivation. Input is a BIP-39 mnemonic phrase (with optional passphrase) or a pre-computed 64-byte BIP-39 seed. The output is a `DerivedAccount` that exposes the `G...` public key freely and wraps the 32-byte secret seed in a `secrecy::SecretBox`.

It does not generate mnemonics (it derives from an existing phrase only), does not expose non-hardened derivation (ed25519 SLIP-0010 is hardened-only), and performs no network I/O, file I/O, or random number generation. It is a pure local-derivation substrate with no MCP tools or CLI commands.

It is part of the stellar-agent-wallet workspace and is used by the wallet's key-management paths rather than directly by most users.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
