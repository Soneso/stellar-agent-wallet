# stellar-agent-sep53

SEP-53 prefixed-message sign and verify primitive for the stellar-agent-wallet.

This crate implements the canonical SEP-53 message scheme: `sign_message` computes `SHA-256("Stellar Signed Message:\n" ‖ message)` and ed25519-signs the digest; `verify_message` recomputes the digest and ed25519-verifies it against a supplied public key. A typed `Sep53Error` enum covers the signing and verification failure modes.

SEP-53 is a pure off-chain signature scheme: the crate submits no transaction and does not handle base64 encoding of the message, which is the caller's responsibility.

It is part of the stellar-agent-wallet workspace. Most users interact with it through the `stellar_sep53_sign_message` and `stellar_sep53_verify_message` tools in `stellar-agent-mcp` rather than directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
