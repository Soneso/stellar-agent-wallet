# stellar-agent-headless-keyring

Opt-in file-backed keyring store for headless deployments of the stellar-agent-wallet.

Platform keyrings are unavailable or unusable in some deployment shapes: Windows Credential Manager requires an interactive logon session, so a Windows service, an SSH/WinRM session, or a scheduled task cannot reach it, and Linux services or CI runners may have no Secret Service. This crate provides a `keyring-core` credential store backed by a single encrypted file, so every existing enrollment, rotation, and signing path works unchanged behind the same keyring coordinates.

Two protection modes, selected by `STELLAR_AGENT_KEYRING_BACKEND`:

- `headless-env` — entries sealed with XChaCha20-Poly1305 under a 32-byte key supplied via `STELLAR_AGENT_HEADLESS_KEYRING_KEY` (URL-safe base64, no padding). Works on every platform; the env var is the root of trust.
- `headless-dpapi` — Windows only; entries sealed with DPAPI in CurrentUser scope. The trust boundary is the same as Windows Credential Manager (any process running as the same user can decrypt), without the interactive-session requirement.

The platform keyring remains the default. The headless store never activates implicitly and never falls back to or from the platform keyring on any initialisation failure. Tampered or corrupt entries fail closed with typed errors.

It is part of the stellar-agent-wallet workspace and is used by the wallet's keyring registration rather than directly by most users. See the wallet's security-internals documentation for the storage format and threat model.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
