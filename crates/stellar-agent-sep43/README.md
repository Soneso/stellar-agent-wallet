# stellar-agent-sep43

SEP-43 Wallet Protocol dispatch substrate for the stellar-agent-wallet.

This crate implements the agent-side SEP-43 `ModuleInterface`, covering the five methods `get_address`, `sign_transaction`, `sign_auth_entry`, `sign_message`, and `get_network`. It provides a typed `Sep43Error` enum, whose variants each carry a stable wire code and a spec-compliant JSON serializer. It also provides active-address resolution across the classic-G, smart-account-C, and muxed-M kinds, strkey validation, the async `ModuleAdapter` trait, and the concrete `StellarAgentModule` implementation that dispatches each method.

It does not implement the optional submit/submitUrl options of `signTransaction`; transactions are returned signed, not submitted. Ordinary signing refuses mainnet with `sep43.mainnet_signing_forbidden`. With the `mainnet-write` feature, `signing::sign_soroban_auth_entry_authorized` signs an authorization entry under a mainnet authorization and refuses with `sep43.mainnet_authorization_refused` when a check of that authorization fails.

It is part of the stellar-agent-wallet workspace. Most users interact with it through the six `stellar_sep43_*` tools in `stellar-agent-mcp` rather than directly: one per method, plus `stellar_sep43_sign_and_submit_transaction`, which signs and submits. Those MCP tools decide each payment of a transaction or authorization entry under the wallet's payment policy before calling this crate; the crate itself evaluates no policy. `signing::validate_soroban_auth_entry` runs the `signAuthEntry` input checks without a signer, so a caller can decide the authorized invocation before it loads a key.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
