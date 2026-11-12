# stellar-agent-approval-remote

TLS-protected, passkey-authenticated approval from another device.

Testnet authorization checks the live profile allowlist and enrolled operator key.
Mainnet requires a signed approval origin and leaf SPKI pin from the verified policy.
Mainnet login and decisions trust policy credentials alone; the operator store supplies counters.
Each verified login, approval or rejection enforces the counter once, allowing zero after zero.
Receipt verification and commit do not update counters.

Configure explicit `cert_path` and `key_path` for mainnet.
The SPKI pin hashes the leaf key structure, not the full certificate fingerprint.
The browser separately trusts a public CA or an installed private CA.
Restart after policy signing or certificate replacement; running listeners never reload TLS.
Issuance, renewal automation and TLS-terminating proxies are outside this crate's scope.

Persistent serving uses `approve serve --remote --confirm-remote-exposure`.
Signed-origin serving accepts `--no-open` and needs no display or browser opener.
One-shot consent requires enabled remote configuration and prints the signed approval link without a token.
It scopes every route to one entry and closes on completion, cancellation, expiry or interruption.
An occupied socket reports `approval.listener_busy` and directs the operator to the running inbox.
See the repository's remote approval guide for setup and refusal codes.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
