# stellar-agent-anchor

SEP-24 interactive hand-off and SEP-6 discovery-only anchor client for the stellar-agent-wallet.

This crate provides a privacy-first anchor client. For SEP-6 it calls `GET {transfer_server}/info` only, decoding the anchor's capability set and `authentication_required` flags without touching any deposit, withdraw, or KYC-initiating endpoint. For SEP-24 it obtains the anchor's interactive deposit/withdraw URL and returns it to the operator for browser hand-off; the wallet never opens, scrapes, or follows the URL.

Every anchor endpoint fetch is preceded by a host check on an `https` transfer-server URL. With an anchor domain, the host must equal that domain or be a subdomain of it. With a direct URL, the host must be a public FQDN of at least two labels and no IP address. The crate transmits no SEP-9 KYC field and performs no SEP-10/SEP-45 authentication itself; the caller supplies an opaque JWT string.

It is part of the stellar-agent-wallet workspace. Most users interact with it through the `stellar-agent-mcp` tools `stellar_sep6_deposit_info` and `stellar_sep24_interactive_url` rather than directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
