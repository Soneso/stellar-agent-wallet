# stellar-agent-xdr-limits

Internal support crate for the stellar-agent-wallet.

This leaf crate provides `untrusted_decode_limits`, the recursion-depth and length bounds every site in the workspace uses when decoding XDR that originates from an untrusted caller or network peer, instead of an unbounded `Limits::none()`. The depth bound (matching the limit `soroban-env-host` applies to its own XDR) prevents a crafted depth-bomb from exhausting the stack and aborting the process, and the length bound (capped to the input buffer size) prevents a forged length field from driving an oversized allocation. It is a separate leaf so lean crates can apply the policy without depending on the heavier `stellar-agent-core` substrate.

It is published as part of the stellar-agent-wallet workspace to complete the dependency graph on crates.io and is not designed for standalone use.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
