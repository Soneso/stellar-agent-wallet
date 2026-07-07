# stellar-agent-claimable

Claimable-balance domain logic for the stellar-agent-wallet.

This crate provides the substrate for claiming claimable balances: balance-id normalization, RPC fetch of a `ClaimableBalanceEntry` and the claiming account's trustline state, `ClaimPredicate` evaluation, and a typed, XDR-free claim preview with pure guard functions. It registers no MCP tool and no CLI subcommand, and performs no on-chain submission.

Predicate previews evaluate against a caller-supplied wall-clock `now`, whereas the Stellar network evaluates time-bound predicates against the apply ledger's close time. A driver wanting tighter guarantees for a boundary-close claim should re-fetch the entry and re-evaluate immediately before submission.

It is part of the stellar-agent-wallet workspace. Most users reach this logic through the `claim` verb in the `stellar-agent-cli` and the `stellar_claim` / `stellar_claim_commit` tools in `stellar-agent-mcp` rather than directly.

## Status

Pre-release alpha. APIs may change between alpha releases without notice.

## License

Apache-2.0. See the repository LICENSE file.

https://github.com/Soneso/stellar-agent-wallet
