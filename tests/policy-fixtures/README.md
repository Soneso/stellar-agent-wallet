# tests/policy-fixtures: adversarial policy fixtures

The driver is `crates/stellar-agent-core/tests/core/policy_fixtures_adversarial.rs`.
Each case is a pair: `<name>.toml`, an unsigned policy body the driver signs
at run time, and `<name>.case.json`, the call and its expected outcome.

## Legacy axes

`adversarial/` holds seven axes of version 1 cases:

- `per_tx_cap_boundary/`: per-transaction cap boundary values.
- `per_period_rollover/`: rolling-window caps over seeded usage.
- `combinator_and_or/`: first-failure order across criteria.
- `counterparty_lookalike/`: homoglyph and case variants of `HOME_DOMAIN`.
- `null_source_account/`: the all-zero G account against a G allowlist.
- `home_domain_resolved/`: home-domain resolution and the missing cache.
- `mutation_stale_key/`: owner-signature verification at load time.

Each of the 28 pairs has a `<name>_v2` companion. Its policy is the same body
as a version 2 document with `sequence = 1`, and its case keeps every
expectation under the companion name. Both must reach the same outcome.

## Version 2 additions

`adversarial/extended_grammar/` covers the four additions, which only
version 2 accepts: the nested `counterparty_allowlist.unlisted` table,
`total_budget`, `balance_floor`, and `memo_binding`. Its cases check the
closed grammar, recipient modes, unlisted budgets on both networks, total
epochs, floor facts, memo bindings, and refusal codes in named tests.

`extended_corpus_budget_network_matrix` checks mainnet approval beyond either
allowance bound, the unchanged testnet refusals, and network-specific spending
summaries. Recorded approval-requiring payments consume the total allocation;
hard caps still deny. Durable mint tests prove actual approval authority.

A `sequence` case evaluates its steps in order against one usage history.
Except for the deliberate zero-digest refusal case, each step loads its policy
through the verified loader, so a total budget counts against the signed
digest. Account views in floor cases are core test
inputs; they do not show that a CLI or MCP caller supplies them.

Oracle staleness and SEP-10 replay are not covered here.

## Durable alias history

`accounting/unlisted_alias_history` is a policy and case pair consumed by
`documented_unlisted_alias_fixture` in the network crate's `policy_engine`
integration tests. Its two history amounts use classic text and its network
SAC, derived through `CanonicalAsset`. Both hydrate into one counter through
the production store. The signed policy evaluates both spellings against that
history and checks equality and excess without rewriting stored bytes.
Restart, re-signing, release, and overflow proofs remain in the accounting
tests; this fixture adds no simulated lifecycle.
