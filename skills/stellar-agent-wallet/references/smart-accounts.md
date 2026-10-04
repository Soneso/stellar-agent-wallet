# Smart-account governance

The `smart-account` CLI group (alias `sa`) governs an on-chain OpenZeppelin smart-account: its context rules, the signer sets and thresholds on each rule, the policy contracts attached to a rule, and the supporting infrastructure (verifier registry, multicall-router registry, upgrade timelock). Every command prints one JSON envelope on stdout and returns exit code `0` on success, `1` on any error.

This file is self-contained. For the MCP tool surface and result-envelope shape see `./mcp-tools.md`. For the value-transfer / DeFi verbs see `./defi.md`.

## Output envelope and amount/asset conventions

- Envelope: `{ ok, data | error, request_id }`. On success `ok: true` with a `data` object; on error `ok: false` with an `error` object carrying a wire code (for example `network.mainnet_write_forbidden`, `validation.rule_name_too_long`, `sa.threshold_policy_identification_failed`).
- Amounts are always decimal strings with a unit, for example `"10 XLM"`, never JSON numbers. Assets are `native` / `XLM` or `CODE:GISSUER`. (These verbs are governance-only; no amounts are taken except per-op fees in stroops.)
- MCP tools take `chain_id`, the CAIP-2 id of the target network, and most tools require it. The CLI reads the network from the profile; `--network <testnet|mainnet>` only asserts the profile's chain.

## Mainnet write refusal

Every signing verb that mutates context-rule, signer, or timelock state refuses a mainnet profile before any RPC call or signing-key access (`network.mainnet_write_forbidden`). This covers `rules` writes, all `signers` verbs including `list` and `refresh`, and `execute`. `list` and `refresh` are included because they emit audit rows. `rules verify-pins` is included because it loads a signer to derive its simulation source account. It also covers `multicall`, `migrate-verifier` submissions, and timelock writes (`schedule`, `cancel`, and `execute`). The four deploy verbs are `deploy-webauthn-verifier`, `deploy-ed25519-verifier`, `deploy-spending-limit-policy`, and `deploy-policy`. A mainnet `migrate-verifier` dry-run remains read-only and allowed.

Exceptions:

| Verb | Mainnet behavior |
|------|------------------|
| `smart-account register-multicall` / `unregister-multicall` | Accept `mainnet` as a local-registry key. |
| Read-only verbs | `smart-account rules get`, `smart-account rules get-spending-limit`, `smart-account rules list` / `smart-account list-rules`, `smart-account list-verifiers`, `smart-account timelock list-pending` accept `mainnet` unconditionally. |

## Signer source (write verbs)

Write verbs take a signer-source group: exactly one of `--signer-secret-env <VAR>` (an env-var name holding the source-account S-strkey) or `--sign-with-ledger` (mutually exclusive; the command refuses if neither is given). `--account-index <INDEX>` selects the Ledger BIP-44 index (default `0`). Pass the variable name, never the secret. The examples on this page that sign with `--signer-secret-env WALLET_SK` read the source-account seed from `WALLET_SK`. Before the first of them, the operator sets it as [Pass a secret seed](https://github.com/Soneso/stellar-agent-wallet/blob/main/docs/getting-started.md#pass-a-secret-seed) shows. In the operator's terminal, run this line on its own, paste the seed when prompted, and press Enter. The line reads the seed from the terminal, so the operator runs it, not the agent.

```bash
printf 'WALLET_SK seed: ' && read -rs WALLET_SK && echo && export WALLET_SK
```

After the last of those examples, the operator runs `unset WALLET_SK` to remove the seed from the shell.

All write signing goes through the smart-account auth-entry digest path: the signer signs the auth digest, which binds the authorizing context-rule ids.

Shared flags available on most verbs: `--profile`, `--network`, `--rpc-url`, `--secondary-rpc-url`, `--timeout-seconds`, `--output` (`json` default or `table`). The `smart-account signers` verbs do not accept `--output`.

## Context rules

A context rule has a `rule_id` (`u32`), a name (OZ cap: 20 bytes), an optional expiry ledger, a signer set (OZ cap: 15 signers), and up to 5 policy contracts. On the write verbs `--auth-rule-id` names the rule whose signers authorize the operation; where it is optional it defaults to the rule being modified (`--rule-id`). Rule `0` is the bootstrap rule installed at deploy time and is the default authorizer.

### `smart-account rules` verbs

| Verb | Purpose | Key flags | Notes |
|------|---------|-----------|-------|
| `create` | Install a rule (OZ `add_context_rule`); returns new `rule_id` | `--account` (req), `--name` (req), `--context <SPEC>` (default `default`), `--signer-delegated <G\|C>` (repeatable), `--signer-webauthn <CRED>` (repeatable), `--signer-ed25519 <HEX_PUBKEY_64>` (repeatable, opt `--verifier <C>` override), `--accept-no-delegated-fallback`, `--accept-mutable-verifier`, `--accept-unknown-verifier`, `--auth-rule-id` (repeatable, default `[0]`), `--valid-until <LEDGER\|none>` (default `none`) | Testnet only. At least one `--signer-delegated`, `--signer-webauthn`, or `--signer-ed25519` required. `--signer-delegated` takes a G-strkey account or a C-strkey contract; only an account delegate is the fallback that spares `--accept-no-delegated-fallback`. After the install confirms, the observed rule's signer identities and simple threshold must equal the proposal's. The observation is recorded as a `SaSignerSetBaselinedV2` baseline (reason `confirmed_install`), so the signer verbs work on it at once. The name, context, expiry, and other policy attachments are not compared. Otherwise the rule stays on chain without a baseline: `sa.install_state_mismatch` (delete it with `rules delete --rule-id N --auth-rule-id 0` or accept it with `signers refresh --rule-id N`), or `sa.baseline_write_failed` with the transaction hash. `--context` scopes the rule: `default` matches any invocation, `call-contract:<C>` scopes it to one contract, `create-contract:<64_HEX_WASM_HASH>` scopes it to deploying one wasm hash. Malformed specs refuse before any network call. |
| `get` | Read one rule (OZ `get_context_rule`) | `--account` (req), `--rule-id` (req), `--source-account <G>` (req) | Read-only, mainnet OK. Source account is for simulation only, not debited. Envelope: `present: true\|false`. |
| `set-name` | Rename (OZ `update_context_rule_name`) | `--account`, `--rule-id`, `--name` (all req), `--auth-rule-id` (opt, default `--rule-id`) | Testnet only. 20-byte name cap. An `--auth-rule-id` other than `0` passes the pre-submission checks. |
| `set-valid-until` | Change expiry (OZ `update_context_rule_valid_until`) | `--account`, `--rule-id`, `--valid-until <LEDGER\|none>` (all req), `--auth-rule-id` (opt) | Testnet only. `none` clears expiry (permanent rule). An `--auth-rule-id` other than `0` passes the pre-submission checks. |
| `delete` | Remove a rule (OZ `remove_context_rule`) | `--account`, `--rule-id` (req), `--auth-rule-id` (opt) | Testnet only. An `--auth-rule-id` other than `0` passes the pre-submission checks. |
| `verify-pins` | Drift-check pinned verifier/policy WASM hashes vs on-chain | `--account`, `--rule-id` (req) | Read-only. Refuses a mainnet profile with `network.mainnet_write_forbidden`, because it loads a signer. Exit `1` if any pin status is `drift`. Envelope adds `observed_*_executable` (external-reference summary or `no code`, `null` for plain WASM) and `pinned_*_executable_refs` (pinned owner and tag, `null` for a WASM pin), aligned with the first-8 lists and omitted when empty. |
| `add-policy` | Attach a policy (OZ `add_policy`); returns `policy_id` | `--account`, `--rule-id` (req); `--kind <raw\|spending-limit\|simple-threshold\|weighted-threshold>` (default `raw`); raw: `--policy-address <C>`, `--install-param <SCVAL_BASE64>` (req); spending-limit: `--limit <STROOPS>`, `--period <LEDGERS>` (req), `--policy <C>` (opt override); simple-threshold: `--threshold <U32>` (req); weighted-threshold: `--threshold <U32>` (req) plus one or more `--weighted-signer-delegated <G=WEIGHT>` / `--weighted-signer-webauthn <CRED=WEIGHT>`; `--auth-rule-id` (opt, repeatable); `--accept-mutable-verifier` / `--accept-unknown-verifier` (opt) | Testnet only. Per-rule cap of 5 enforced via pre-fetch. The add holds the lock of the rule and of its non-zero auth rules until its pin rows are written, so a concurrent `signers add` runs before or after it. Under the lock, for any policy, the rule needs a version-2 baseline matching the chain (`sa.signer_set_missing_baseline`, `sa.signer_set_baseline_legacy` or `sa.signer_set_diverged` otherwise); then the policy's executable is read through both endpoints. On a pinned rule the policy is probed (policy allowlist and mutability, the two flags as on `rules create`). After the add confirms, `SaContextRulePinsUpdated` (reason `policy_added`) records its pin; with no policy on chain the row replaces the policy pins with the added policy's pin. Two policy pins make every checked signing verb refuse with `sa.pin_check_unavailable`. Raw `--install-param` is standard-base64 XDR `ScVal` (not base64url), passed through raw. Attaching the simple-threshold policy needs a non-zero `{ threshold: u32 }` parameter (`sa.simple_threshold_install_refused` otherwise); a rule that already has one refuses with `sa.threshold_policy_identification_failed`. Once it confirms, `SaThresholdChangedV2` records the threshold; a result that is not the intended change refuses with `sa.signer_set_diverged` and the transaction hash, and the pin and policy rows are still written. Row order: `SaThresholdChangedV2` (simple-threshold policy only), override rows, `SaContextRulePinsUpdated`, `SaPolicyAdded`, `SaRawInvocation`. A simulated return value that carries no policy id refuses the add before signing with `sa.deployment_failed`. A confirmed add whose return value still carries no policy id returns `sa.baseline_write_failed` at stage `observe` with the transaction hash and writes its pin rows; `rules get --rule-id N` shows the attached policy's id. `--kind spending-limit` resolves the deployed policy from the registry, builds the typed install param, and refuses client-side if `--limit <= 0`, `--period == 0`, or the rule's context type is not `call-contract`. `--kind weighted-threshold` refuses client-side if the signer-weight set is empty, `--threshold == 0`, or `--threshold` exceeds the weight sum. |
| `remove-policy` | Detach a policy (OZ `remove_policy`) | `--account`, `--rule-id`, `--policy-id <U32>` (all req), `--auth-rule-id` (opt, repeatable) | Testnet only. The removal holds the lock of the rule and of its non-zero auth rules until its pins row is written, so a concurrent `signers add` runs before or after it and its verifier pin survives. Under the lock, for any policy, a rule without a signer-set state refuses with `sa.signer_set_missing_baseline` before any RPC. A rule with a state that is not on chain refuses from the comparison's rule read, and a `--policy-id` the rule does not hold refuses with `sa.deployment_failed` after the comparison. A version-1 state refuses with `sa.signer_set_baseline_legacy` and a changed chain with `sa.signer_set_diverged`. A policy whose executable cannot be read refuses with `sa.deployment_failed`, `sa.contract_instance_unsupported` or `network.rpc_divergence` (remove a rule whose policy stays unreadable with `rules delete --rule-id N --auth-rule-id 0`). Detaching the simple-threshold policy needs the observed threshold policy to be the removed one, and records the cleared threshold as `SaThresholdChangedV2`. Removing one of two simple-threshold policies, a state the signer verbs refuse, repairs the rule when it has a version-2 baseline recorded before it gained its second policy: its signers must equal the baseline's, and the wallet records the remaining policy's threshold. Without a baseline it refuses with `sa.signer_set_missing_baseline`; delete it with `rules delete --rule-id N --auth-rule-id 0`. Removing a policy other than the two from such a rule refuses with `sa.threshold_policy_identification_failed`. Row order: `SaThresholdChangedV2` (simple-threshold policy only), `SaContextRulePinsUpdated`, `SaPolicyRemoved`, `SaRawInvocation`. On a pinned rule, after the removal confirms, `SaContextRulePinsUpdated` (reason `policy_removed`) drops the pin equal to the removed policy's hash. The single pin of a rule's only policy is dropped even when the policy differs from its pin; otherwise no matching pin writes no row. Removing the last policy under a record with two or more policy pins leaves the rule refused with `sa.pinned_policy_absent` until `rules add-policy` under rule `0` re-pins a policy or a reinstall replaces the rule. |
| `list` | Enumerate active rules (on-chain scan) | same as `smart-account list-rules` | Read-only, mainnet OK. Alias of `smart-account list-rules`. Reports each rule's signer-set `baseline` (see "Rule enumeration"). |
| `get-spending-limit` | Read an installed spending-limit policy's budget state | `--account`, `--rule-id`, `--source-account <G>` (all req) | Read-only, mainnet OK. Identifies the policy, reads `get_spending_limit_data`, computes the rolling-window snapshot. Envelope includes `spending_limit`, `period_ledgers`, `in_window_spent`, `remaining_budget`, `as_of_ledger`, `window_cutoff_ledger`, `history_entries`, `cached_total_spent`; the i128 amount fields are decimal strings, not JSON numbers. `in_window_spent`/`remaining_budget` are exact only as of `as_of_ledger`: a point-in-time estimate, not a guarantee for a future submission. |
| `set-spending-limit` | Retune the limit (OZ `set_spending_limit`) without resetting spend history | `--account`, `--rule-id`, `--limit <STROOPS>` (all req) | Testnet only. Refuses client-side if `--limit <= 0`. Mutates ONLY the limit: the period is immutable post-install; changing it requires `remove-policy` + `add-policy`, which DOES reset history. |

Name-related errors: a name over 20 bytes is refused with `validation.rule_name_too_long`. A rule with only `--signer-webauthn` signers and no `--accept-no-delegated-fallback` is refused with `validation.passkey_only_rule_no_delegated_fallback`.

Create example:

```bash
stellar-agent smart-account rules create \
  --account CABC...WXYZ \
  --name agent-ops \
  --signer-delegated GABC...WXYZ \
  --signer-secret-env WALLET_SK
```

`verify-pins` reports each `*_pin_status` as one of `match`, `drift`, `unavailable`, `no_pin`, `no_contracts`. `drift` also covers a pinned policy with no policy on chain: `policy_pin_status` is `drift` with an empty observed list. A live verifier the record does not pin also reports verifier `drift`.

A rule with one drifted and one unavailable pin reports both statuses, carries the unavailable probe's code in `unavailable_reason`, and exits 1.
A failed executable read reports `sa.deployment_failed` in `unavailable_reason`.

## Signer kinds

The wallet labels signer sources in the `signers add` envelope and observed kinds in `signers list`. The labels are:

| `signer_source` in `signers add` | `signer_kinds` in `signers list` | OZ signer | How added |
|---|---|---|---|
| `delegated` | `delegated_ed25519` | `Signer::Delegated(Address)` with a G-strkey account | `--signer-delegated <G>` (alias `--new-signer`) |
| `ed25519` | `external` | External Ed25519 verifier and public key; no funded classic account required, HSM/keyring-holdable, cheap rotation | `--signer-ed25519 <HEX_PUBKEY_64>`; optional `--verifier <C>` |
| `external` | `external` | External verifier and raw key data | `--signer-external <C>` with `--signer-key-data <HEX>` |
| `webauthn` | `external` | External WebAuthn verifier and passkey data | `--signer-webauthn <CRED>` |
| No add source | `delegated_contract` | `Signer::Delegated(Address)` with a contract | `rules create --signer-delegated <C>` |

The wallet cannot decode an unknown signer kind, a malformed signer, or an `External` signer with empty key data. A rule holding such a signer is refused for every operation with `sa.deployment_failed`, and the reason names the signer's index. Delete it with `smart-account rules delete --rule-id N --auth-rule-id M`, where rule `M` is one the wallet can read. A signer delegated to a contract address is readable, and `rules create` installs one.

## Signer-set and threshold lifecycle

All `smart-account signers` verbs take `--account <C>` and `--rule-id <U32>` (both required), the signer-source group, `--profile`, `--network`, `--rpc-url`, `--secondary-rpc-url`, `--timeout-seconds`. None accept `--output`. All structurally refuse `mainnet` (including `list` and `refresh`). `list` and `refresh` require a signer source because the manager needs a source account to assemble the read envelope.

Every signature under a non-zero rule compares its signer set with its audit-log baseline through both RPCs before signing. This covers signer mutations, `execute`, `multicall`, authorizing `rules` write rules, and the passkey path (see "Pre-submission checks"). Mutations record the confirmed result as version 2 state. `sa.signer_set_missing_baseline` requires `signers list`. `sa.signer_set_baseline_legacy` requires one `signers refresh` before `signers add`, `remove`, `set-threshold`, or `batch-add`. It also covers `rules add-policy` and `rules remove-policy` for any policy, and a `migrate-verifier` removal. `sa.signer_set_diverged` means the chain changed; inspect with `list`, and accept with `refresh --accept-divergence`. `sa.baseline_write_failed` means the confirmed result was not recorded; refresh with acceptance records it. Refresh also pins a live verifier when the pin record pins none (`sa.pinned_verifier_absent`). Each verb waits for the rule's lock at most `--timeout-seconds`, then refuses with `sa.auth_entry_construction_failed` at stage `rule_lock`.

Version 2 compares signer additions, removals, any key-data byte swapped, id reassociations, and Delegated contract-address replacements. It also compares simple-threshold values and that policy's attachment or detachment outside the wallet. Version 1 sees only 16 bytes of External key data and has no contract-delegate form; `signers refresh` records version 2. The comparison holds the rule's lock, and both RPC endpoints must agree. Rule 0 skips the lock, signer-set check, and pin check. On a rule with a pin record, each live verifier is compared with the verifier pin, and each live policy with the policy pins. The first eight bytes of the live code hash must equal the pinned value; the record stores that prefix. An external reference must also match its pinned reference identity and resolved hash prefix. An empty policy-pin list checks no policy code, so pins do not detect a policyless rule gaining a policy outside the wallet. During a `migrate-verifier` pair, the migrating rule skips its verifier pin check. The attached policy set itself is not recorded. A policy attached outside the wallet with a matching pinned hash prefix and reference identity is not detected by pins. A rule without a pin record has no code check. Coverage excludes weighted-policy weights and thresholds, spending-limit configuration, arbitrary policy storage, rule scope and expiry, identical or commonly stale endpoints, and observation-to-settlement changes. It excludes weighted-threshold or spending-limit attachment and detachment outside the wallet, subject to the code check. Re-simulation does not prove equality at execution.

| Verb | Purpose | Extra flags | Notes |
|------|---------|-------------|-------|
| `list` | Read the signer set through both RPCs; baseline if none exists, otherwise compare | none | Testnet only. Writes a `SaSignerSetBaselinedV2` audit row on first sight of a `(rule_id, account)` pair and nothing afterwards. Envelope: `signer_count`, `threshold` (`null` without a simple-threshold policy), `snapshot_version`, `signer_ids`, `signer_kinds`, `signer_summaries`, `baseline` (`none`, `matched`, `diverged`, `not_comparable`). No on-chain tx. |
| `refresh` | Compare with the baseline and re-anchor it | `--accept-divergence`, `--accept-mutable-verifier`, `--accept-unknown-verifier` | Testnet only. Audit-log write only; use after an intentional out-of-band signer change, once on a rule whose baseline is version 1 (`sa.signer_set_baseline_legacy`), and on a rule refused with `sa.pinned_verifier_absent`. A changed set, or a version 1 baseline the chain cannot be compared with, refuses with `sa.signer_set_diverged` unless `--accept-divergence` is set. When the rule's pin record pins no verifier while the rule holds `External` signers, the refresh probes each live verifier as `rules create` does. A mutable or unknown verifier needs the matching flag (`sa.verifier_mutable` / `sa.verifier_wasm_not_in_allowlist`), and an unpinnable one refuses with `sa.contract_instance_unsupported` regardless. After the baseline it writes the override rows and `SaContextRulePinsUpdated` (reason `baseline_refreshed`) pinning the verifier. Two verifier addresses whose pins are equal, in hash and executable reference, share one pin. Live verifiers whose pins differ refuse with `sa.multiple_pinned_hashes_unsupported` before the baseline or any pin row is written; delete the rule (`rules delete --rule-id N --auth-rule-id 0`) or reinstall it. A record that already pins a verifier is left alone. Envelope adds `previous_baseline` and `verifier_pinned`. |
| `add` | Add a signer (OZ `add_signer`); returns `new_signer_id` | exactly one of `--signer-delegated <G>` (alias `--new-signer`) / `--signer-ed25519 <HEX_PUBKEY_64>` (optional `--verifier <C>` override) / `--signer-external <C>` / `--signer-webauthn <CRED>`; `--signer-key-data <HEX>` required with and only with `--signer-external` | Testnet only. Per-rule cap of 15 checked via pre-fetch. `--signer-ed25519` fails closed if no verifier is registered and `--verifier` is omitted (deploy one via `smart-account deploy-ed25519-verifier`). On a pinned rule, an External signer on a verifier the rule does not use yet is probed first (allowlist and mutability, `--accept-unknown-verifier` / `--accept-mutable-verifier` as on `rules create`) and, after the add confirms, `SaContextRulePinsUpdated` (reason `signer_added`) records one pin per distinct verifier; two verifier pins make every checked signing verb refuse with `sa.pin_check_unavailable`. |
| `remove` | Remove a signer (OZ `remove_signer`) | `--signer-id <U32>` (req) | Testnet only. Refused if removing would drop `signer_count` below `threshold`; lower the threshold first. A rule whose policies include no simple-threshold policy, such as a weighted-threshold rule, refuses with `sa.threshold_policy_identification_failed` before submission. |
| `set-threshold` | Change quorum threshold via the threshold-policy contract `set_threshold` | `--new-threshold <U32>` (req) | Testnet only. No `--auth-rule-id` override (the authorizing rule is `--rule-id`). The threshold-policy contract is found by WASM-hash allowlist lookup; no match refuses with `sa.threshold_policy_not_installed`, more than one with `sa.threshold_policy_identification_failed`. |
| `set-weighted-threshold` | Change a weighted-threshold policy's threshold (`set_threshold` on that policy) | `--new-threshold <U32>` (req); `--auth-rule-id <U32>` (opt, default `--rule-id`) | Testnet only. Refuses client-side if `0` or above the current signer-weight sum. Use an admin rule for `--auth-rule-id` when `--rule-id` is scoped (CallContract/CreateContract). |
| `set-signer-weight` | Change one signer's weight in a weighted-threshold policy (`set_signer_weight`) | `--new-weight <U32>` (req); target signer: one of `--signer-delegated <G>` / `--signer-ed25519 <HEX_PUBKEY_64>` (opt `--verifier`) / `--signer-external <C>` (req `--signer-key-data`) / `--signer-webauthn <CRED>`; `--auth-rule-id` (opt, same default) | Testnet only. Refuses client-side if the adjusted weight sum would fall below the current threshold. |
| `batch-add` | Add MULTIPLE signers in ONE transaction (OZ `batch_add_signer`); returns `new_signer_ids` | one or more, repeatable, any combination: `--signer-delegated <G>` / `--signer-webauthn <CRED>` / `--signer-ed25519 <HEX_PUBKEY_64>` (opt `--verifier` override for all `--signer-ed25519` entries) | Testnet only. Per-rule cap of 15 checked client-side. Refuses an empty batch. Returns the id the chain assigned to each signer, in input order. Keeps a pinned rule's pin record in step as `add` does, with the same two override flags. |

Quorum update sequence: to raise then add, or to lower then remove, order matters. It runs on an installed rule with a simple-threshold policy; the bootstrap rule `0` a deploy creates has none:

```bash
# Lower threshold before removing a signer
stellar-agent smart-account signers set-threshold --account CABC...WXYZ --rule-id 1 --new-threshold 1 --signer-secret-env WALLET_SK
stellar-agent smart-account signers remove --account CABC...WXYZ --rule-id 1 --signer-id 2 --signer-secret-env WALLET_SK
```

## Verifier and policy WASM-hash pinning

Verifier contracts are governed by a compile-time allowlist; no central server is consulted. Each entry carries a SHA-256 WASM hash and an audit status with `kind` discriminator `audited`, `provisional`, `unaudited`, `revoked`, or `retired`:

| Status | Meaning | Install gate | Advisory |
|--------|---------|--------------|----------|
| `audited` | Auditor-attested (`auditor` + `audited_at` fields) | Allowed | None |
| `provisional` | Named-party internal artefact review; no external audit report yet (`attested_by` + `attested_at` fields) | Allowed | None |
| `unaudited` | No audit attached | Operator-acknowledged risk required | None |
| `revoked` | Disclosed-vulnerable (`revoked_at` + `reason`) | Blocked unless overridden | Fires on every CLI invocation until migrated |
| `retired` | `revoked` past 24-month retention (`revoked_at` + `retired_at`; reason dropped) | Blocked unless overridden | Still fires |

`smart-account list-verifiers` enumerates the allowlist with this taxonomy (read-only, no network, only flag is `--output`). It has two `provisional` OZ `multisig-webauthn-verifier-example` entries: the canonical v0.7.2 (WASM SHA-256 `9427e3dd71fb29115c6f0efdf2f703b32fec566b151421f991c3b4e248ebb1f7`), which new deployments use, and the legacy v0.7.1 (WASM SHA-256 `678006909b50c6c365c033f137197e910d8396a2c68e9281327a2ed7dbf4b27a`), still recognized for verifier contracts already deployed on-chain. The two versions share an identical ABI.

Override flags on `smart-account rules create`:

- `--accept-mutable-verifier`: proceed even if a referenced verifier or policy contract is mutable. It has an admin/owner key, or its executable is an owner-managed external reference (envelope reports `mutable_override: true`). For an external reference the pin records the owner, the tag, and the first eight bytes of the resolved code hash. The envelope lists them in `pinned_verifier_executable_refs` / `pinned_policy_executable_refs`. When the resolved hash prefix, reference identity, or executable kind differs from the pin, the pinned-hash drift check (below) refuses signing under the rule with `sa.verifier_hash_drift` / `sa.policy_hash_drift`. It refuses in `execute`, `multicall`, the rule and signer write verbs, and `migrate-verifier` for the rule's policies. A rule whose record holds policy pins while the rule has no policy on chain refuses with `sa.pinned_policy_absent`. A rule holding an `External` signer while its record pins no verifier refuses with `sa.pinned_verifier_absent`, and a check that cannot run refuses with `sa.pin_check_unavailable`. `--accept-unknown-verifier` is also required when the resolved hash is outside the allowlist. The wallet refuses an external reference with no live tag entry, an undecodable instance, or an instance returned under an unrequested key. It also refuses a non-Wasm executable or an executable that changes during install. These cases return `sa.contract_instance_unsupported`. The reason is `external reference with no live tag entry`, `undecodable instance`, `non-Wasm executable`, or `executable changed during install`. Neither override flag admits them, because the wallet cannot pin their code.
- `--accept-unknown-verifier`: proceed even if a referenced verifier or policy WASM hash is not in the allowlist (envelope reports `unknown_override: true`).

A refusal raised while the referenced contracts are probed before install (`sa.verifier_wasm_not_in_allowlist`, `sa.policy_wasm_not_in_allowlist`, `sa.verifier_mutable`, `sa.policy_mutable`, `sa.contract_instance_unsupported`, `network.rpc_divergence`) carries no `rule_id`, because the rule has no on-chain id yet. An applied override is recorded as `SaMutableContractOverride` / `SaUnknownContractOverride` after the install confirms, carrying the new rule's id, before `SaContextRuleCreated`; a refused install writes no override row.

The policy allowlist holds the simple-threshold, weighted-threshold and spending-limit Wasms the wallet vendors; `rules add-policy` takes the same two flags for the policy it attaches.

Drift detection: `smart-account rules verify-pins` compares a rule's pinned verifier and policy hashes against the live on-chain contracts (see the rules table).

Pre-submission checks run before anything is simulated or signed. Every verb that signs under a rule other than `0` runs four steps for each such rule, in ascending rule order and under one deadline. This covers `execute`, `multicall`, the `rules` and `signers` write verbs, and `migrate-verifier`. It holds the rule's lock (stage `rule_lock` when the lock is not acquired in time). It reads the rule's signer-set baseline with no RPC (`sa.signer_set_missing_baseline` without one; `sa.audit_log` on an audit-log integrity error). It runs the pinned-hash drift check (step 3). It compares the rule's signer set through both RPCs with the baseline (`sa.signer_set_diverged`, `network.rpc_divergence`). Each step runs for every rule before the next starts, so the earliest step's refusal wins. An elapse during a baseline read or a comparison refuses with `sa.auth_entry_construction_failed` at stage `baseline_read` or `signer_set_compare`; during the pin check, with `sa.pin_check_unavailable`. `multicall` reports refusals of these checks as `sa.multicall_failed`. Most refusals render at phase `policy_gate`; a `sa.deployment_failed` keeps its `simulate` or `submit` phase. A version 1 authorizing rule with a contract delegate cannot form its projection and refuses at phase `simulate`. A signer-set read that refuses with `sa.contract_instance_unsupported` renders at phase `submit`. A verb that holds the rule's lock itself (a signer verb, `migrate-verifier`) compares the rule before it submits. A verb that reads an id from the return value (`signers add`, `rules add-policy`, `rules create`) refuses a simulated return value of another shape with `sa.deployment_failed` before signing. The add step of `migrate-verifier` reports the same refusal as `sa.verifier_migration_failed` at phase `submit_simulate`.

Pinned-hash drift check (step 3): the wallet compares the rule's live verifiers and policies with its pin record, the newest `SaContextRuleCreated` or `SaContextRulePinsUpdated` audit row for the rule.

- Drift refuses with `sa.verifier_hash_drift` / `sa.policy_hash_drift` and writes a drift audit row carrying the request id. A rule whose pin record holds policy pins while the rule has no policy on chain refuses with `sa.pinned_policy_absent` (no drift row). Repair it with `rules add-policy` authorized under rule `0`, which pins the added policy and replaces the stale pins, or reinstall the rule. A rule holding an `External` signer whose pin record pins no verifier refuses with `sa.pinned_verifier_absent` (no drift row). Repair it with `signers refresh --rule-id N`, which pins the live verifier.
- A check that cannot run refuses with `sa.pin_check_unavailable`, whose message leads with the inner code (RPC failure, or `sa.multiple_pinned_hashes_unsupported` for a record with two verifier or policy pins). An audit-log integrity error is reported earlier, by the baseline read, as `sa.audit_log`, under the migrating rule of `migrate-verifier` too.
- A rule without a pin record (installed outside the wallet) is not checked for drift. A rule with a pin record and no `External` signer is not checked for a verifier. Rule 0, the bootstrap rule, is exempt from the rule lock, the signer-set check and the pin check; it has no pins, and the submit path never reads a baseline for it. The wallet sends nothing in any refusal.
- `migrate-verifier` checks the migrating rule's policies and skips its verifiers. `signers add` / `batch-add` / `migrate-verifier` / `rules add-policy` / `rules remove-policy` write `SaContextRulePinsUpdated` when they change a pinned rule's verifiers or policies, so the wallet's own changes do not lock the rule out. The signer verbs, the policy verbs and `migrate-verifier` read the record and write that row under the rule's lock, so a concurrent pair on one rule never loses a pin. A `signers add` whose new verifier's pin equals a recorded pin (hash and executable reference) keeps the list unchanged. `signers refresh` writes one (reason `baseline_refreshed`) when it pins the live verifier of a record that pins none, and when it drops the one verifier pin of a rule with no `External` signer.
- A rule whose verifier, policy, or signers changed outside the wallet is refused for its own administration too: authorize the repair through rule `0`.

## Smart-account infrastructure

The chain and endpoints come from the resolved profile. Optional `--network` must equal the profile's chain.
Optional RPC flags override testnet endpoints; a mainnet profile refuses either RPC flag, including equal values.
Without a secondary flag, the profile's `secondary_rpc_url` applies. RPC flags refuse URLs containing credentials.

`rules get`, `rules get-spending-limit`, and all four deployment verbs accept `--profile`. Explicitly named missing profiles refuse.
Mainnet seed, Ledger, and keyring signers must match the enrolled account. `rules verify-pins` reads both endpoints from the profile.

### Verifier deploy and migration

`smart-account deploy-webauthn-verifier` deploys the OZ WebAuthn-verifier WASM and records its address in the verifier registry (`<canonical_data_root>/networks.toml`). Idempotent — if the registry already holds a same-WASM-hash entry for the network it returns `status: "already_deployed"` with no RPC traffic. Testnet only.

- Deployer source (exactly one): `--deployer-secret-env <VAR>` or `--sign-with-ledger`; `--account-index <INDEX>` default `0`.
- `--profile` selects the chain and endpoints. `--rpc-url` overrides testnet only and defaults to the profile endpoint. `--fee <STROOPS|auto[:pNN]>` (`auto` = p95; also `auto:p50`/`auto:p75`/`auto:p95`/`auto:p99`; absent uses the profile default 100-stroop base plus simulated Soroban resource fees). `--timeout-seconds` default `60`.
- `--dry-run` derives the verifier address with no network access or signing; returns `status: "dry_run"`.

This example reads the deployer seed from `DEPLOYER_SK`; the operator sets it as [Pass a secret seed](https://github.com/Soneso/stellar-agent-wallet/blob/main/docs/getting-started.md#pass-a-secret-seed) shows and unsets it after the command.

```bash
stellar-agent smart-account deploy-webauthn-verifier --deployer-secret-env DEPLOYER_SK
```

`smart-account deploy-ed25519-verifier` and `smart-account deploy-spending-limit-policy` deploy the OZ Ed25519-verifier and spending-limit-policy WASMs respectively, with the same idempotency, signer modes, and flags as `deploy-webauthn-verifier` above. Both are per-network singletons — deploy once per network. The Ed25519 verifier backs `--signer-ed25519`; the spending-limit policy backs `rules add-policy --kind spending-limit`.

These examples read the deployer seed from `DEPLOYER_SK`; the operator sets it as [Pass a secret seed](https://github.com/Soneso/stellar-agent-wallet/blob/main/docs/getting-started.md#pass-a-secret-seed) shows and unsets it after the commands.

```bash
stellar-agent smart-account deploy-ed25519-verifier --deployer-secret-env DEPLOYER_SK
stellar-agent smart-account deploy-spending-limit-policy --deployer-secret-env DEPLOYER_SK
```

`smart-account deploy-policy --kind <simple-threshold|spending-limit|weighted-threshold>` deploys any of the three policy contracts through one verb, same flags/idempotency as above; recommended over `deploy-spending-limit-policy`. Each kind uses its own salt domain, so the three kinds deployed by the same deployer on the same network land at different addresses.

This example reads the deployer seed from `DEPLOYER_SK`; the operator sets it as [Pass a secret seed](https://github.com/Soneso/stellar-agent-wallet/blob/main/docs/getting-started.md#pass-a-secret-seed) shows and unsets it after the command.

```bash
stellar-agent smart-account deploy-policy --kind weighted-threshold --deployer-secret-env DEPLOYER_SK
```

`smart-account migrate-verifier` builds and optionally executes a plan that moves all `external` signers from one verifier to another across every context rule. Dry-run is read-only and renders the plan as JSON; without `--dry-run` it signs and submits `remove_signer` / `add_signer` pairs. Mainnet dry-run allowed (read-only); mainnet submit structurally refused (`network.mainnet_write_forbidden`). Pre-flight gates (fail closed): destination verifier hash must be allowlisted, its audit status must be `audited`, `provisional`, or `unaudited`, and the destination contract must be immutable. Each pair runs under the rule's lock as two checked signer mutations. The removal compares the rule with its version-2 state (`sa.signer_set_missing_baseline`, `sa.signer_set_baseline_legacy`, `sa.signer_set_diverged`), checks the plan (`sa.verifier_migration_failed` at phase `plan_build`) and the removal's preconditions, then records `SaSignerRemovedV2`. On a pinned rule `SaContextRulePinsUpdated` (reason `verifier_migrated`) then names the destination's hash as the rule's verifier pin. The add compares against the removal's row, records `SaSignerAddedV2`, then `SaVerifierMigrated`; no refresh is needed afterwards. Each pair signs under the migrating rule: the drift check runs on its policies (`sa.policy_hash_drift` / `sa.pinned_policy_absent` / `sa.pin_check_unavailable`) and skips its verifiers.

- Preconditions (refused before any send): `sa.threshold_unreachable` when the rule's threshold equals its signer count, a 1-of-1 rule included; `sa.threshold_policy_identification_failed` for a rule with policies and no simple-threshold policy. The source key must be a Delegated signer of the rule. A rule that cannot be administered under itself is deleted (`rules delete --rule-id N --auth-rule-id 0`) and reinstalled with the destination. Adding the destination first and removing the source second leaves two verifier pins, and the removal refuses with `sa.pin_check_unavailable`.
- Partial failure: a pair that stops after its removal was sent returns `pending_add` (`rule_id`, `signer_id`, `to_verifier_address`, `key_data_hex`, `remove_tx_hash`, `remove_confirmed`, `add_tx_hash`, `recovery_command`) and prints the completing line on stderr. Removal recorded, add failed: run the printed `signers add`. `sa.baseline_write_failed` or `sa.signer_set_diverged` (the newest state row is not the chain's): run `signers refresh --account C --rule-id N --accept-divergence`, then the `signers add`. Removal with an unknown outcome (`submission.*`, `remove_confirmed: false`): once it is confirmed, refresh then add; if it is not found, re-run `migrate-verifier`. Add with an unknown outcome: once confirmed, refresh; if not found, the `signers add`. Add the invocation's `--rpc-url` / `--secondary-rpc-url` yourself; the output never echoes a URL. A re-run of `migrate-verifier` does not find a removed signer.
- From a pair's removal on, the record names the destination: on a rule with remaining source signers, signing under it refuses with `sa.verifier_hash_drift` until they migrate. The printed line then names `re-run migrate-verifier for the remaining signers of rule <N>` after the refresh or the wait for an unknown outcome, and before the `signers add`.

- `--account <C>` (req), `--from <HASH_HEX>` (req, 64-char hex SHA-256 of the source verifier WASM), `--to <C>` (req, destination verifier), `--dry-run`, signer-source group (required for submit, not for dry-run).

```bash
stellar-agent smart-account migrate-verifier \
  --account CABC...WXYZ \
  --from 678006909b50c6c365c033f137197e910d8396a2c68e9281327a2ed7dbf4b27a \
  --to CNEW...WXYZ \
  --dry-run
```

### Rule enumeration

`smart-account list-rules` (alias backing `smart-account rules list`) scans the on-chain `[0, max_scan_id)` rule-id space and returns each active rule in `rule_id` order. Read-only, mainnet OK. Each rule's `baseline` reports its signer-set baseline in the profile's audit log: `none`, `v1`, `v2`, `unreadable` (an audit-log integrity error) or `unknown` (the log was not read). A rule reporting `none` refuses every signature under it with `sa.signer_set_missing_baseline` until one `signers list --rule-id N` records the baseline.

- `--account <C>` is required. `--source-account <G>` defaults to a funded account on testnet; on mainnet, supply a funded account for simulation.
- `--rpc-url` and `--secondary-rpc-url` use the profile endpoints. Optional `--network` must match the profile chain; `--profile` selects the profile.
- `--max-scan-id <N>` accepts `1..=10000`, using the profile bound or `50` when absent. `--timeout-seconds` defaults to `60`; `--output` selects the output format.

### Multicall router registry

`smart-account register-multicall` records a deployed multicall-router address and its WASM hash in `<canonical_data_root>/networks.toml` (local file plus audit row, idempotent). Refuses if `--wasm-sha256` does not equal the binary's compiled-in router WASM hash.

- `--network` (optional assertion against the profile chain), `--address <C>` (req), `--wasm-sha256 <HEX>` (req, 64-char lowercase hex), `--profile`.

`smart-account unregister-multicall` removes the entry. The normal path validates and removes. `--force` is for registry-file corruption recovery (bypasses strkey/hex validation, locates by network name) and needs interactive `[y/N]` confirmation on a TTY or `--yes-i-have-verified-the-prior-values` for non-TTY; the audit row is written before the file is mutated.

- `--network` (optional assertion against the profile chain), `--force`, `--yes-i-have-verified-the-prior-values`, `--profile`.

## Multicall submission

`smart-account multicall` submits an atomic multicall bundle (1 to 50 invocations) through the registered router for the target network. Signs and submits. The router address is resolved from the local registry. On a mainnet profile the command refuses with `network.mainnet_write_forbidden` before any registry, writer, or signer access. Signer source required.

Each `--invocation` is `<target>:<fn>:<json-args>` where `<target>` is the C-strkey of the contract to call, `<fn>` is the function name, and `<json-args>` is a JSON array of **scalar** arguments encoded directly: a JSON number becomes an `i128`, a JSON string becomes a Soroban `String` (raw UTF-8), and `null` becomes `Void`. Booleans, objects, and nested arrays are rejected. There is no automatic typed encoding — a string is not turned into an `Address`, so functions that take addresses or other non-scalar types cannot be driven through this JSON form.

| Flag | Meaning |
|------|---------|
| `--smart-account <C>` (req) | Smart-account executing the bundle |
| `--rule-id <U32>` (req) | Context rule authorizing the bundle |
| `--invocation <TARGET:FN:JSON_ARGS>` (req, repeatable, 1–50) | One invocation descriptor |
| `--secondary-rpc-url <URL>` | Secondary RPC for cross-verification: the flag, else the profile's `secondary_rpc_url`, else a typed error. |
| `--fee <STROOPS>` | Per-op base fee, default `100`; `auto[:pNN]` is rejected here (unlike the deploy verbs) |

```bash
stellar-agent smart-account multicall \
  --smart-account CABC...WXYZ \
  --rule-id 0 \
  --invocation 'CCTR...WXYZ:set_value:[42]' \
  --secondary-rpc-url https://rpc2.example \
  --signer-secret-env WALLET_SK
```

## Upgrade timelock (`smart-account timelock`)

Schedule, cancel, execute, and list pending operations on an OpenZeppelin timelock contract. The signer must hold the appropriate role for each write verb. All four share `--timelock <C>` (req), `--rpc-url`, `--secondary-rpc-url`, `--network`, `--profile`; the write verbs add the signer-source group. Write verbs (`schedule`, `cancel`, `execute`) refuse `mainnet`; `list-pending` is read-only and accepts `mainnet`. Without the secondary flag, the profile secondary applies. Timelock uses the primary if no secondary is configured.

| Verb | Role | Extra flags | Notes |
|------|------|-------------|-------|
| `schedule` | PROPOSER | `--target <C>` (req), `--function <NAME>` (req), `--delay-ledgers <N>` (req) | Salt is derived non-deterministically and returned as the `salt` field (64-char lowercase hex). The envelope also carries `operation_id_full_hex`. Record the salt immediately — it is required by `execute` and `cancel` and cannot be recomputed. |
| `cancel` | CANCELLER | `--operation-id <HEX>` (req, 64-char hex from schedule) | Cross-confirms the on-chain cancellation event. |
| `execute` | EXECUTOR (or open-execution) | `--target <C>` (req), `--function <NAME>` (req), `--operation-id <HEX>` (req), `--salt <HEX>` (req) | Dual-RPC ready-window check, fails closed if not ready. `--target`, `--function`, `--operation-id`, `--salt` must exactly match the scheduled operation, since OZ re-derives the operation id from them. |
| `list-pending` | — | — | Read-only, mainnet OK. Cross-references the local audit log with a dual-RPC `get_operation_state` query. |

The schedule-then-execute flow centers on the returned `{operation_id, salt}`. The schedule step reads the proposer seed from `PROPOSER_SK`, and the execute step reads the executor seed from `EXECUTOR_SK`. The operator sets each as [Pass a secret seed](https://github.com/Soneso/stellar-agent-wallet/blob/main/docs/getting-started.md#pass-a-secret-seed) shows and unsets it after its command.

```bash
# 1. Schedule (PROPOSER). Save the "salt" and operation id from the JSON output.
stellar-agent smart-account timelock schedule \
  --timelock CTLCK...WXYZ \
  --target CTGT...WXYZ \
  --function upgrade \
  --delay-ledgers 100 \
  --signer-secret-env PROPOSER_SK

# 2. After the delay, execute (EXECUTOR) with the exact saved target/function/operation-id/salt.
stellar-agent smart-account timelock execute \
  --timelock CTLCK...WXYZ \
  --target CTGT...WXYZ \
  --function upgrade \
  --operation-id abcdef01...89abcdef \
  --salt 11223344...aabbccdd \
  --signer-secret-env EXECUTOR_SK
```

To abort before the delay elapses, cancel with the operation id. This example reads the canceller seed from `CANCELLER_SK`; the operator sets it as [Pass a secret seed](https://github.com/Soneso/stellar-agent-wallet/blob/main/docs/getting-started.md#pass-a-secret-seed) shows and unsets it after the command.

```bash
stellar-agent smart-account timelock cancel \
  --timelock CTLCK...WXYZ \
  --operation-id abcdef01...89abcdef \
  --signer-secret-env CANCELLER_SK
```

## Agent-signed execute

`smart-account execute` submits one `CallContract` invocation against an external contract, authorized by a named context rule and signed by an External-Ed25519 rule signer — the CLI surface for the agent-delegation flow (see `agent-delegation.md`). Testnet only; structurally refuses `mainnet` before any RPC call or key-material access. No MCP tool equivalent exists (see `mcp.md`'s "why there is no agent-facing execute tool" — the typed-tool consent model has no meaningful preview for an arbitrary-invocation verb).

Two distinct signers: `--rule-signer-ed25519-secret-env <VAR>` (req) is the agent's own key that authorizes the call (full mlock ceremony; no funded account needed); the ordinary signer-source group (`--signer-secret-env` / `--sign-with-ledger`) is the fee-payer that pays the transaction fee and signs the envelope.

| Flag | Required | Notes |
|------|----------|-------|
| `--account <C>` | yes | Smart account whose rule authorizes the call (`auth_address`). |
| `--contract <C>` | yes | External target contract (`target_contract`); usually different from `--account`. |
| `--function <NAME>` | yes | Contract function to invoke. |
| `--arg <SCVAL_BASE64>` | no, repeatable | One standard-base64 XDR `ScVal` per argument, in order. Bounded-decoded to validate only; never re-encoded. A malformed value names the failing index. |
| `--auth-rule-id <U32>` | yes, repeatable | NO default (deviation from every other write verb) — the delegation use case always names a specific scoped rule. |
| `--rule-signer-ed25519-secret-env <VAR>` | yes | The agent's S-strkey seed env var. |
| `--expect-rule-signer <64_HEX>` | no | Fail closed before signing if the derived pubkey differs. |
| `--verifier <C>` | no | Ed25519-verifier override; else resolves from the registry (`smart-account deploy-ed25519-verifier`). |

Success envelope: `status: "submitted"`, `contract`, `function`, `arg_count`, `auth_rule_ids`, `rule_signer_pubkey_first8`, `verifier_address`, `tx_hash`. On-chain refusals render the same typed `SaError` wire codes and OZ annotations (`[OZ:SpendingLimitExceeded]`, `[OZ:UnvalidatedContext]`, etc.) every other smart-account write verb uses.

Before simulating, every `--auth-rule-id` other than `0` passes the pinned-hash drift check against the profile's audit log. A verifier or policy that differs from its pin refuses with `sa.verifier_hash_drift` / `sa.policy_hash_drift`, and a check that cannot run with `sa.pin_check_unavailable`. A rule whose record holds policy pins while the rule has no policy on chain refuses with `sa.pinned_policy_absent`. A rule holding an `External` signer while its record pins no verifier refuses with `sa.pinned_verifier_absent`. Nothing is signed or sent on a refusal.

This example also reads the agent's seed from `AGENT_SK`, set as [Pass a secret seed](https://github.com/Soneso/stellar-agent-wallet/blob/main/docs/getting-started.md#pass-a-secret-seed) shows. In the operator's terminal, run this line on its own, paste the agent's seed when prompted, and press Enter. The line reads the seed from the terminal, so the operator runs it, not the agent.

```bash
printf 'AGENT_SK seed: ' && read -rs AGENT_SK && echo && export AGENT_SK
```

```bash
stellar-agent smart-account execute \
  --account CABC...WXYZ \
  --contract CTOK...WXYZ \
  --function transfer \
  --arg AAAAEgAAAAA... --arg AAAAEgAAAAA... --arg AAAACgAAAAA... \
  --auth-rule-id 3 \
  --rule-signer-ed25519-secret-env AGENT_SK \
  --signer-secret-env WALLET_SK
unset AGENT_SK
```

## External-contract submit convention

When a smart-account authorizes a call into an external contract (a DeFi adapter, a router, a token), the auth-entry locator distinguishes the contract being invoked from the wallet credential providing the authorization:

- The invoked contract is the target.
- The wallet credential address is the auth address (defaults to the target when not overridden; pass it explicitly for entrypoints that require a different C-strkey credential address — G-strkey addresses are rejected at strkey parse).
- One or more authorizing context-rule ids bind the auth digest; a single rule id is auto-expanded to match the number of invocation contexts.

This is the same convention the higher-level value-transfer and DeFi verbs use under the hood when the source is a smart-account.
