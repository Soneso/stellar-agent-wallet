# CLI reference: smart-account

The chain and endpoints come from the resolved profile. Optional `--network` must equal the profile's chain.
Optional RPC flags override testnet endpoints; a mainnet profile refuses either RPC flag, including equal values.
Without a secondary flag, the profile's `secondary_rpc_url` applies. RPC flags refuse URLs containing credentials.

Mainnet signers must match `mcp_signer_default.account`, including both signers on `execute`. A placeholder or malformed pin refuses before signing.

The `smart-account` command group (also available under the shorter alias `sa`) governs an on-chain OpenZeppelin smart-account: its context rules, its signer sets and thresholds, the policy contracts attached to each rule, and the supporting infrastructure (verifier registry, multicall router registry, upgrade timelock). It also submits multicall bundles through the registered router.

The following commands refuse a mainnet profile with `network.mainnet_write_forbidden` before any RPC call or signer access:

- Rule writes, policy writes, and all signer verbs, including `list` and `refresh`.
- `rules verify-pins`, which loads a signer to derive its simulation source account.
- `execute`, `multicall`, and `migrate-verifier` submit mode.
- Timelock `schedule`, `cancel`, and `execute`, and all four deployment commands.

The following operations have no structural refusal:

- `smart-account register-multicall` / `smart-account unregister-multicall` accept `mainnet` as a local-registry key.
- The read-only verbs (`smart-account rules get`, `smart-account rules get-spending-limit`, `smart-account rules list` / `smart-account list-rules`, `smart-account list-verifiers`, `smart-account timelock list-pending`) allow mainnet inspection.

For the terms used here — [profile](../profiles.md), policy engine, approval spine, audit log, [context rule](../concepts.md), auth digest — see [concepts](../concepts.md). The shared flags (`--profile`, `--network`, `--rpc-url`, `--secondary-rpc-url`, `--timeout-seconds`, `--output`, and the signer-source group) are defined once on the [CLI reference index](index.md#global-conventions); this page names each flag a command takes and only describes the flags specific to that command.

Every command prints one JSON envelope on stdout and returns exit code `0` on success, `1` on any error (see [output envelope and exit codes](index.md#output-envelope-and-exit-codes)).

## Signer source

The write verbs use the shared signer-source group: exactly one of `--signer-secret-env <VAR>` (an env-var name holding the source-account S-strkey) or `--sign-with-ledger` (the two are mutually exclusive, and the command refuses if neither is supplied), with `--account-index <INDEX>` selecting the Ledger BIP-44 index (default `0`). See [signer source](index.md#signer-source). All signing in this group goes through the smart-account auth-entry digest path: the signer signs the [auth digest](../concepts.md), which binds the authorizing context-rule ids.

The examples on this page that sign with `--signer-secret-env WALLET_SK` read the source-account seed from `WALLET_SK`. Before the first of them, run this line on its own, paste the seed when prompted, and press Enter (see [Pass a secret seed](../getting-started.md#pass-a-secret-seed)):

```bash
printf 'WALLET_SK seed: ' && read -rs WALLET_SK && echo && export WALLET_SK
```

After the last of those examples, run `unset WALLET_SK` to remove the seed from the shell.

## Pre-submission checks

Every verb that signs a transaction authorized by a rule other than rule `0` checks each such rule before anything is simulated or signed: `smart-account execute`, `smart-account multicall`, the `smart-account rules` and `smart-account signers` write verbs, and `smart-account migrate-verifier` (see that verb). For each authorizing rule other than `0`, in ascending order, the wallet:

1. Holds the rule's lock. A verb holds the lock of each rule it signs under while it signs, and a concurrent verb on the same rule waits for it. A lock not acquired before the pre-submit budget (`--timeout-seconds`) ends refuses with `sa.auth_entry_construction_failed` at stage `rule_lock`.
2. Reads the rule's [signer-set baseline](#smart-account-signers--signer-set-lifecycle) from the audit log, with no RPC. A rule without one refuses with `sa.signer_set_missing_baseline`; run `signers list --rule-id N` once to record it. [`rules list`](#smart-account-rules-list) shows which rules have one. An audit-log integrity error refuses with `sa.audit_log`.
3. Runs the [pinned-hash drift check](#pinned-hash-drift-check).
4. Compares the rule's signer set, read through both RPC endpoints, with the baseline in the baseline's version; a version 1 baseline is compared through its version 1 projection. A changed set writes a `SaSignerSetDiverged` row and refuses with `sa.signer_set_diverged`. Endpoints that disagree refuse with `network.rpc_divergence`.

Each step runs for every rule before the next step starts, so when several faults coexist the refusal is the earliest step's. The steps share one deadline: an elapse during a baseline read or a comparison refuses with `sa.auth_entry_construction_failed` at stage `baseline_read` or `signer_set_compare`. Rule 0, the bootstrap rule, is exempt from the rule lock, the signer-set check and the pin check; it has no pins, and the submit path never reads a baseline for it. A verb that locks a rule itself, such as a signer verb or `migrate-verifier`, compares that rule before it submits and the submit path does not compare it again.

Nothing is sent when a check refuses. `smart-account multicall` reports the refusal as `sa.multicall_failed` at phase `policy_gate`, naming the inner code. A verb that reads an id from the transaction's return value checks the simulated return value before it signs. `signers add`, `rules add-policy` and `rules create` refuse a value of another shape with `sa.deployment_failed`, and nothing is signed or sent. The add step of `migrate-verifier` reports the same refusal as `sa.verifier_migration_failed` at phase `submit_simulate`. A verb holds a rule's lock through its signing, which can wait on a hardware signer or a passkey, and through its confirmation. A concurrent verb on the same rule then refuses at stage `rule_lock` when its own pre-submit budget ends.

### Pinned-hash drift check

`smart-account rules create` pins every verifier and policy contract a rule references. The audit log records each contract's hash in the rule's `SaContextRuleCreated` row, and for a CAP-85 external reference also its owner, its tag, and the hash the tag resolves to. Every verb that signs a transaction authorized by a rule checks that rule against its pin record before anything is simulated or signed, as step 3 of the [pre-submission checks](#pre-submission-checks). `smart-account migrate-verifier` checks the migrating rule's policies and skips its verifiers, the contracts it moves the rule away from and to (see that verb). For each authorizing rule other than `0`, the wallet fetches the rule's verifier and policy addresses from chain and compares each live contract with its pin:

- A changed hash, a repointed or different external reference, or a changed executable kind refuses with `sa.verifier_hash_drift` / `sa.policy_hash_drift` and writes a `SaVerifierHashDrift` / `SaPolicyHashDrift` audit row carrying the command's request id. A rule whose pin record holds policy pins while the rule has no policy on chain refuses with `sa.pinned_policy_absent` and writes no drift row. Repair it with `rules add-policy` authorized under rule `0`, which pins the added policy and replaces the stale pins, or reinstall the rule. A rule holding an `External` signer whose pin record pins no verifier refuses with `sa.pinned_verifier_absent` and writes no drift row, since the live verifier would sign unchecked. The record misses the pin when a verb was interrupted between its confirmation and its pin rows, when its outcome was never resolved, or when the signer was added through another client. Repair it with [`signers refresh --rule-id N`](#smart-account-signers-refresh), which pins the live verifier.
- A check that cannot run refuses with `sa.pin_check_unavailable`. Its message leads with the inner wire code: an RPC failure or divergence, an instance the wallet cannot read, or a record with more than one verifier or policy pin (`sa.multiple_pinned_hashes_unsupported`). The baseline read, which runs first, reports an audit-log integrity error as `sa.audit_log`, under the migrating rule of `migrate-verifier` too.
- A rule without a pin record, such as one installed outside the wallet, is not checked for drift. Rule 0, the bootstrap rule, is exempt from the rule lock, the signer-set check and the pin check; it has no pins, and the submit path never reads a baseline for it.

A write verb whose `--auth-rule-id` names a rule other than `0` compares its signer-set baseline and any executable pins with the chain. Where a pin is checked, the first eight bytes of the live code hash must equal the pinned value. An external reference must also match its pinned owner, tag, and resolved hash prefix. Changes to a verifier, policy, or signer outside the wallet can refuse the rule's own administration. Authorize the repair through rule `0`, or reinstall the rule.

The pin record is the newest `SaContextRuleCreated` or `SaContextRulePinsUpdated` row for the rule. `smart-account migrate-verifier`, `signers add`, `signers batch-add`, `rules add-policy` and `rules remove-policy` write a `SaContextRulePinsUpdated` row when they change the verifier or policy set of a pinned rule (see those verbs). The check therefore follows the wallet's own changes. The signer verbs, the policy verbs and `migrate-verifier` read the record and write their row under the rule's lock, so two of them on one rule never overwrite each other's pins. `smart-account signers refresh` writes one when it pins the live verifier of a record that pins none. `smart-account rules verify-pins` runs the same comparison on demand without signing, and reports a live verifier the record does not pin as verifier `drift`.

Every read of a rule's signer set decodes the whole set. The wallet cannot decode an unknown signer kind, a malformed signer, or an `External` signer with empty key data. A rule holding such a signer is refused for every operation that reads it, including this check and the signer-set baseline, with `sa.deployment_failed` and the signer's index in the reason. A signer delegated to a contract address is readable, and [`rules create --signer-delegated`](#smart-account-rules-create) installs one. Only a comparison with a version 1 signer-set baseline cannot represent it (see [`signers refresh`](#smart-account-signers-refresh)). Remove such a rule with `smart-account rules delete --rule-id N --auth-rule-id M`, where rule `M` is one the wallet can read; `--auth-rule-id` defaults to the deleted rule.

### Audit row order

The rows a confirmed verb writes, in order. A row that does not apply is skipped. A rule without a pin record gets no pin rows, and an override row exists only for an applied override flag. A confirmed transaction whose result was not the intended change writes a `SaSignerSetDiverged` row in place of its state row (see each verb). The signer verbs, the policy verbs, `signers refresh` and `migrate-verifier` write every row up to and including the pins row under the rule's lock; `migrate-verifier` holds it through each pair's last row.

| Verb | Rows |
|---|---|
| `rules create` | override rows, `SaContextRuleCreated`, `SaSignerSetBaselinedV2` (reason `confirmed_install`), `SaRawInvocation` |
| `signers add`, `signers batch-add` | one `SaSignerAddedV2` row per added signer, override rows, `SaContextRulePinsUpdated` (reason `signer_added`) |
| `signers remove`, `signers set-threshold` | `SaSignerRemovedV2` / `SaThresholdChangedV2` |
| `signers refresh` | `SaSignerSetDiverged` (a changed set accepted with `--accept-divergence`), `SaSignerSetBaselinedV2`, override rows and `SaContextRulePinsUpdated` (reason `baseline_refreshed`) when it pins the live verifier |
| `rules add-policy`, the simple-threshold policy | `SaThresholdChangedV2`, override rows, `SaContextRulePinsUpdated` (reason `policy_added`), `SaPolicyAdded`, `SaRawInvocation` |
| `rules add-policy`, any other policy | override rows, `SaContextRulePinsUpdated` (reason `policy_added`), `SaPolicyAdded`, `SaRawInvocation` |
| `rules remove-policy`, the simple-threshold policy | `SaThresholdChangedV2`, `SaContextRulePinsUpdated` (reason `policy_removed`), `SaPolicyRemoved`, `SaRawInvocation` |
| `rules remove-policy`, any other policy | `SaContextRulePinsUpdated` (reason `policy_removed`), `SaPolicyRemoved`, `SaRawInvocation` |
| `migrate-verifier`, per pair | `SaSignerRemovedV2`, `SaContextRulePinsUpdated` (reason `verifier_migrated`), `SaSignerAddedV2`, `SaVerifierMigrated` |

---

## `smart-account rules` — context-rule lifecycle

Manages the OpenZeppelin context rules on a smart-account. Each rule has a `rule_id` (a `u32`), a name (OZ cap: 20 bytes), an optional expiry ledger, a signer set (OZ cap: 15 signers), and up to 5 policy contracts.

The `--auth-rule-id` flag on the write verbs names the rule whose signers authorize the operation; where it is optional it defaults to the rule being modified (`--rule-id`). The exception is `rules set-spending-limit`, whose default is `0`: a spending-limit rule is CallContract-scoped and can never authorize its own retune (see that verb's entry).

### `smart-account rules create`

Installs a new context rule (OZ `add_context_rule`) and returns the newly minted `rule_id`. Signs and submits, then records the confirmed rule as its signer-set baseline, as **Signer-set baseline** in this section describes. Testnet only.

Flags:

- `--account <C_STRKEY>` (required): smart-account contract address.
- `--name <STRING>` (required): rule name; refused as `validation.rule_name_too_long` over 20 bytes.
- `--context <SPEC>`: the rule's context type. `default` (also the default when the flag is omitted) authorizes any invocation; `call-contract:<C_STRKEY>` scopes the rule to invocations of one target contract; `create-contract:<64_HEX_WASM_HASH>` scopes it to creating a contract with that wasm hash. A malformed spec is refused before any network call, naming the accepted grammar. See [Agent delegation](../agent-delegation.md) for the `call-contract` shape for scoping an autonomous agent to one token contract.
- `--signer-delegated <STRKEY>`: a delegated signer, given as a G-strkey for an ed25519 account or a C-strkey for a contract whose own authorization decides for the signer. Repeatable. Only an account delegate counts as the delegated fallback of `--accept-no-delegated-fallback`.
- `--signer-webauthn <CREDENTIAL_NAME>`: a passkey signer, resolved from the profile's passkey registry (see [`credentials add-passkey`](profile-and-governance.md)). Repeatable. The verifier contract address is read from the verifier registry, which is populated by `smart-account deploy-webauthn-verifier`.
- `--signer-ed25519 <HEX_PUBKEY_64>`: a first-class External-Ed25519 signer (a raw 32-byte ed25519 public key). Repeatable. The recommended shape for an autonomous agent's own key (see [Agent delegation](../agent-delegation.md)): no funded classic account is required. Encodes the same on-chain shape as [`signers add --signer-ed25519`](#smart-account-signers-add).
- `--verifier <C_STRKEY>`: Ed25519-verifier contract override for `--signer-ed25519`. Omitted, it resolves from the verifier registry (populated by `smart-account deploy-ed25519-verifier`), failing closed if none is registered.
- `--accept-no-delegated-fallback`: acknowledge an External-only rule (no delegated ed25519-G-key fallback). Required when `--signer-webauthn` or `--signer-ed25519` signers, or both, are given and no `--signer-delegated` is a G-strkey; without it the command refuses with `validation.passkey_only_rule_no_delegated_fallback` after printing a stderr warning. A contract delegate is not a fallback signer: it is not a key the operator holds. An invalid `--signer-delegated` value is refused before this check.
- `--accept-mutable-verifier`: proceed even if a referenced verifier or policy contract is mutable. It has an admin/owner key, or its executable is an owner-managed external reference (reason `owner-managed external reference`). The envelope reports `mutable_override: true`. For an external reference the pin records the owner, the tag, and the first eight bytes of the resolved code hash. The envelope lists them in `pinned_verifier_executable_refs` / `pinned_policy_executable_refs`. When the resolved hash prefix, reference identity, or executable kind differs from the pin, the [pinned-hash drift check](#pinned-hash-drift-check) refuses signing under the rule with `sa.verifier_hash_drift` / `sa.policy_hash_drift`. It refuses in `execute`, `multicall`, the rule and signer write verbs, and `migrate-verifier` for the rule's policies. A rule whose record holds policy pins while the rule has no policy on chain refuses with `sa.pinned_policy_absent`. A rule holding an `External` signer while its record pins no verifier refuses with `sa.pinned_verifier_absent`, and a check that cannot run refuses with `sa.pin_check_unavailable`. `--accept-unknown-verifier` is also required when the resolved hash is not in the allowlist. The wallet refuses an external reference with no live tag entry, an undecodable instance, or an instance returned under an unrequested key. It also refuses a non-Wasm executable or an executable that changes during install. These cases return `sa.contract_instance_unsupported`. The reason is `external reference with no live tag entry`, `undecodable instance`, `non-Wasm executable`, or `executable changed during install`. Neither override flag admits them, because the wallet cannot pin their code.
- `--accept-unknown-verifier`: proceed even if a referenced verifier or policy WASM hash (for an external reference, the hash its tag resolves to) is not in the allowlist. The envelope reports `unknown_override: true`.
- `--auth-rule-id <U32>`: authorizing rule id(s). Repeatable. Default `[0]` (the bootstrap rule installed at deploy time).
- `--valid-until <LEDGER>`: expiry ledger sequence, or `none` for a permanent rule. Default `none`.
- Shared: `--profile`, signer-source group, `--network`, `--rpc-url`, `--secondary-rpc-url`, `--timeout-seconds`, `--output`.

At least one `--signer-delegated`, `--signer-webauthn`, or `--signer-ed25519` is required.

Before submission each referenced verifier and policy contract is identified and probed. A refusal from that step (`sa.verifier_wasm_not_in_allowlist`, `sa.policy_wasm_not_in_allowlist`, `sa.verifier_mutable`, `sa.policy_mutable`, `sa.contract_instance_unsupported` or `network.rpc_divergence`) carries no `rule_id` and its message names no rule, because the rule has no on-chain id yet. When `--accept-mutable-verifier` or `--accept-unknown-verifier` admits a contract, the audit log records `SaMutableContractOverride` or `SaUnknownContractOverride` after the install confirms, carrying the new rule's id, before the `SaContextRuleCreated` row. A refused install writes no override row.

**Signer-set baseline.** After the install confirms, both RPC endpoints (`--rpc-url` and `--secondary-rpc-url`) read the new rule at or past the confirmation ledger. Its signers, and its simple-threshold policy with its threshold when the rule has one, must be the ones the command authorized. The wallet records them as a `SaSignerSetBaselinedV2` row with reason `confirmed_install` before the `sa.ok` row, so the [signer verbs](#smart-account-signers--signer-set-lifecycle) work on the rule at once. The rule stays on chain without a baseline, and the command exits non-zero, in these cases:

- `sa.install_state_mismatch`: the observed rule is not the authorized definition, or the transaction's return value carried no rule id. The message names the transaction. Inspect the rule with `rules get --rule-id N`, then either delete it with `rules delete --rule-id N --auth-rule-id 0` or accept it with `signers refresh --rule-id N`, which also pins a live verifier the rule's pin record does not pin. The rule cannot authorize its own removal without a baseline. When the rule id could not be read, find the rule with `rules list` first. No override row and no `SaContextRuleCreated` row is written then, since neither has a rule id to carry, so an applied override flag is not recorded. A simulated return value without a rule id is refused before the install is signed, with `sa.deployment_failed` (see [pre-submission checks](#pre-submission-checks)).
- `sa.baseline_write_failed` with the transaction hash: the rule could not be observed within `--timeout-seconds` (stage `observe`) or its baseline row was not written (stage `write`). `signers refresh --rule-id N --accept-divergence` records the chain state.

```bash
stellar-agent smart-account rules create \
  --account CABC...WXYZ \
  --name agent-ops \
  --signer-delegated GABC...WXYZ \
  --signer-secret-env WALLET_SK
```

### `smart-account rules get`

`--profile <NAME>` selects the profile, followed by `STELLAR_AGENT_PROFILE`, then `default`. An explicitly named missing profile refuses.

Reads a single rule by id (OZ `get_context_rule`). Read-only; no signing, no submission. `mainnet` is accepted. The envelope reports `present: true` or `present: false`.

Flags:

- `--account <C_STRKEY>` (required) — smart-account contract address.
- `--rule-id <U32>` (required) — rule index to fetch.
- `--source-account <G_STRKEY>` (required) — any funded account on the target network; used only to assemble the simulation envelope. It is not debited and not signed for.
- Shared: `--profile`, `--network`, `--rpc-url`, `--timeout-seconds`, `--output`.

```bash
stellar-agent smart-account rules get \
  --account CABC...WXYZ \
  --rule-id 1 \
  --source-account GDEF...WXYZ
```

### `smart-account rules set-name`

Renames a rule (OZ `update_context_rule_name`). Signs and submits. Testnet only.

Flags:

- `--account <C_STRKEY>` (required).
- `--rule-id <U32>` (required) — rule to rename.
- `--name <STRING>` (required) — new name; same 20-byte cap as `create`.
- `--auth-rule-id <U32>` (optional): authorizing rule id; defaults to `--rule-id`. The authorizing rule passes the [pre-submission checks](#pre-submission-checks), its signer-set baseline included.
- Shared: `--profile`, signer-source group, `--network`, `--rpc-url`, `--secondary-rpc-url`, `--timeout-seconds`, `--output`.

```bash
stellar-agent smart-account rules set-name \
  --account CABC...WXYZ \
  --rule-id 1 \
  --name treasury \
  --signer-secret-env WALLET_SK
```

### `smart-account rules set-valid-until`

Changes a rule's expiry (OZ `update_context_rule_valid_until`). Signs and submits. Testnet only.

Flags:

- `--account <C_STRKEY>` (required).
- `--rule-id <U32>` (required) — rule to update.
- `--valid-until <LEDGER|none>` (required) — a ledger sequence sets explicit expiry; `none` clears it (permanent rule).
- `--auth-rule-id <U32>` (optional): defaults to `--rule-id`. The authorizing rule passes the [pre-submission checks](#pre-submission-checks), its signer-set baseline included.
- Shared: `--profile`, signer-source group, `--network`, `--rpc-url`, `--secondary-rpc-url`, `--timeout-seconds`, `--output`.

```bash
stellar-agent smart-account rules set-valid-until \
  --account CABC...WXYZ \
  --rule-id 1 \
  --valid-until none \
  --signer-secret-env WALLET_SK
```

### `smart-account rules delete`

Removes a rule (OZ `remove_context_rule`). Signs and submits. Testnet only.

Flags:

- `--account <C_STRKEY>` (required).
- `--rule-id <U32>` (required) — rule to delete.
- `--auth-rule-id <U32>` (optional): defaults to `--rule-id`. The authorizing rule passes the [pre-submission checks](#pre-submission-checks), its signer-set baseline included.
- Shared: `--profile`, signer-source group, `--network`, `--rpc-url`, `--secondary-rpc-url`, `--timeout-seconds`, `--output`.

```bash
stellar-agent smart-account rules delete \
  --account CABC...WXYZ \
  --rule-id 1 \
  --signer-secret-env WALLET_SK
```

### `smart-account rules verify-pins`

Verifies a rule's pinned verifier and policy WASM hashes against the live on-chain contracts (drift detection). Read-only; no signing, no submission. A mainnet profile is refused with `network.mainnet_write_forbidden` before the signer loads. Exit code is `1` when either pin status is `drift`, otherwise `0`; the JSON envelope is well-formed in both cases.

Each `*_pin_status` is one of `match`, `drift`, `unavailable`, `no_pin`, or `no_contracts`. `drift` also covers a pinned policy with no policy on chain: the pin record holds policy pins while the rule has none, and `policy_pin_status` is `drift` with an empty observed list. It covers a live verifier the record does not pin too: the rule holds an `External` signer while the record pins no verifier, and `verifier_pin_status` is `drift` with an empty observed list; `signers refresh` repairs it. The signer-source flags are used only to derive a source account for the simulation; no transaction is signed.

A rule with one drifted and one unavailable pin reports both statuses, carries the unavailable probe's code in `unavailable_reason`, and exits 1.
A failed executable read reports `sa.deployment_failed` in `unavailable_reason`.

Flags:

- `--account <C_STRKEY>` (required).
- `--rule-id <U32>` (required) — rule whose pins to verify.
- `--rpc-url <URL>`: optional testnet override; absent uses the profile endpoint. Mainnet profiles refuse the flag.
- Shared: `--profile`, signer-source group, `--network`, `--secondary-rpc-url`, `--timeout-seconds`, `--output`.

Envelope: `{ smart_account, rule_id, verifier_pin_status, policy_pin_status, pinned_verifier_first8, pinned_policy_first8, observed_verifier_first8, observed_policy_first8, observed_verifier_executable?, observed_policy_executable?, pinned_verifier_executable_refs?, pinned_policy_executable_refs?, mutable_override, unknown_override, unavailable_reason?, chain_id }`. `observed_*_executable` is aligned with `observed_*_first8`: an entry is the bounded summary of an external-reference executable (owner, tag and resolved hash) or `no code`, and `null` for a plain WASM executable. `pinned_*_executable_refs` is aligned with `pinned_*_first8`: an entry is the pinned external reference (`owner_redacted`, `tag`, `ref_key_hex`, `resolved_hash_first8`) and `null` for a position pinned by its WASM hash. The four fields are omitted when empty.

```bash
stellar-agent smart-account rules verify-pins \
  --account CABC...WXYZ \
  --rule-id 1 \
  --signer-secret-env WALLET_SK
```

### `smart-account rules add-policy`

Adds a policy contract to a rule (OZ `add_policy`). The per-rule policy cap (5) is checked before simulation via a `get_context_rule` pre-fetch. Signs and submits. Testnet only. Returns the assigned `policy_id`.

`--kind <raw|spending-limit|simple-threshold|weighted-threshold>` (default `raw`) selects the install-parameter mode:

- `--kind raw` (default): the caller supplies `--policy-address` and a hand-encoded `--install-param`. Works with any policy contract.
- `--kind spending-limit`: the wallet resolves the deployed OZ spending-limit policy from the [`VerifierRegistry`](../agent-delegation.md) (or an explicit `--policy` override) and builds the typed `SpendingLimitAccountParams` install parameter internally. Refused client-side before any network call when `--limit <= 0` or `--period == 0` (mirroring the on-chain `InvalidLimitOrPeriod` constraint), and when the target rule's context type is not `call-contract` (mirroring `OnlyCallContractAllowed`): see [Agent delegation](../agent-delegation.md).
- `--kind simple-threshold`: the wallet resolves the deployed OZ simple threshold-policy (signer-count based; use `smart-account deploy-policy --kind simple-threshold` first) and builds the `SimpleThresholdAccountParams { threshold }` install parameter from `--threshold`. Refused client-side when `--threshold == 0`.
- `--kind weighted-threshold`: the wallet resolves the deployed OZ weighted-threshold policy (`smart-account deploy-policy --kind weighted-threshold`) and builds the `WeightedThresholdAccountParams { signer_weights, threshold }` install parameter from one or more `--weighted-signer-delegated` / `--weighted-signer-webauthn` flags plus `--threshold`. Refused client-side when the signer-weight set is empty, when `--threshold == 0`, or when `--threshold` exceeds the sum of the supplied weights.

Flags:

- `--account <C_STRKEY>` (required).
- `--rule-id <U32>` (required): rule to add the policy to.
- `--policy-address <C_STRKEY>`: policy contract address. Required with `--kind raw`; rejected with the other kinds.
- `--install-param <SCVAL_BASE64>`: a standard-base64 XDR `ScVal` install parameter (not base64url), passed to `add_policy` without further validation (raw passthrough). Required with `--kind raw`; rejected with the other kinds.
- `--limit <STROOPS>`: spending limit in stroops (`--kind spending-limit`, required). The `i128` amount the rolling window admits before the policy panics `SpendingLimitExceeded`.
- `--period <LEDGERS>`: rolling-window length in ledgers (`--kind spending-limit`, required).
- `--policy <C_STRKEY>`: spending-limit policy contract override (`--kind spending-limit`). When omitted, resolves from the registry populated by `smart-account deploy-spending-limit-policy`; fails closed with a deploy-first hint if absent.
- `--threshold <U32>`: signer threshold (`--kind simple-threshold` / `--kind weighted-threshold`, required with both). For `simple-threshold` this is the minimum signer count; for `weighted-threshold` this is the minimum total weight.
- `--weighted-signer-delegated <G_STRKEY=WEIGHT>`: one Delegated (ed25519) signer-weight pair (`--kind weighted-threshold`). Repeatable.
- `--weighted-signer-webauthn <CREDENTIAL_NAME=WEIGHT>`: one External WebAuthn signer-weight pair, resolved by credential name from the passkeys registry (`--kind weighted-threshold`). Repeatable.
- `--auth-rule-id <U32>` (optional): authorizing rule id(s). Repeatable. Defaults to `--rule-id`.
- `--accept-mutable-verifier`: pin a policy that is mutable (admin/owner key, or an owner-managed external reference). Applies only as described under "Pin record" below; the audit log then records `SaMutableContractOverride`, carrying the rule id, after the add confirms; a refused add writes none.
- `--accept-unknown-verifier`: pin a policy whose hash is outside the policy allowlist (the simple-threshold, weighted-threshold and spending-limit Wasms the wallet vendors). Same scope; the audit log then records `SaUnknownContractOverride`, carrying the rule id, after the add confirms.
- Shared: `--profile`, signer-source group, `--network`, `--rpc-url`, `--secondary-rpc-url`, `--timeout-seconds`, `--output`.

The add holds the lock of `--rule-id` and of every `--auth-rule-id` other than `0` from before its first read until its pin rows are written. A concurrent verb on the rule, such as `signers add`, therefore runs before or after the whole add. Under the lock, whatever the policy, the wallet compares the chain with the rule's version 2 [signer-set state](#smart-account-signers--signer-set-lifecycle). A rule without one refuses with `sa.signer_set_missing_baseline` (run `signers list --rule-id N`), a version 1 state with `sa.signer_set_baseline_legacy` (run `signers refresh --rule-id N`) and a changed chain with `sa.signer_set_diverged`. The wallet then reads the policy's executable through both RPC endpoints, to tell whether it is the simple-threshold policy, and plans the pin record. The add signs under `--auth-rule-id`, so those rules pass the [pre-submission checks](#pre-submission-checks); the target's signer set is compared once, under its lock. The wallet sends nothing on a refusal.

**Simple-threshold policy.** When the policy's executable is the simple-threshold policy (`--kind simple-threshold`, or a `--kind raw` address that runs it), the add records the threshold in the rule's signer-set state:

- The install parameter must be the `{ threshold: u32 }` map with a non-zero threshold; the add refuses anything else with `sa.simple_threshold_install_refused` before signing.
- A rule that already has a simple-threshold policy refuses with `sa.threshold_policy_identification_failed`. The wallet sends nothing.
- After the add confirms, both endpoints are read at or past the confirmation ledger. The signers must be unchanged and the threshold the parameter's on the added policy; a `SaThresholdChangedV2` row records it. A different result writes a `SaSignerSetDiverged` row and refuses with `sa.signer_set_diverged` naming the transaction hash. A result that cannot be observed or recorded returns `sa.baseline_write_failed`. The wallet writes the pin and `SaPolicyAdded` rows in either case, since the policy is on chain.

The add attaches any other policy without a signer-set state row. A simulated return value that carries no policy id, for any policy, refuses the add before it is signed with `sa.deployment_failed`; nothing is sent, and only the `SaRawInvocation` row is written. A confirmed add whose return value still carries no policy id returns `sa.baseline_write_failed` at stage `observe` with the transaction hash, writes its pin rows and no `SaPolicyAdded` row; `rules get --rule-id N` shows the attached policy's id. [Audit row order](#audit-row-order) lists the rows of each outcome.

**Pin record.** When the rule has a pin record and the policy is not already attached to it, the add keeps the record in step with the rule's policies. The record is read, and the rule's policies observed, under the rule's lock. Before submission the policy is identified and probed as `rules create` probes one. A hash outside the policy allowlist fails with `sa.policy_wasm_not_in_allowlist` and a mutable contract with `sa.policy_mutable` unless the matching flag above is set. An unpinnable instance fails with `sa.contract_instance_unsupported` regardless. After the add confirms, a `SaContextRulePinsUpdated` row (reason `policy_added`) records the policy pins with the new pin appended, so later signing under the rule checks the policy too. When the rule has no policy on chain, the row replaces the policy pins with the added policy's pin. A record with two policy pins is refused by every checked signing verb with `sa.pin_check_unavailable` (inner code `sa.multiple_pinned_hashes_unsupported`), the same outcome as a rule installed with two policies. A rule without a pin record stays unpinned: nothing is probed and no row is written.

```bash
stellar-agent smart-account rules add-policy \
  --account CABC...WXYZ \
  --rule-id 1 \
  --policy-address CPOL...WXYZ \
  --install-param AAAAAQ== \
  --signer-secret-env WALLET_SK
```

```bash
stellar-agent smart-account rules add-policy \
  --account CABC...WXYZ \
  --rule-id 1 \
  --kind spending-limit \
  --limit 50000000 \
  --period 17280 \
  --signer-secret-env WALLET_SK
```

```bash
stellar-agent smart-account rules add-policy \
  --account CABC...WXYZ \
  --rule-id 1 \
  --kind weighted-threshold \
  --weighted-signer-delegated GOPER...WXYZ=2 \
  --weighted-signer-webauthn my-passkey=1 \
  --threshold 2 \
  --signer-secret-env WALLET_SK
```

### `smart-account rules remove-policy`

Removes a policy from a rule by its on-chain `policy_id` (OZ `remove_policy`). Signs and submits. Testnet only.

Flags:

- `--account <C_STRKEY>` (required).
- `--rule-id <U32>` (required): rule to remove the policy from.
- `--policy-id <U32>` (required): on-chain policy id to remove.
- `--auth-rule-id <U32>` (optional): authorizing rule id(s). Repeatable. Defaults to `--rule-id`.
- Shared: `--profile`, signer-source group, `--network`, `--rpc-url`, `--secondary-rpc-url`, `--timeout-seconds`, `--output`.

The removal holds the lock of `--rule-id` and of every `--auth-rule-id` other than `0` from before its first read until its pins row is written. A concurrent verb on the rule, such as `signers add`, therefore runs before or after the whole removal, and neither loses the other's pin. Under the lock, whatever the policy, the wallet compares the chain with the rule's version 2 signer-set state, with the refusals of [`rules add-policy`](#smart-account-rules-add-policy). A rule without a signer-set state refuses with `sa.signer_set_missing_baseline` before any RPC. A rule with a state that is not on chain refuses from the comparison's rule read. A `--policy-id` the rule does not hold refuses with `sa.deployment_failed` after the comparison. The comparison reads every attached policy's executable through both RPC endpoints, and the wallet reads the removed policy's again to tell whether it is the simple-threshold policy. A policy whose executable cannot be read refuses with `sa.deployment_failed` when the read fails. An undecodable instance or an external reference with no live tag entry gives `sa.contract_instance_unsupported`, and endpoints that disagree give `network.rpc_divergence`. The removal signs under `--auth-rule-id`, so those rules pass the [pre-submission checks](#pre-submission-checks). The wallet sends nothing on a refusal. Remove a rule whose policy stays unreadable with `rules delete --rule-id N --auth-rule-id 0`.

**Simple-threshold policy.** When the removed policy is the simple-threshold policy, the removal records the cleared threshold. Its observed simple-threshold policy must be the removed one; otherwise the removal refuses with `sa.threshold_policy_identification_failed`. After the removal confirms, the signers must be unchanged and the threshold gone; a `SaThresholdChangedV2` row records it. A different result refuses with `sa.signer_set_diverged` naming the transaction hash, and the pin and `SaPolicyRemoved` rows are still written. [Audit row order](#audit-row-order) lists the rows of each outcome.

The wallet cannot observe a rule with two simple-threshold policies, so the signer verbs refuse it with `sa.threshold_policy_identification_failed`. Removing one of the two repairs it when the rule has a version 2 signer-set state, recorded before the rule gained its second policy. Such a rule with no state refuses with `sa.signer_set_missing_baseline`; remove it with `rules delete --rule-id N --auth-rule-id 0`. The removal requires the rule's signers to equal its state's signers before submission, else it writes a `SaSignerSetDiverged` row and refuses with `sa.signer_set_diverged`. After confirmation it records the remaining policy's threshold, with no previous threshold. Removing a policy other than the two simple-threshold policies from such a rule refuses with `sa.threshold_policy_identification_failed`, and so does a rule with three or more simple-threshold policies.

**Pin record.** When the rule has a pin record, the wallet reads it and observes the policy's hash under the rule's lock, before submission. After the removal confirms, a `SaContextRulePinsUpdated` row (reason `policy_removed`) records the policy pins without the pin equal to that hash. When the policy is the rule's only policy and the record holds a single policy pin, that pin is dropped even when the policy differs from its pin. The rule then has no policy and no policy pin, and a later `rules add-policy` pins its policy afresh. Otherwise, when no pin equals the hash, the wallet writes no row. Removing the last policy under a record with two or more policy pins leaves the rule refused with `sa.pinned_policy_absent`. A `rules add-policy` authorized under rule `0` that re-pins a policy, or a reinstall of the rule, clears the refusal.

```bash
stellar-agent smart-account rules remove-policy \
  --account CABC...WXYZ \
  --rule-id 1 \
  --policy-id 0 \
  --signer-secret-env WALLET_SK
```

### `smart-account rules list`

Enumerates the active context rules on a smart-account through an on-chain scan. Read-only; no signing. `mainnet` is accepted. This is the canonical name for the enumeration; it produces the same JSON envelope as `smart-account list-rules` and takes the same flags (see [`smart-account list-rules`](#smart-account-list-rules)). Each rule's `baseline` reports its signer-set baseline in the profile's audit log; a rule reporting `none` needs one `signers list --rule-id N` before any signature under it.

```bash
stellar-agent smart-account rules list --account CABC...WXYZ
```

### `smart-account rules get-spending-limit`

`--profile <NAME>` selects the profile, followed by `STELLAR_AGENT_PROFILE`, then `default`. An explicitly named missing profile refuses.

Reads an installed spending-limit policy's budget state: identifies the policy attached to `--rule-id` via wasm-hash allowlist lookup, reads its on-chain `get_spending_limit_data`, and computes the rolling-window budget snapshot. Read-only; no signing; no submission; no audit-log emission. `mainnet` is accepted.

The returned `in_window_spent` and `remaining_budget` are exact only as of `as_of_ledger` — a point-in-time estimate, not a guarantee for a future submission. Forward ledger movement past that point only grows headroom (older spend entries fall out of the rolling window), but an intervening spend shrinks it; a later `set-spending-limit` or agent transfer can still cause `SpendingLimitExceeded`.

Trust boundary: this read consults a single RPC endpoint (no two-RPC cross-check) — an advisory view, not a signing input. The write verbs keep the full two-RPC consultation.

Flags:

- `--account <C_STRKEY>` (required).
- `--rule-id <U32>` (required) — rule whose spending-limit policy to read.
- `--source-account <G_STRKEY>` (required) — source account for the simulation envelope. Any funded account on the target network works (read-only path; no signing).
- Shared: `--profile`, `--network`, `--rpc-url`, `--timeout-seconds`, `--output`.

Envelope: `{ smart_account, rule_id, policy_address, spending_limit, period_ledgers, in_window_spent, remaining_budget, as_of_ledger, window_cutoff_ledger, history_entries, cached_total_spent }`. `spending_limit`, `in_window_spent`, `remaining_budget`, and `cached_total_spent` are decimal strings (i128, stroops), not JSON numbers — a raw JSON number above `2^53` cannot be represented exactly by an `f64`-backed parser. `cached_total_spent` is the on-chain cached total verbatim, for transparency — it is NOT used to compute `in_window_spent` (the on-chain cache is not evicted on read, so it can include entries already outside the rolling window).

```bash
stellar-agent smart-account rules get-spending-limit \
  --account CABC...WXYZ \
  --rule-id 1 \
  --source-account GABC...WXYZ
```

### `smart-account rules set-spending-limit`

Retunes an installed spending-limit policy's limit (OZ `set_spending_limit`) without resetting the rolling spend history. Signs and submits. Testnet only.

HONESTY CONSTRAINT: `set_spending_limit` mutates ONLY the limit; the period is immutable once installed. Retuning the period requires `remove-policy` followed by `add-policy --kind spending-limit`, which DOES reset the spend history (the OZ contract's `install` initializes empty history) — there is no way to change the period without that reset.

Refused client-side before any network call when `--limit <= 0` (mirroring the on-chain `InvalidLimitOrPeriod` constraint). Pre-reads the current spending-limit data before submitting, both to report `old_limit` in the audit row and to fail closed early if no spending-limit policy is installed on the rule.

Flags:

- `--account <C_STRKEY>` (required).
- `--rule-id <U32>` (required) — rule whose spending-limit policy to retune. This rule keys the policy's storage; it does NOT authorize the call.
- `--auth-rule-id <U32>`: rule that authorizes the retune. Default `0` (the bootstrap rule), not `--rule-id`. The retune executes on the smart account itself. A CallContract-scoped target rule refuses that context on chain (`UnvalidatedContext`). Supply another admin-capable rule id when the bootstrap rule has been replaced. An authorizing rule other than `0` passes the [pre-submission checks](#pre-submission-checks).
- `--limit <STROOPS>` (required) — new spending limit, in stroops. Must be positive.
- Signer-source group (see [Signer source](#signer-source)); the signer must satisfy the `--auth-rule-id` rule.
- Shared: `--profile`, `--network`, `--rpc-url`, `--secondary-rpc-url`, `--timeout-seconds`, `--output`.

```bash
stellar-agent smart-account rules set-spending-limit \
  --account CABC...WXYZ \
  --rule-id 1 \
  --limit 80000000 \
  --signer-secret-env WALLET_SK
```

---

## `smart-account signers` — signer-set lifecycle

Manages the signer set and threshold of a context rule. All verbs take `--account <C_STRKEY>` and `--rule-id <U32>` (both required), the signer-source group, `--profile`, `--network`, `--rpc-url`, `--secondary-rpc-url`, and `--timeout-seconds`. None of these verbs accept `--output` (passing it is rejected). All structurally refuse `mainnet`, including `list` and `refresh` (see the intro).

`list` and `refresh` also require a signer source: the manager needs a source account to assemble the read envelope.

Every verb waits for the rule's lock at most `--timeout-seconds`, then refuses with `sa.auth_entry_construction_failed` at stage `rule_lock`; another verb on the same rule holds the lock while it signs and records.

**Signer-set baseline.** The audit log keeps each rule's signer-set state: a baseline row, then one state row per signer change the wallet makes. A version 2 state records every signer's full identity, an `External` signer by the SHA-256 and the length of its whole key data. It also records the rule's simple-threshold policy and threshold, or no threshold when the rule has no simple-threshold policy. A version 1 state keeps the first 16 bytes of an `External` signer's key data. Both RPC endpoints (`--rpc-url` and `--secondary-rpc-url`) read the rule, the executable of each attached policy and the threshold, and must agree; otherwise the verb refuses with `network.rpc_divergence`.

- Every signature under a rule other than `0` compares the chain with the rule's state before signing, through the [pre-submission checks](#pre-submission-checks). This covers the signer verbs, `execute`, `multicall`, authorizing rules of `rules` write verbs, and the passkey path. A rule without a state refuses with `sa.signer_set_missing_baseline`; run `signers list --rule-id N` to record one. `signers add`, `remove`, `set-threshold`, and `batch-add` require version 2 state. So do `rules add-policy` and `rules remove-policy` for any policy, and a `migrate-verifier` removal. Version 1 refuses these operations before any RPC with `sa.signer_set_baseline_legacy`; run `signers refresh --rule-id N` once. Other signatures compare version 1 state through its version 1 projection. A changed chain writes `SaSignerSetDiverged` and refuses with `sa.signer_set_diverged`; nothing is sent.
- After the transaction confirms, both endpoints are read again at or past the confirmation ledger, and the result must be exactly the intended change. It is recorded as a `SaSignerAddedV2`, `SaSignerRemovedV2` or `SaThresholdChangedV2` row. A different result writes a `SaSignerSetDiverged` row and refuses with `sa.signer_set_diverged` naming the transaction hash.
- When the confirmed result cannot be observed within `--timeout-seconds` (stage `observe`) or its row cannot be written (stage `write`), the verb returns `sa.baseline_write_failed` with the transaction hash. The transaction stands; `signers refresh --rule-id N --accept-divergence` records the chain state. The same holds for the confirmed removal and add of a [`migrate-verifier`](#smart-account-migrate-verifier) pair. On a pinned rule, a confirmed `add` or `batch-add` writes its pin rows once. They follow the state row when the change is recorded, and precede the refusal when the result is not observed or not the intended change. The pin record then holds every verifier the transaction added. When the state row is not written, the pin rows are attempted and are usually refused too. A pin row the audit log refuses is logged as a warning, and the rule keeps its previous pin record. A record left without the added verifier's pin refuses the next signature under the rule with `sa.pinned_verifier_absent`; the same `signers refresh` pins the live verifier.

**A log from an earlier release.** A rule created under an earlier release has no state row. The exception is a rule that `signers list` or `signers refresh` recorded while it held a simple-threshold policy; that row is version 1. `rules list` reports `none` or `v1` for these rules. A non-zero rule reporting `none` needs one `signers list --rule-id N` before any signature it authorizes. This includes `execute`, `multicall`, `rules set-name`, `rules set-valid-until`, and `rules delete`. A rule reporting `v1` signs through the version 1 projection. Run `signers refresh --rule-id N` once before `signers add`, `remove`, `set-threshold`, or `batch-add`. Also refresh before `rules add-policy` or `rules remove-policy` for any policy, and before a `migrate-verifier` removal. `set-weighted-threshold`, `set-signer-weight`, and `set-spending-limit` compare version 1 state through the projection. A version 1 row cannot compare a rule that lost its simple-threshold policy or gained a contract delegate, so signing refuses. `signers refresh --rule-id N --accept-divergence` records that rule's current state.

### `smart-account signers list`

Reads the rule's signer set through both RPC endpoints and compares it with the rule's audit-log state. When the `(rule_id, account)` pair has no state, it writes a `SaSignerSetBaselinedV2` audit row to anchor future divergence detection; otherwise it writes nothing. A rule without a simple-threshold policy is baselined with no threshold. Submits no on-chain transaction, but is state-changing on the audit log. Testnet only. A rule holding a signer the wallet cannot decode is refused with `sa.deployment_failed` naming the signer's index, and no baseline is written. Delete such a rule with `smart-account rules delete --rule-id N` authorized by a rule the wallet can read (see [pinned-hash drift check](#pinned-hash-drift-check)).

The envelope reports `signer_count`, `threshold` (`null` when the rule has no simple-threshold policy), `snapshot_version` (`2`), the `signer_ids` with parallel `signer_kinds` and `signer_summaries` lists, and `baseline`. A `signer_kinds` entry is `delegated_ed25519`, `external` (a passkey signer included) or `delegated_contract`; a `signer_summaries` entry renders the signer's identity as first-8 hex projections. `baseline` is `none` when this call wrote the first baseline, otherwise `matched`, `diverged` or `not_comparable`. `not_comparable` reports a version 1 state the wallet cannot compare the chain with, because the rule holds a signer delegated to a contract address or has no simple-threshold policy.

```bash
stellar-agent smart-account signers list \
  --account CABC...WXYZ \
  --rule-id 0 \
  --signer-secret-env WALLET_SK
```

### `smart-account signers refresh`

Compares the chain with the rule's audit-log state and writes a fresh `SaSignerSetBaselinedV2` audit row. Use it to re-anchor after an intentional out-of-band signer change, and to repair a rule refused with `sa.pinned_verifier_absent`. Use it once to upgrade a version 1 state, which the wallet compares with the version 1 form of the chain's signer set. State-changing on the audit log only. Testnet only. Same flags as `list`, plus:

- `--accept-divergence`: record the chain state even when it differs from the rule's state, or when a version 1 state cannot be compared with it. Without the flag, a differing set writes a `SaSignerSetDiverged` row and refuses with `sa.signer_set_diverged`, and an incomparable version 1 state refuses the same way without writing a row. With the flag, a differing set writes the `SaSignerSetDiverged` row and then the baseline, and the command prints one warning line on stderr.
- `--accept-mutable-verifier`: pin a live verifier that is mutable (admin/owner key, or an owner-managed external reference). Applies only as **Verifier pin** describes; the audit log then records `SaMutableContractOverride`, carrying the rule id.
- `--accept-unknown-verifier`: pin a live verifier whose hash is outside the verifier allowlist. Same scope; the audit log then records `SaUnknownContractOverride`, carrying the rule id.

**Verifier pin.** A rule whose pin record pins no verifier while the rule holds `External` signers is refused by every signature under it with `sa.pinned_verifier_absent`. The refresh repairs it once its comparison accepts the chain, with or without `--accept-divergence`. Before the baseline is written, each distinct live verifier is identified and probed as `rules create` probes one. A mutable verifier fails with `sa.verifier_mutable` and a hash outside the allowlist with `sa.verifier_wasm_not_in_allowlist` unless the matching flag is set. An unpinnable instance fails with `sa.contract_instance_unsupported` regardless. A refusal writes no baseline and no pin row. After the baseline, the override rows and a `SaContextRulePinsUpdated` row (reason `baseline_refreshed`) add the verifier's pin, the policy pins unchanged, and the command prints one warning line on stderr. Two verifier addresses whose pins are equal, in hash and executable reference, share one pin. Live verifiers whose pins differ refuse with `sa.multiple_pinned_hashes_unsupported` before the baseline or any pin row is written, since a rule is pinned to one verifier. Recover by deleting the rule with `rules delete --rule-id N --auth-rule-id 0`, or by reinstalling it. A record that already pins a verifier is left as it is while the rule holds `External` signers, whatever the live verifier runs, and a rule without a pin record gets none. A rule with no `External` signer whose record pins one verifier loses that pin, since such a pin protects nothing. After the baseline, a `SaContextRulePinsUpdated` row (reason `baseline_refreshed`) records the record without a verifier pin, the policy pins unchanged.

The envelope reports `signer_count`, `threshold` (`null` without a simple-threshold policy), `snapshot_version`, `previous_baseline` (`none`, `matched`, `diverged` or `not_comparable`) and `verifier_pinned` (`true` when the refresh pinned the live verifier). A rule holding a signer the wallet cannot decode cannot be re-anchored: `refresh` refuses it like `list`, with the signer's index in the reason.

```bash
stellar-agent smart-account signers refresh \
  --account CABC...WXYZ \
  --rule-id 0 \
  --signer-secret-env WALLET_SK
```

### `smart-account signers add`

Adds one signer to a rule (OZ `add_signer`). Signs and submits. Testnet only. The per-rule signer cap (15) is checked before submission via a `get_rule` pre-fetch. Returns the `new_signer_id`.

Exactly one of the following signer-source forms is required (mutually exclusive group):

- `--signer-delegated <G_STRKEY>` (alias `--new-signer`): a delegated ed25519 signer.
- `--signer-ed25519 <HEX_PUBKEY_64>`: a first-class external Ed25519 signer: the raw 32-byte public key, hex-encoded. The recommended signer shape for an autonomous agent's own key: see [Agent delegation](../agent-delegation.md). Optional `--verifier <C_STRKEY>` overrides the verifier contract; when omitted it resolves from the verifier registry's registered Ed25519 verifier for the target network (deploy one via `smart-account deploy-ed25519-verifier`), failing closed if none is registered.
- `--signer-external <C_STRKEY>`: a custom external-verifier signer with caller-supplied key data. Requires `--signer-key-data <HEX>`. `--signer-ed25519` is the typed equivalent for the Ed25519 verifier specifically and produces the identical on-chain signer entry.
- `--signer-webauthn <CREDENTIAL_NAME>`: a passkey signer resolved from the profile's passkey registry; the verifier address is read from the verifier registry.

Plus:

- `--signer-key-data <HEX>`: raw hex key-data for an external signer; required with, and only valid with, `--signer-external`.
- `--accept-mutable-verifier`: pin a new verifier that is mutable (admin/owner key, or an owner-managed external reference). Applies only as described under "Pin record" below; the audit log then records `SaMutableContractOverride`, carrying the rule id, after the add confirms; a refused add writes none.
- `--accept-unknown-verifier`: pin a new verifier whose hash is outside the verifier allowlist. Same scope; the audit log then records `SaUnknownContractOverride`, carrying the rule id, after the add confirms.
- Shared: `--profile`, signer-source group, `--network`, `--rpc-url`, `--secondary-rpc-url`, `--timeout-seconds`.

The add first compares the target rule with its version 2 state under its lock. It then passes the [pinned-hash drift check](#pinned-hash-drift-check) before signing under `--rule-id`.

**Pin record.** When the new signer is `External` (`--signer-ed25519`, `--signer-external`, `--signer-webauthn`) and the rule has a pin record, the add keeps the record in step with the rule's verifiers. Before submission, a verifier address the rule does not already use is identified and probed as `rules create` probes one. A hash outside the allowlist fails with `sa.verifier_wasm_not_in_allowlist` and a mutable contract with `sa.verifier_mutable` unless the matching flag above is set. An unpinnable instance fails with `sa.contract_instance_unsupported` regardless. After the add confirms, a `SaContextRulePinsUpdated` row (reason `signer_added`) records the verifier pins, one per distinct pin, in hash and executable reference, whether or not the resulting state is then recorded. A signer on a verifier the rule already uses, or on a new verifier whose pin equals a recorded pin, leaves them unchanged. A signer on a new verifier with another pin appends its pin. A record with two verifier pins is refused by every checked signing verb with `sa.pin_check_unavailable` (inner code `sa.multiple_pinned_hashes_unsupported`), the same outcome as a rule installed with two verifiers. When the rule has no `External` signer, [`signers refresh`](#smart-account-signers-refresh) removes the record's sole verifier pin and its reference before the add, as after a `migrate-verifier` pair whose repoint was not written. The policy pins, the policy references and the override flags stay as they are. A rule without a pin record stays unpinned: nothing is probed and no row is written.

```bash
stellar-agent smart-account signers add \
  --account CABC...WXYZ \
  --rule-id 0 \
  --signer-delegated GNEW...WXYZ \
  --signer-secret-env WALLET_SK
```

```bash
stellar-agent smart-account signers add \
  --account CABC...WXYZ \
  --rule-id 1 \
  --signer-ed25519 3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29 \
  --signer-secret-env WALLET_SK
```

### `smart-account signers remove`

Removes a signer by its on-chain id (OZ `remove_signer`). Signs and submits. Testnet only. Refused (with a safe-ordering hint) if removing the signer would drop `signer_count` below `threshold`: lower the threshold first, then remove. A rule whose policies include no simple-threshold policy, such as a weighted-threshold rule, refuses with `sa.threshold_policy_identification_failed` before submission. Another policy decides which signers suffice there. A rule without any policy has no threshold to check.

Extra flag:

- `--signer-id <U32>` (required): the on-chain signer id to remove, from `smart-account signers list`.

```bash
stellar-agent smart-account signers remove \
  --account CABC...WXYZ \
  --rule-id 0 \
  --signer-id 2 \
  --signer-secret-env WALLET_SK
```

### `smart-account signers set-threshold`

Changes the rule's signing threshold via the threshold-policy contract's `set_threshold`. Signs and submits. Testnet only. The threshold-policy contract is the attached policy whose executable hash is in the simple-threshold allowlist. A rule with none refuses with `sa.threshold_policy_not_installed`, and a rule with more than one with `sa.threshold_policy_identification_failed`.

Extra flag:

- `--new-threshold <U32>` (required): the new threshold. There is no `--auth-rule-id` override on this verb; the authorizing rule is `--rule-id`.

```bash
stellar-agent smart-account signers set-threshold \
  --account CABC...WXYZ \
  --rule-id 0 \
  --new-threshold 2 \
  --signer-secret-env WALLET_SK
```

### `smart-account signers set-weighted-threshold`

Changes a rule's weighted-threshold policy's `threshold` (OZ `set_threshold` on the weighted-threshold policy contract). Signs and submits. Testnet only. The policy is identified by wasm-hash allowlist lookup (a SEPARATE allowlist from the simple threshold-policy's: the two kinds never cross-identify); zero or multiple matches refuse with the typed `WeightedThresholdNotInstalled` / `WeightedThresholdPolicyIdentificationFailed`. Refused client-side before any network call when the new threshold is `0` or exceeds the checked sum of current signer weights.

Extra flags:

- `--new-threshold <U32>` (required).
- `--auth-rule-id <U32>` (optional): rule that AUTHORIZES the change. Defaults to `--rule-id`: a weighted policy commonly sits on a Default-scoped rule that self-authorizes. Pass an explicit admin-capable rule id when `--rule-id` names a CallContract- or CreateContract-scoped rule: a scoped rule cannot validate the `execute` auth context and can never authorize its own retune (the same constraint documented for `rules set-spending-limit`). An authorizing rule other than `0` has its signer-set baseline checked before signing (see [pre-submission checks](#pre-submission-checks)).

```bash
stellar-agent smart-account signers set-weighted-threshold \
  --account CABC...WXYZ \
  --rule-id 1 \
  --new-threshold 2 \
  --signer-secret-env WALLET_SK
```

### `smart-account signers set-signer-weight`

Changes one signer's weight in a rule's weighted-threshold policy (OZ `set_signer_weight`). Signs and submits. Testnet only. Refused client-side when the adjusted weight sum (current sum minus the target signer's old weight plus the new weight) would fall below the current threshold.

Exactly one of the following identifies the TARGET signer (mutually exclusive group):

- `--signer-delegated <G_STRKEY>`: a delegated ed25519 signer.
- `--signer-ed25519 <HEX_PUBKEY_64>`: a first-class external Ed25519 signer; optional `--verifier <C_STRKEY>` override.
- `--signer-external <C_STRKEY>`: a custom external-verifier signer; requires `--signer-key-data <HEX>`.
- `--signer-webauthn <CREDENTIAL_NAME>`: a passkey signer resolved from the profile's passkey registry.

Plus:

- `--new-weight <U32>` (required): the target signer's new weight.
- `--auth-rule-id <U32>` (optional): same default-to-`--rule-id` / scoped-rule override rule as `set-weighted-threshold`. An authorizing rule other than `0` has its signer-set baseline checked before signing (see [pre-submission checks](#pre-submission-checks)).

```bash
stellar-agent smart-account signers set-signer-weight \
  --account CABC...WXYZ \
  --rule-id 1 \
  --signer-delegated GTARGET...WXYZ \
  --new-weight 2 \
  --signer-secret-env WALLET_SK
```

### `smart-account signers batch-add`

Adds MULTIPLE signers to a rule in ONE transaction (OZ `batch_add_signer`). Signs and submits. Testnet only. Refused client-side if the batch is empty, or if `current_signer_count + batch_len` would exceed the per-rule signer cap (15). Emits one `SaSignerAddedV2` audit row per signer. Returns `new_signer_ids` in the order supplied: each entry is the id the chain assigned to that signer. A rule without a simple-threshold policy accepts a batch.

Flags (each repeatable, any combination, at least one signer required across all three):

- `--signer-delegated <G_STRKEY>`: one Delegated (ed25519) signer per occurrence.
- `--signer-webauthn <CREDENTIAL_NAME>`: one WebAuthn passkey signer (resolved from the profile's passkey registry) per occurrence.
- `--signer-ed25519 <HEX_PUBKEY_64>`: one first-class External-Ed25519 signer per occurrence; `--verifier <C_STRKEY>` (optional) overrides the verifier used for ALL `--signer-ed25519` entries in the call.
- `--accept-mutable-verifier`, `--accept-unknown-verifier`: as on `signers add`.

The batch keeps the rule's pin record in step as `signers add` does (see "Pin record" there). Each distinct new verifier address the rule does not use is probed before submission. After confirmation, one `SaContextRulePinsUpdated` row (reason `signer_added`) records the resulting verifier pins.

```bash
stellar-agent smart-account signers batch-add \
  --account CABC...WXYZ \
  --rule-id 1 \
  --signer-delegated GNEW1...WXYZ \
  --signer-ed25519 3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29 \
  --signer-webauthn my-passkey \
  --signer-secret-env WALLET_SK
```

---

## `smart-account execute`

Submits one `CallContract` invocation against an external contract, authorized by a named context rule and signed by an External-Ed25519 rule signer, with a separate fee-paying envelope signer. This is the delegation surface: an agent holding only its own ed25519 seed submits a call through its scoped rule — see [Agent delegation](../agent-delegation.md) for the full walkthrough. Signs and submits. Testnet only; structurally refuses `mainnet` before any RPC call or key-material access.

Two distinct signers participate — neither is the other:

- The **rule signer** (`--rule-signer-ed25519-secret-env`) authorizes the smart-account call. It is the agent's own key; it never needs a funded classic account.
- The **fee-payer signer** (`--signer-secret-env` / `--sign-with-ledger`, the standard [signer source](index.md#signer-source) group) pays the transaction fee and signs the envelope.

Flags:

- `--account <C_STRKEY>` (required): the smart account whose rule authorizes the call (`auth_address`).
- `--contract <C_STRKEY>` (required): the external target contract (`target_contract`). For most delegated calls this differs from `--account`.
- `--function <NAME>` (required): the contract function to invoke.
- `--arg <SCVAL_BASE64>`: one standard-base64 XDR `ScVal` argument, in call order. Repeatable. Decoded client-side only to validate well-formedness (bounded XDR decode): never re-encoded; a malformed value is refused with the failing argument's index named.
- `--auth-rule-id <U32>` (required): authorizing rule id(s). Repeatable, with no default. The delegation call names a specific scoped rule. A default bootstrap rule (`[0]`) could authorize against the wrong rule or produce an on-chain refusal that hides the caller's mistake.
- `--rule-signer-ed25519-secret-env <VAR>` (required): environment variable holding the rule signer's S-strkey seed.
- `--expect-rule-signer <64_HEX>`: fail closed, before any signing, if the seed-derived public key differs from this value. Surfaces a misconfigured environment variable before any signing.
- `--verifier <C_STRKEY>`: Ed25519-verifier contract override. Omitted, it resolves from the verifier registry (populated by `smart-account deploy-ed25519-verifier`), failing closed if none is registered.
- Shared: `--profile`, fee-payer signer-source group, `--network`, `--rpc-url`, `--secondary-rpc-url`, `--timeout-seconds`, `--output`.

On success the envelope carries `status: "submitted"`, `contract`, `function`, `arg_count`, `auth_rule_ids`, `rule_signer_pubkey_first8` (never the full key or seed), `verifier_address`, and `tx_hash`. On-chain refusals (spending-limit cap, scope mismatch, expired rule) surface through the same typed `SaError` wire codes and message annotations (for example `[OZ:SpendingLimitExceeded]`, `[OZ:UnvalidatedContext]`) every other smart-account write verb renders.

Before anything is simulated or signed, every `--auth-rule-id` other than `0` goes through the [pre-submission checks](#pre-submission-checks) against the profile's audit log. A rule without a signer-set baseline refuses with `sa.signer_set_missing_baseline`, and an audit-log integrity error with `sa.audit_log`. For a checked verifier or policy, the first eight bytes of the live code hash must equal the pinned value. An external reference must also match its pinned owner, tag, and resolved hash prefix. A mismatch refuses with `sa.verifier_hash_drift` / `sa.policy_hash_drift`, and a drift check that cannot run with `sa.pin_check_unavailable`. A rule whose record holds policy pins while the rule has no policy on chain refuses with `sa.pinned_policy_absent`. A rule holding an `External` signer while its record pins no verifier refuses with `sa.pinned_verifier_absent`. A signer set that differs from the baseline refuses with `sa.signer_set_diverged`. The checks read and fetch through the same `--rpc-url` / `--secondary-rpc-url` endpoints as the submission. Endpoint disagreement is `network.rpc_divergence`. Lock timeout is `sa.auth_entry_construction_failed` at stage `rule_lock`. A deadline that elapses during the baseline read or the comparison uses that code at `baseline_read` or `signer_set_compare`. A version 1 authorizing rule compares through its projection. Its own refusals are `sa.threshold_policy_not_installed`, `sa.threshold_policy_identification_failed`, and `sa.deployment_failed`.

This example also reads the agent's seed from `AGENT_SK` (see [Pass a secret seed](../getting-started.md#pass-a-secret-seed)). Run this line on its own, paste the agent's seed when prompted, and press Enter:

```bash
printf 'AGENT_SK seed: ' && read -rs AGENT_SK && echo && export AGENT_SK
```

```bash
stellar-agent smart-account execute \
  --account CABC...WXYZ \
  --contract CTOK...WXYZ \
  --function transfer \
  --arg AAAAEgAAAAA... \
  --arg AAAAEgAAAAA... \
  --arg AAAACgAAAAA... \
  --auth-rule-id 3 \
  --rule-signer-ed25519-secret-env AGENT_SK \
  --signer-secret-env WALLET_SK
unset AGENT_SK
```

There is currently no MCP tool for this verb; see [MCP: why there is no agent-facing execute tool](../mcp.md#why-there-is-no-agent-facing-execute-tool).

---

## `smart-account multicall`

Submits an atomic multicall bundle (1 to 50 invocations) through the registered multicall router contract for the target network. Signs and submits. The router address is resolved from the local registry (`<canonical_data_root>/networks.toml`). On a mainnet profile the command refuses with `network.mainnet_write_forbidden` before any registry, writer, or signer access. A signer source is required.

Each `--invocation` value has the form `<target>:<fn>:<json-args>`, where `<target>` is the C-strkey of the contract to invoke, `<fn>` is the function name, and `<json-args>` is a JSON array of XDR-encoded arguments.

Flags:

- `--smart-account <C_STRKEY>` (required): the smart-account executing the bundle.
- `--rule-id <U32>` (required): the context rule authorizing the bundle.
- `--invocation <TARGET:FN:JSON_ARGS>` (required, repeatable, 1 to 50): one invocation descriptor.
- `--secondary-rpc-url <URL>`: secondary RPC for cross-verification. Resolved from the flag, else the profile's `secondary_rpc_url`, else a typed error.
- `--fee <STROOPS>`: per-op base fee in stroops (default 100). Unlike the deploy verb, `auto[:pNN]` is rejected here.
- Signer-source flags are required (one of `--signer-secret-env` or `--sign-with-ledger`); `--account-index <INDEX>` defaults to `0`.
- Shared: `--profile`, `--network`, `--rpc-url`, `--timeout-seconds`.

A `--rule-id` other than `0` goes through the [pre-submission checks](#pre-submission-checks) before the bundle is simulated; a refusal surfaces as `sa.multicall_failed` at phase `policy_gate`, naming the inner code.

```bash
stellar-agent smart-account multicall \
  --smart-account CABC...WXYZ \
  --rule-id 0 \
  --invocation 'CTOK...WXYZ:transfer:["GABC...WXYZ","GWXY...WXYZ","1000000"]' \
  --secondary-rpc-url https://rpc2.example \
  --signer-secret-env WALLET_SK
```

---

## Infrastructure and timelock verbs

Deploy-time, registry-management, migration, and upgrade-timelock operations that sit alongside the context-rule and signer lifecycle.

### `smart-account deploy-webauthn-verifier`

`--profile <NAME>` selects the profile, followed by `STELLAR_AGENT_PROFILE`, then `default`. An explicitly named missing profile refuses.

Deploys the OpenZeppelin WebAuthn-verifier WASM and records its address in the verifier registry (`<canonical_data_root>/networks.toml`). Idempotent: if the registry already holds an entry for the target network with the same WASM hash, it returns `status: "already_deployed"` with no RPC traffic. Signs and submits unless `--dry-run`. Testnet only.

Exactly one deployer source is required (mutually exclusive group): `--deployer-secret-env <VAR>` or `--sign-with-ledger`.

Flags:

- `--deployer-secret-env <VAR>` — env-var name holding the deployer S-strkey. Mutually exclusive with `--sign-with-ledger`.
- `--sign-with-ledger` — use a connected Ledger as the deployer.
- `--account-index <INDEX>` — Ledger BIP-44 index. Default `0`.
- `--network <NETWORK>`: optional assertion that must match the profile chain.
- `--rpc-url <URL>`: optional testnet override; absent uses the profile endpoint. Mainnet profiles refuse the flag.
- `--fee <STROOPS|auto[:pNN]>` (optional) — explicit per-op stroop fee, or `auto` (p95), or `auto:p50` / `auto:p75` / `auto:p95` / `auto:p99`. Absent uses the profile default (100 stroops base; Soroban resource fees are added by simulation).
- `--timeout-seconds <SECONDS>` — default `60`.
- `--output <FORMAT>` — `json` (default) or `table`.
- `--dry-run` — derive the verifier address with no network access or signing; returns `status: "dry_run"`.

This example reads the deployer seed from `DEPLOYER_SK`; set it as [Pass a secret seed](../getting-started.md#pass-a-secret-seed) shows, and unset it after the command.

```bash
stellar-agent smart-account deploy-webauthn-verifier --deployer-secret-env DEPLOYER_SK
```

### `smart-account deploy-ed25519-verifier`

`--profile <NAME>` selects the profile, followed by `STELLAR_AGENT_PROFILE`, then `default`. An explicitly named missing profile refuses.

Deploys the OpenZeppelin Ed25519-verifier WASM and records its address in the verifier registry. Same idempotency, signer modes, and flags as `deploy-webauthn-verifier` above. This is the verifier bootstrap for first-class external Ed25519 signers (`smart-account signers add --signer-ed25519`) — see [Agent delegation](../agent-delegation.md).

This example reads the deployer seed from `DEPLOYER_SK`; set it as [Pass a secret seed](../getting-started.md#pass-a-secret-seed) shows, and unset it after the command.

```bash
stellar-agent smart-account deploy-ed25519-verifier --deployer-secret-env DEPLOYER_SK
```

### `smart-account deploy-spending-limit-policy`

`--profile <NAME>` selects the profile, followed by `STELLAR_AGENT_PROFILE`, then `default`. An explicitly named missing profile refuses.

Deploys the OpenZeppelin spending-limit-policy WASM and records its address in the verifier registry. Same idempotency, signer modes, and flags as `deploy-webauthn-verifier` above. The policy is a per-network singleton: one deployed instance serves every account and context rule on the network, so this only needs to run once per network. Attach the deployed policy to a rule via [`smart-account rules add-policy --kind spending-limit`](#smart-account-rules-add-policy).

This example reads the deployer seed from `DEPLOYER_SK`; set it as [Pass a secret seed](../getting-started.md#pass-a-secret-seed) shows, and unset it after the command.

```bash
stellar-agent smart-account deploy-spending-limit-policy --deployer-secret-env DEPLOYER_SK
```

### `smart-account deploy-policy`

`--profile <NAME>` selects the profile, followed by `STELLAR_AGENT_PROFILE`, then `default`. An explicitly named missing profile refuses.

Deploys any one of the three OpenZeppelin policy contracts through a single verb, selected by `--kind`. Same idempotency (`status: "already_deployed"` on a repeat run with the same deployer, no RPC traffic), signer modes, and shared flags as `deploy-webauthn-verifier` above. Each kind uses its OWN salt-domain prefix, so different kinds deployed by the same deployer on the same network derive DIFFERENT addresses. This is the recommended entry point for deploying any policy; `deploy-spending-limit-policy` remains for backward compatibility and delegates to the same substrate for that kind.

Extra flag:

- `--kind <simple-threshold|spending-limit|weighted-threshold>` (required) — which policy contract to deploy.
  - `simple-threshold` — signer-count-based threshold policy. Attach via [`rules add-policy --kind simple-threshold`](#smart-account-rules-add-policy).
  - `spending-limit` — rolling-window spending-limit policy. Attach via [`rules add-policy --kind spending-limit`](#smart-account-rules-add-policy).
  - `weighted-threshold` — weighted-signer quorum policy. Attach via [`rules add-policy --kind weighted-threshold`](#smart-account-rules-add-policy); tune via [`signers set-weighted-threshold`](#smart-account-signers-set-weighted-threshold) / [`signers set-signer-weight`](#smart-account-signers-set-signer-weight).

This example reads the deployer seed from `DEPLOYER_SK`; set it as [Pass a secret seed](../getting-started.md#pass-a-secret-seed) shows, and unset it after the command.

```bash
stellar-agent smart-account deploy-policy \
  --kind weighted-threshold \
  --deployer-secret-env DEPLOYER_SK
```

### `smart-account migrate-verifier`

Builds and optionally executes a plan that moves all `External` signers from one verifier to another across every context rule on a smart-account. Dry-run is read-only and renders the plan as JSON; without `--dry-run` it signs and submits `remove_signer` / `add_signer` pairs. Mainnet dry-run is allowed (read-only); mainnet submit is structurally refused (`network.mainnet_write_forbidden`).

Pre-flight gates (fail-closed): the destination verifier hash must be in the allowlist, its audit status must be `Audited`, `Provisional`, or `Unaudited`, and the destination contract must be immutable.

The plan reads every active rule's signer set in full. A rule holding a signer the wallet cannot decode refuses the whole plan, dry-run included, with `sa.verifier_migration_failed` at phase `plan_build`; the reason names the rule, the signer's index and why it does not decode. Delete that rule (see [pinned-hash drift check](#pinned-hash-drift-check)), then migrate.

Each pair runs under the migrating rule's lock as two checked signer mutations; the lock is held from the removal's comparison to the pair's last row, and released between two pairs.

1. The removal compares the rule with its newest [signer-set state](#smart-account-signers--signer-set-lifecycle), which must be version 2. A rule without one refuses with `sa.signer_set_missing_baseline`, a version 1 state with `sa.signer_set_baseline_legacy`, both before any RPC, and a changed chain with `sa.signer_set_diverged`.
2. The pair's plan is checked against the compared set before anything is sent. The signer must still hold an `External` identity on the rule, and the add must restore its key data on the destination verifier; otherwise the pair refuses with `sa.verifier_migration_failed` at phase `plan_build`.
3. The removal's preconditions are checked, as `signers remove` checks them (below).
4. The removal is sent. The confirmed rule must be the compared set without the signer, and is recorded as `SaSignerRemovedV2`.
5. On a rule with a pin record, a `SaContextRulePinsUpdated` row (reason `verifier_migrated`) names the destination verifier's hash as the rule's verifier pin, with the policy pins unchanged. A rule without a pin record stays unpinned, and a record that already names the destination alone is not rewritten.
6. The add compares the rule with the removal's row. Its simulated return value must be a signer id before it is signed. The confirmed rule must hold the removed key data on the destination under that id, every other signer and the threshold unchanged, and is recorded as `SaSignerAddedV2`.
7. `SaVerifierMigrated` records the pair.

Signer verbs and every other signature under a migrated rule then compare against the add's row; no refresh is needed. Both transactions of each pair sign under the migrating rule. The [pinned-hash drift check](#pinned-hash-drift-check) runs on that rule's policies, refusing with `sa.policy_hash_drift`, `sa.pinned_policy_absent` or `sa.pin_check_unavailable`. It skips the rule's verifiers: the migration's gates already vetted the destination, and the source verifier may be the drifted contract being replaced.

The removal's preconditions refuse before anything is sent:

- `sa.threshold_unreachable`: the rule's threshold equals its signer count, a 1-of-1 rule included. Each pair signs under the migrating rule with the source key alone, so that key must be a Delegated signer of the rule, and the rule's threshold must stay reachable after the removal. `add_signer` signs under the target rule alone, so no other rule can add a signer to it. Delete such a rule with `rules delete --rule-id <N> --auth-rule-id 0` and install it again with the destination verifier. Running `signers add` for the destination first and `signers remove` second is no alternative: on a pinned rule the add appends a second verifier pin, and the removal then refuses with `sa.pin_check_unavailable`.
- `sa.threshold_policy_identification_failed`: the rule has policies and none is the simple-threshold policy. A weighted policy keys its weights by signer value, and the restored signer on the new verifier would hold none.

**Partial failure.** A pair that stops after its removal was sent returns the add that completes it as `pending_add`, and the command prints the line that completes it on stderr, before the JSON envelope. A re-run of `migrate-verifier` does not find a removed signer, since the planner matches the signers the rule holds; it migrates the signers no pair has started. The printed `signers add` carries the signer-source, `--profile`, `--network` and `--timeout-seconds` flags of the invocation. Add the `--rpc-url` and `--secondary-rpc-url` flags of the invocation yourself: the output never echoes an endpoint URL, since one can carry a credential. The cases, decided on the pair's error:

- The removal confirmed and was recorded, and the add failed: `run: stellar-agent smart-account signers add --account <C> --rule-id <N> --signer-external <C_DEST> --signer-key-data <HEX> ...`.
- The rule's newest state row is not the chain's state: the removal confirmed and its state row was not written (`sa.baseline_write_failed`), or the chain differs from the pair's newest state row (`sa.signer_set_diverged`). The divergence carries the removal's hash when the confirmed removal left another state, and no hash when the chain changed between the two steps. The line is `run: stellar-agent smart-account signers refresh --account <C> --rule-id <N> --accept-divergence ..., then:` the `signers add`.
- The removal's outcome is unknown (`submission.tx_timeout`, `submission.tx_already_submitted` or `submission.hash_mismatch`, with `remove_confirmed: false`): once the removal is confirmed, run the refresh, then the `signers add`. A re-run of `migrate-verifier` that finds an empty plan means the removal landed, and the refresh then the printed add complete the pair. If the removal is not found, re-run `migrate-verifier`.
- The add's outcome is unknown (`add_tx_hash` set): once the add is confirmed, run the refresh; if it is not found, run the `signers add`.

A pair that stops before its removal was sent prints no line: nothing changed on chain. A pair whose add confirmed returns no pending add; its error names the refresh.

The rule's pin record names the destination from the moment a pair's removal was sent. On a rule with several affected signers, a signing under the rule then refuses with `sa.verifier_hash_drift` for the source verifier until the rule's last pair has migrated; the pairs themselves skip the verifier check. The printed `signers add` of a failed pair on such a rule is refused the same way. Its line therefore names `re-run migrate-verifier for the remaining signers of rule <N>` after the repair step (the refresh, or the wait for an unknown outcome) and before the `signers add`. The re-run compares the rule with its newest state row, so it follows the refresh. After a removal with an unknown outcome that is not found on chain, the source signer is still live while the record names the destination. Every signing under the rule refuses with `sa.verifier_hash_drift` until `migrate-verifier` is re-run, which finds the signer on the source verifier and completes the pair.

The result envelope lists, for each step, `key_data_hex` (the key data its add restores, so the step's `signers add` can be rebuilt from the plan), the submitted hashes and, for a completed pair, `new_signer_id`. `failed_step_remove_tx_hash` names a confirmed removal of the failed pair. `pending_add` carries `rule_id`, `signer_id`, `to_verifier_address`, `key_data_hex`, `remove_tx_hash`, `remove_confirmed`, `add_tx_hash` (an add with an unknown outcome) and `recovery_command`.

Flags:

- `--account <C_STRKEY>` (required): smart-account to migrate.
- `--from <HASH_HEX>` (required): 64-char hex SHA-256 of the source verifier WASM; only `External` signers whose verifier matches are included.
- `--to <C_STRKEY>` (required): destination verifier contract.
- `--dry-run`: plan only, no transactions submitted.
- Shared: `--profile`, signer-source group (required for submit, not for dry-run), `--network`, `--rpc-url`, `--secondary-rpc-url`, `--timeout-seconds`.

```bash
stellar-agent smart-account migrate-verifier \
  --account CABC...WXYZ \
  --from 678006909b50c6c365c033f137197e910d8396a2c68e9281327a2ed7dbf4b27a \
  --to CNEW...WXYZ \
  --dry-run
```

### `smart-account list-verifiers`

Enumerates the compile-time verifier allowlist with its audit-status taxonomy. Read-only; no network calls, no signing. The only flag is `--output <FORMAT>` (`json` default; `table` supported).

```bash
stellar-agent smart-account list-verifiers --output table
```

### `smart-account list-rules`

Enumerates the active context rules on a smart-account by scanning the on-chain `[0, max_scan_id)` rule-id space and returning each active rule in `rule_id` order. Read-only; no signing. `mainnet` is accepted. This is the alias backing `smart-account rules list`; both produce the same envelope.

Flags:

- `--account <C_STRKEY>` (required): smart-account to query.
- `--source-account <G_STRKEY>` (optional): simulation source account. On testnet it defaults to a well-known funded interop deployer; on mainnet pass any funded account (it is not debited).
- `--rpc-url <URL>`: optional testnet override; absent uses the profile endpoint. Mainnet profiles refuse the flag.
- `--secondary-rpc-url <URL>`: optional testnet override; absent uses the profile secondary. Mainnet profiles refuse the flag.
- `--network <NETWORK>`: optional assertion that must match the profile chain.
- `--profile <NAME>`.
- `--max-scan-id <N>`: override the scan upper bound. Must be in `1..=10000`; values outside that range are rejected at parse time. When unset, the profile value is used, else `50`.
- `--timeout-seconds <SECONDS>`: default `60`; covers the full enumeration, the baseline reads included.
- `--output <FORMAT>`: `json` default; `table` mode is deferred (the flag is accepted but renders the JSON envelope).

Each entry of `rules` carries `rule_id`, `name`, `context_type_label`, `signer_count`, `policy_count`, `valid_until` (omitted for a permanent rule) and `baseline`. `baseline` is the rule's signer-set baseline in the profile's audit log: `none` (no state row), `v1`, `v2`, `unreadable` (an audit-log integrity error for that rule) or `unknown` (the log was not read). Every signature under a rule other than `0` needs the baseline: a rule reporting `none` refuses with `sa.signer_set_missing_baseline` until one `signers list --rule-id N` records it. Rule `0` reports its own state like any rule.

```bash
stellar-agent smart-account list-rules --account CABC...WXYZ
```

### `smart-account register-multicall`

Registers a deployed multicall router address and its WASM hash in the local registry (`<canonical_data_root>/networks.toml`). State-changing on a local file plus an audit row. Idempotent. Refuses if `--wasm-sha256` does not equal the binary's compiled-in `MULTICALL_WASM_SHA256` (typo and config-plant defence).

Flags:

- `--network <NETWORK>`: optional assertion that must match the profile chain.
- `--address <C_STRKEY>` (required) — deployed router contract address.
- `--wasm-sha256 <HEX>` (required) — 64-char lowercase hex; must match the compiled-in router WASM hash.
- `--profile <NAME>` — for the audit-log path.

```bash
stellar-agent smart-account register-multicall \
  --address CRTR...WXYZ \
  --wasm-sha256 67800690...b27a
```

### `smart-account unregister-multicall`

Removes the multicall router registry entry for a network. State-changing on a local file plus an audit row.

The normal path validates the stored entry and removes it. The `--force` path is for registry-file corruption recovery: it bypasses strkey/hex validation and locates the entry by network name. `--force` requires interactive `[y/N]` confirmation on a TTY, or `--yes-i-have-verified-the-prior-values` for non-TTY invocations; the audit row is written before the file is mutated.

Flags:

- `--network <NETWORK>`: optional assertion that must match the profile chain.
- `--force` — corruption-recovery bypass.
- `--yes-i-have-verified-the-prior-values` — suppress the confirmation prompt for `--force` on a non-TTY.
- `--profile <NAME>` — for the audit-log path.

```bash
stellar-agent smart-account unregister-multicall --network testnet
```

### `smart-account timelock` — OpenZeppelin upgrade timelock

Schedule, cancel, execute, and list pending operations on an OpenZeppelin timelock contract. The signer must hold the appropriate timelock role for each write verb. All four share `--timelock <C_STRKEY>` (required), `--rpc-url`, `--secondary-rpc-url`, `--network`, and `--profile`; the write verbs add the signer-source group. The write verbs (`schedule`, `cancel`, `execute`) structurally refuse `mainnet`; `list-pending` is read-only and accepts `mainnet`.

Without `--secondary-rpc-url`, the profile secondary applies. The timelock manager uses the primary when neither source supplies a secondary.

#### `smart-account timelock schedule`

Schedules an operation (PROPOSER role). Signs and submits. The operation salt is derived non-deterministically and is returned in the JSON output as the `salt` field (64-char lowercase hex). Record it immediately — it is required by the matching `execute` and `cancel` calls and cannot be recomputed later. On success the envelope also carries `operation_id_full_hex`.

Flags add: `--target <C_STRKEY>` (required) — the target contract; `--function <NAME>` (required) — the function to call on execute; `--delay-ledgers <N>` (required) — minimum delay in ledgers before execution; plus the signer-source group.

This example reads the proposer seed from `PROPOSER_SK`; set it as [Pass a secret seed](../getting-started.md#pass-a-secret-seed) shows, and unset it after the command.

```bash
stellar-agent smart-account timelock schedule \
  --timelock CTLCK...WXYZ \
  --target CTGT...WXYZ \
  --function upgrade \
  --delay-ledgers 100 \
  --signer-secret-env PROPOSER_SK
# Save the "salt" field from the JSON output — required for execute and cancel.
```

#### `smart-account timelock cancel`

Cancels a pending operation (CANCELLER role). Signs and submits, then cross-confirms the on-chain cancellation event.

Flags add: `--operation-id <HEX>` (required) — the 64-char hex id from `schedule`; plus the signer-source group.

This example reads the canceller seed from `CANCELLER_SK`; set it as [Pass a secret seed](../getting-started.md#pass-a-secret-seed) shows, and unset it after the command.

```bash
stellar-agent smart-account timelock cancel \
  --timelock CTLCK...WXYZ \
  --operation-id abcdef01...89abcdef \
  --signer-secret-env CANCELLER_SK
```

#### `smart-account timelock execute`

Executes a ready operation (EXECUTOR role, or open-execution mode). A pre-flight dual-RPC state check guards the ready-window race and fails closed if the operation is not ready. The `--target`, `--function`, `--operation-id`, and `--salt` must exactly match the scheduled operation, since OpenZeppelin re-derives the operation id from them.

Flags add: `--target <C_STRKEY>` (required); `--function <NAME>` (required); `--operation-id <HEX>` (required); `--salt <HEX>` (required) — the 64-char lowercase hex `salt` field from the `schedule` command's JSON output; plus the signer-source group.

This example reads the executor seed from `EXECUTOR_SK`; set it as [Pass a secret seed](../getting-started.md#pass-a-secret-seed) shows, and unset it after the command.

```bash
stellar-agent smart-account timelock execute \
  --timelock CTLCK...WXYZ \
  --target CTGT...WXYZ \
  --function upgrade \
  --operation-id abcdef01...89abcdef \
  --salt 11223344...aabbccdd \
  --signer-secret-env EXECUTOR_SK
```

#### `smart-account timelock list-pending`

Lists pending operations for a timelock contract by cross-referencing the local audit log with a dual-RPC `get_operation_state` query. Read-only; no signing. `mainnet` is accepted.

Flags: `--timelock <C_STRKEY>` (required), `--rpc-url`, `--secondary-rpc-url`, `--network`, `--profile`.

```bash
stellar-agent smart-account timelock list-pending --timelock CTLCK...WXYZ
```

---

## Related pages

- [CLI reference index](index.md) — shared flags, output envelope, mainnet-write refusal.
- [Concepts](../concepts.md) — context rules, auth digest, policy engine, approval spine, audit log.
- [Profiles](../profiles.md) — profile schema, keyring entry references, thresholds.
- [Agent delegation](../agent-delegation.md) — scoping an autonomous agent to one contract under a spending cap.
