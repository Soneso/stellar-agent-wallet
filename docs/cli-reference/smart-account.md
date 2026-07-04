# CLI reference: smart-account

The `smart-account` command group (also available under the shorter alias `sa`) governs an on-chain OpenZeppelin smart-account: its context rules, its signer sets and thresholds, the policy contracts attached to each rule, and the supporting infrastructure (verifier registry, multicall router registry, upgrade timelock). It also submits multicall bundles through the registered router.

Most on-chain signing verbs that mutate context-rule, signer, or timelock state structurally refuse `mainnet` before any RPC call or signing key access, surfacing the wire code `network.mainnet_write_forbidden`: the `smart-account rules` write verbs, all `smart-account signers` verbs (including `list` and `refresh`, which emit audit rows), the timelock write verbs (`schedule`, `cancel`, `execute`), and `smart-account deploy-webauthn-verifier`. The exceptions:

- `smart-account migrate-verifier` allows a mainnet dry-run and permits a mainnet submit only when `--confirm-mainnet-migrate` is supplied; it never returns `network.mainnet_write_forbidden`.
- `smart-account multicall` accepts `mainnet` at the flag level but requires a multicall router registered for mainnet.
- `smart-account register-multicall` / `smart-account unregister-multicall` accept `mainnet` as a local-registry key.
- The read-only verbs (`smart-account rules get`, `smart-account rules verify-pins`, `smart-account rules list` / `smart-account list-rules`, `smart-account list-verifiers`, `smart-account timelock list-pending`) accept `mainnet` unconditionally.

For the terms used here — [profile](../profiles.md), policy engine, approval spine, audit log, [context rule](../concepts.md), auth digest — see [concepts](../concepts.md). The shared flags (`--profile`, `--network`, `--rpc-url`, `--secondary-rpc-url`, `--timeout-seconds`, `--output`, and the signer-source group) are defined once on the [CLI reference index](index.md#global-conventions); this page names each flag a command takes and only describes the flags specific to that command.

Every command prints one JSON envelope on stdout and returns exit code `0` on success, `1` on any error (see [output envelope and exit codes](index.md#output-envelope-and-exit-codes)).

## Signer source

The write verbs use the shared signer-source group: exactly one of `--signer-secret-env <VAR>` (an env-var name holding the source-account S-strkey) or `--sign-with-ledger` (the two are mutually exclusive, and the command refuses if neither is supplied), with `--account-index <INDEX>` selecting the Ledger BIP-44 index (default `0`). See [signer source](index.md#signer-source). All signing in this group goes through the smart-account auth-entry digest path: the signer signs the [auth digest](../concepts.md), which binds the authorizing context-rule ids.

```bash
export WALLET_SK="S..."   # source-account secret key; pass the var name, never the secret
```

---

## `smart-account rules` — context-rule lifecycle

Manages the OpenZeppelin context rules on a smart-account. Each rule has a `rule_id` (a `u32`), a name (OZ cap: 20 bytes), an optional expiry ledger, a signer set (OZ cap: 15 signers), and up to 5 policy contracts.

The `--auth-rule-id` flag on the write verbs names the rule whose signers authorize the operation; where it is optional it defaults to the rule being modified (`--rule-id`).

### `smart-account rules create`

Installs a new context rule (OZ `add_context_rule`) and returns the newly minted `rule_id`. Signs and submits. Testnet only.

Flags:

- `--account <C_STRKEY>` (required) — smart-account contract address.
- `--name <STRING>` (required) — rule name; refused as `validation.rule_name_too_long` over 20 bytes.
- `--signer-delegated <G_STRKEY>` — a delegated ed25519 signer. Repeatable.
- `--signer-webauthn <CREDENTIAL_NAME>` — a passkey signer, resolved from the profile's passkey registry (see [`credentials add-passkey`](profile-and-governance.md)). Repeatable. The verifier contract address is read from the verifier registry, which is populated by `smart-account deploy-webauthn-verifier`.
- `--accept-no-delegated-fallback` — acknowledge a passkey-only rule (no ed25519 fallback). Required when only `--signer-webauthn` signers are given; without it the command refuses with `validation.passkey_only_rule_no_delegated_fallback` after printing a stderr warning.
- `--accept-mutable-verifier` — proceed even if a referenced verifier or policy contract has a mutable admin/owner key. The envelope reports `mutable_override: true`.
- `--accept-unknown-verifier` — proceed even if a referenced verifier or policy WASM hash is not in the allowlist. The envelope reports `unknown_override: true`.
- `--auth-rule-id <U32>` — authorizing rule id(s). Repeatable. Default `[0]` (the bootstrap rule installed at deploy time).
- `--valid-until <LEDGER>` — expiry ledger sequence, or `none` for a permanent rule. Default `none`.
- Shared: `--profile`, signer-source group, `--network`, `--rpc-url`, `--secondary-rpc-url`, `--timeout-seconds`, `--output`.

At least one `--signer-delegated` or `--signer-webauthn` is required.

```bash
stellar-agent smart-account rules create \
  --account CABC...WXYZ \
  --name agent-ops \
  --signer-delegated GABC...WXYZ \
  --signer-secret-env WALLET_SK
```

### `smart-account rules get`

Reads a single rule by id (OZ `get_context_rule`). Read-only; no signing, no submission. `mainnet` is accepted. The envelope reports `present: true` or `present: false`.

Flags:

- `--account <C_STRKEY>` (required) — smart-account contract address.
- `--rule-id <U32>` (required) — rule index to fetch.
- `--source-account <G_STRKEY>` (required) — any funded account on the target network; used only to assemble the simulation envelope. It is not debited and not signed for.
- Shared: `--network`, `--rpc-url`, `--timeout-seconds`, `--output`.

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
- `--auth-rule-id <U32>` (optional) — authorizing rule id; defaults to `--rule-id`.
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
- `--auth-rule-id <U32>` (optional) — defaults to `--rule-id`.
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
- `--auth-rule-id <U32>` (optional) — defaults to `--rule-id`.
- Shared: `--profile`, signer-source group, `--network`, `--rpc-url`, `--secondary-rpc-url`, `--timeout-seconds`, `--output`.

```bash
stellar-agent smart-account rules delete \
  --account CABC...WXYZ \
  --rule-id 1 \
  --signer-secret-env WALLET_SK
```

### `smart-account rules verify-pins`

Verifies a rule's pinned verifier and policy WASM hashes against the live on-chain contracts (drift detection). Read-only; no signing, no submission. `mainnet` is accepted. Exit code is `1` when either pin status is `drift`, otherwise `0`; the JSON envelope is well-formed in both cases.

Each `*_pin_status` is one of `match`, `drift`, `unavailable`, `no_pin`, or `no_contracts`. The signer-source flags are used only to derive a source account for the simulation; no transaction is signed.

Flags:

- `--account <C_STRKEY>` (required).
- `--rule-id <U32>` (required) — rule whose pins to verify.
- `--rpc-url <URL>` (optional) — when omitted, defaults to the testnet RPC on testnet and the mainnet RPC default on mainnet.
- Shared: `--profile`, signer-source group, `--network`, `--secondary-rpc-url`, `--timeout-seconds`, `--output`.

```bash
stellar-agent smart-account rules verify-pins \
  --account CABC...WXYZ \
  --rule-id 1 \
  --signer-secret-env WALLET_SK
```

### `smart-account rules add-policy`

Adds a policy contract to a rule (OZ `add_policy`). The per-rule policy cap (5) is checked before simulation via a `get_context_rule` pre-fetch. Signs and submits. Testnet only. Returns the assigned `policy_id`.

Flags:

- `--account <C_STRKEY>` (required).
- `--rule-id <U32>` (required) — rule to add the policy to.
- `--policy-address <C_STRKEY>` (required) — policy contract address.
- `--install-param <SCVAL_BASE64>` (required) — a standard-base64 XDR `ScVal` install parameter (not base64url). It is passed to `add_policy` without further validation (raw passthrough); use the XDR tooling to produce the correct encoding for the policy.
- `--auth-rule-id <U32>` (optional) — authorizing rule id(s). Repeatable. Defaults to `--rule-id`.
- Shared: `--profile`, signer-source group, `--network`, `--rpc-url`, `--secondary-rpc-url`, `--timeout-seconds`, `--output`.

```bash
stellar-agent smart-account rules add-policy \
  --account CABC...WXYZ \
  --rule-id 1 \
  --policy-address CPOL...WXYZ \
  --install-param AAAAAQ== \
  --signer-secret-env WALLET_SK
```

### `smart-account rules remove-policy`

Removes a policy from a rule by its on-chain `policy_id` (OZ `remove_policy`). Signs and submits. Testnet only.

Flags:

- `--account <C_STRKEY>` (required).
- `--rule-id <U32>` (required) — rule to remove the policy from.
- `--policy-id <U32>` (required) — on-chain policy id to remove.
- `--auth-rule-id <U32>` (optional) — authorizing rule id(s). Repeatable. Defaults to `--rule-id`.
- Shared: `--profile`, signer-source group, `--network`, `--rpc-url`, `--secondary-rpc-url`, `--timeout-seconds`, `--output`.

```bash
stellar-agent smart-account rules remove-policy \
  --account CABC...WXYZ \
  --rule-id 1 \
  --policy-id 0 \
  --signer-secret-env WALLET_SK
```

### `smart-account rules list`

Enumerates the active context rules on a smart-account via on-chain scan. Read-only; no signing. `mainnet` is accepted. This is the canonical name for the enumeration; it produces the same JSON envelope as `smart-account list-rules` and takes the same flags (see [`smart-account list-rules`](#smart-account-list-rules)).

```bash
stellar-agent smart-account rules list --account CABC...WXYZ
```

---

## `smart-account signers` — signer-set lifecycle

Manages the signer set and threshold of a context rule. All verbs take `--account <C_STRKEY>` and `--rule-id <U32>` (both required), the signer-source group, `--profile`, `--network`, `--rpc-url`, `--secondary-rpc-url`, and `--timeout-seconds`. None of these verbs accept `--output` (passing it is rejected). All structurally refuse `mainnet`, including `list` and `refresh` (see the intro).

`list` and `refresh` also require a signer source: the manager needs a source account to assemble the read envelope.

### `smart-account signers list`

Reads the on-chain signer set for a rule and, if no prior baseline exists for the `(rule_id, account)` pair, writes a `SaSignerSetBaselined` audit row to anchor future divergence detection. Submits no on-chain transaction, but is state-changing on the audit log. Testnet only.

The envelope reports `signer_count`, `threshold`, the `signer_ids`, and a parallel `signer_kinds` list.

```bash
stellar-agent smart-account signers list \
  --account CABC...WXYZ \
  --rule-id 0 \
  --signer-secret-env WALLET_SK
```

### `smart-account signers refresh`

Unconditionally writes a fresh `SaSignerSetBaselined` audit row (re-anchor after an intentional out-of-band signer change). State-changing on the audit log only. Testnet only. Same flags as `list`.

```bash
stellar-agent smart-account signers refresh \
  --account CABC...WXYZ \
  --rule-id 0 \
  --signer-secret-env WALLET_SK
```

### `smart-account signers add`

Adds one signer to a rule (OZ `add_signer`). Signs and submits. Testnet only. The per-rule signer cap (15) is checked before submission via a `get_rule` pre-fetch. Returns the `new_signer_id`.

Exactly one of the following signer-source forms is required (mutually exclusive group):

- `--signer-delegated <G_STRKEY>` (alias `--new-signer`) — a delegated ed25519 signer.
- `--signer-external <C_STRKEY>` — a custom external-verifier signer. Requires `--signer-key-data <HEX>`.
- `--signer-webauthn <CREDENTIAL_NAME>` — a passkey signer resolved from the profile's passkey registry; the verifier address is read from the verifier registry.

Plus:

- `--signer-key-data <HEX>` — raw hex key-data for an external signer; required with, and only valid with, `--signer-external`.
- Shared: `--profile`, signer-source group, `--network`, `--rpc-url`, `--secondary-rpc-url`, `--timeout-seconds`.

```bash
stellar-agent smart-account signers add \
  --account CABC...WXYZ \
  --rule-id 0 \
  --signer-delegated GNEW...WXYZ \
  --signer-secret-env WALLET_SK
```

### `smart-account signers remove`

Removes a signer by its on-chain id (OZ `remove_signer`). Signs and submits. Testnet only. Refused (with a safe-ordering hint) if removing the signer would drop `signer_count` below `threshold`: lower the threshold first, then remove.

Extra flag:

- `--signer-id <U32>` (required) — the on-chain signer id to remove, from `smart-account signers list`.

```bash
stellar-agent smart-account signers remove \
  --account CABC...WXYZ \
  --rule-id 0 \
  --signer-id 2 \
  --signer-secret-env WALLET_SK
```

### `smart-account signers set-threshold`

Changes the rule's signing threshold via the threshold-policy contract's `set_threshold`. Signs and submits. Testnet only. The threshold-policy contract is identified by WASM-hash allowlist lookup; zero or multiple matches refuse with `sa.threshold_policy_identification_failed`.

Extra flag:

- `--new-threshold <U32>` (required) — the new threshold. There is no `--auth-rule-id` override on this verb; the authorizing rule is `--rule-id`.

```bash
stellar-agent smart-account signers set-threshold \
  --account CABC...WXYZ \
  --rule-id 0 \
  --new-threshold 2 \
  --signer-secret-env WALLET_SK
```

---

## `smart-account multicall`

Submits an atomic multicall bundle (1–50 invocations) through the registered multicall router contract for the target network. Signs and submits. The router address is resolved from the local registry (`~/.config/stellar-agent/networks.toml`); `mainnet` is accepted at the flag level but requires a router registered for mainnet. A signer source is required.

Each `--invocation` value has the form `<target>:<fn>:<json-args>`, where `<target>` is the C-strkey of the contract to invoke, `<fn>` is the function name, and `<json-args>` is a JSON array of XDR-encoded arguments.

Flags:

- `--smart-account <C_STRKEY>` (required) — the smart-account executing the bundle.
- `--rule-id <U32>` (required) — the context rule authorizing the bundle.
- `--invocation <TARGET:FN:JSON_ARGS>` (required, repeatable, 1–50) — one invocation descriptor.
- `--secondary-rpc-url <URL>` — secondary RPC for cross-verification. Resolved as: `profile.secondary_rpc_url`, then this flag (which overrides the profile value), then a typed error if neither is set.
- `--fee <STROOPS>` — per-op base fee in stroops (default 100). Unlike the deploy verb, `auto[:pNN]` is rejected here.
- Signer-source flags are required (one of `--signer-secret-env` or `--sign-with-ledger`); `--account-index <INDEX>` defaults to `0`.
- Shared: `--network`, `--rpc-url`, `--timeout-seconds`, `--profile`.

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

Deploys the OpenZeppelin WebAuthn-verifier WASM and records its address in the verifier registry (`~/.config/stellar-agent/networks.toml`). Idempotent: if the registry already holds an entry for the target network with the same WASM hash, it returns `status: "already_deployed"` with no RPC traffic. Signs and submits unless `--dry-run`. Testnet only.

Exactly one deployer source is required (mutually exclusive group): `--deployer-secret-env <VAR>` or `--sign-with-ledger`.

Flags:

- `--deployer-secret-env <VAR>` — env-var name holding the deployer S-strkey. Mutually exclusive with `--sign-with-ledger`.
- `--sign-with-ledger` — use a connected Ledger as the deployer.
- `--account-index <INDEX>` — Ledger BIP-44 index. Default `0`.
- `--network <NETWORK>` — default `testnet`; `mainnet` is refused.
- `--rpc-url <URL>` — default `https://soroban-testnet.stellar.org`.
- `--fee <STROOPS|auto[:pNN]>` (optional) — explicit per-op stroop fee, or `auto` (p95), or `auto:p50` / `auto:p75` / `auto:p95` / `auto:p99`. Absent uses the profile default (100 stroops base; Soroban resource fees are added by simulation).
- `--timeout-seconds <SECONDS>` — default `60`.
- `--output <FORMAT>` — `json` (default) or `table`.
- `--dry-run` — derive the verifier address with no network access or signing; returns `status: "dry_run"`.

```bash
stellar-agent smart-account deploy-webauthn-verifier --deployer-secret-env DEPLOYER_SK
```

### `smart-account migrate-verifier`

Builds and optionally executes a plan that moves all `External` signers from one verifier to another across every context rule on a smart-account. Dry-run is read-only and renders the plan as JSON; without `--dry-run` it signs and submits `remove_signer` / `add_signer` pairs. Mainnet dry-run is allowed; mainnet submit additionally requires `--confirm-mainnet-migrate`.

Pre-flight gates (fail-closed): the destination verifier hash must be in the allowlist, its audit status must be `Audited` or `Unaudited`, and the destination contract must be immutable.

Flags:

- `--account <C_STRKEY>` (required) — smart-account to migrate.
- `--from <HASH_HEX>` (required) — 64-char hex SHA-256 of the source verifier WASM; only `External` signers whose verifier matches are included.
- `--to <C_STRKEY>` (required) — destination verifier contract.
- `--dry-run` — plan only, no transactions submitted.
- `--confirm-mainnet-migrate` — explicit consent, required for a mainnet submit (distinct from the consent flag on other write surfaces).
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

- `--account <C_STRKEY>` (required) — smart-account to query.
- `--source-account <G_STRKEY>` (optional) — simulation source account. On testnet it defaults to a well-known funded interop deployer; on mainnet pass any funded account (it is not debited).
- `--rpc-url <URL>` — default testnet RPC.
- `--secondary-rpc-url <URL>` — defaults to `--rpc-url`.
- `--network <NETWORK>` — default `testnet`.
- `--profile <NAME>`.
- `--max-scan-id <N>` — override the scan upper bound. Must be in `1..=10000`; values outside that range are rejected at parse time. When unset, the profile value is used, else `50`.
- `--timeout-seconds <SECONDS>` — default `60`; covers the full enumeration.
- `--output <FORMAT>` — `json` default; `table` mode is deferred (the flag is accepted but renders the JSON envelope).

```bash
stellar-agent smart-account list-rules --account CABC...WXYZ
```

### `smart-account register-multicall`

Registers a deployed multicall router address and its WASM hash in the local registry (`~/.config/stellar-agent/networks.toml`). State-changing on a local file plus an audit row. Idempotent. Refuses if `--wasm-sha256` does not equal the binary's compiled-in `MULTICALL_WASM_SHA256` (typo and config-plant defence).

Flags:

- `--network <NETWORK>` — default `testnet`.
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

- `--network <NETWORK>` — default `testnet`.
- `--force` — corruption-recovery bypass.
- `--yes-i-have-verified-the-prior-values` — suppress the confirmation prompt for `--force` on a non-TTY.
- `--profile <NAME>` — for the audit-log path.

```bash
stellar-agent smart-account unregister-multicall --network testnet
```

### `smart-account timelock` — OpenZeppelin upgrade timelock

Schedule, cancel, execute, and list pending operations on an OpenZeppelin timelock contract. The signer must hold the appropriate timelock role for each write verb. All four share `--timelock <C_STRKEY>` (required), `--rpc-url`, `--secondary-rpc-url`, `--network`, and `--profile`; the write verbs add the signer-source group. The write verbs (`schedule`, `cancel`, `execute`) structurally refuse `mainnet`; `list-pending` is read-only and accepts `mainnet`.

When `--secondary-rpc-url` is omitted it defaults to `--rpc-url`; supplying an independent endpoint restores the cross-RPC divergence defence.

#### `smart-account timelock schedule`

Schedules an operation (PROPOSER role). Signs and submits. The operation salt is derived non-deterministically and is returned in the JSON output as the `salt` field (64-char lowercase hex). Record it immediately — it is required by the matching `execute` and `cancel` calls and cannot be recomputed later. On success the envelope also carries `operation_id_full_hex`.

Flags add: `--target <C_STRKEY>` (required) — the target contract; `--function <NAME>` (required) — the function to call on execute; `--delay-ledgers <N>` (required) — minimum delay in ledgers before execution; plus the signer-source group.

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

```bash
stellar-agent smart-account timelock cancel \
  --timelock CTLCK...WXYZ \
  --operation-id abcdef01...89abcdef \
  --signer-secret-env CANCELLER_SK
```

#### `smart-account timelock execute`

Executes a ready operation (EXECUTOR role, or open-execution mode). A pre-flight dual-RPC state check guards the ready-window race and fails closed if the operation is not ready. The `--target`, `--function`, `--operation-id`, and `--salt` must exactly match the scheduled operation, since OpenZeppelin re-derives the operation id from them.

Flags add: `--target <C_STRKEY>` (required); `--function <NAME>` (required); `--operation-id <HEX>` (required); `--salt <HEX>` (required) — the 64-char lowercase hex `salt` field from the `schedule` command's JSON output; plus the signer-source group.

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
