# CLI reference: profiles, credentials, approvals, and audit

See [Mainnet configurations and scope](../getting-started.md#mainnet-configurations-and-scope)
for build configuration, admitted operations, and exclusions.

This page documents four `stellar-agent` command groups: `profile`, `credentials`, `approve`, and `audit`. Together they configure a profile, manage its WebAuthn passkeys, and operate the operator-side governance loop: recording out-of-band approvals, verifying the tamper-evident audit log, and repairing its tip anchor.

For the conventions shared by every command (profile and network resolution, the signer-source flags, the JSON output envelope, exit codes, and mainnet write behavior), see the [CLI reference index](index.md). For the underlying concepts (the policy engine, the approval spine, attestations, the audit log, and toolset gating), see [concepts](../concepts.md). For profile file structure, see [profiles](../profiles.md), and for toolset gating see [toolsets](../toolsets.md).

All four groups operate on local TOML files and platform-keyring entries. None submits a Stellar transaction. Profile selection and enablement enforce their mainnet-specific prerequisites. Every command prints the standard `{ok, data, request_id}` JSON envelope on stdout. Exit `0` means success; exit `1` means an error.

## Profile selection and refused overlays

A mainnet profile loads only through `--profile <name>`. `STELLAR_AGENT_PROFILE` never selects one, and a mainnet `default.toml` needs `--profile default`. Keep the filename: its identity is bound to its keyring entries.

`profile show` displays the named document without applying the selection predicate.
The loader still applies the overlay classes on that read.

| Wire code | Meaning |
|---|---|
| `profile.non_overlayable_field` | An overlay named a key outside its class, or set `mcp_disabled` to anything but `true`, including an equal value. Overlays may set `submit_timeout_seconds` on every chain, the testnet-only endpoint, signer, fee, threshold, and scan-bound keys on testnet, and `mcp_disabled = true`; every other key comes from the file. Remove that environment value, overlay, or flag, and set the value in the profile file. |
| `profile.network_flag_mismatch` | `--network` differs from the loaded chain. Remove the flag or select a profile on that chain. |
| `auth.enrolled_signer_unpinned` | Mainnet enrollment is a placeholder or malformed. Correct a malformed `mcp_signer_default.account`, then run `stellar-agent profile enroll-signer --profile <name>`. |
| `auth.enrolled_signer_mismatch` | The derived key differs from the enrolled identity. Use the enrolled seed, Ledger account, or keyring entry. |
| `auth.enrolled_identity_unusable` | The signer identity record beside the seed is missing or unreadable, names another key or role, or the stored profile's signer differs from the loaded one. Run `stellar-agent profile enroll-signer --profile <name> --repair-identity`. |
| `profile.mainnet_requires_explicit_profile` | A mainnet profile was selected by the environment or the default source. Supply `--profile <name>`. |

Unset the `STELLAR_AGENT_*` variable the refusal names. On every chain that covers `STELLAR_AGENT_CHAIN_ID`, `STELLAR_AGENT_AUDIT_LOG_PATH`, every `*_KEY_ID` variable, and every other key outside the overlay classes. On mainnet it also covers `STELLAR_AGENT_RPC_URL`, `STELLAR_AGENT_SECONDARY_RPC_URL`, `STELLAR_AGENT_ORACLE_PROVIDER_URL`, `STELLAR_AGENT_MCP_SIGNER_DEFAULT`, and the other testnet-only keys. Remove refused keys from programmatic overlays too, and set needed values in the profile file. Then run `stellar-agent profile show --profile <name>` to confirm the file's chain and endpoint. Correct the profile file if either value differs from the intended configuration.

## `profile`

The `profile` group creates, lists, shows, and migrates profiles, and rotates the keyring-backed keys a profile names. A profile is a per-environment TOML config (schema version 2) binding a CAIP-2 chain id, an RPC endpoint, keyring entry references, thresholds, and the active policy engine. Wallet keys stay in the keyring, and the profile only names their entries. An endpoint URL can still embed a credential.

The eight key-writing commands (`enroll-signer`, `enroll-owner-key`, `enroll-rpc-credential`, and the five key-rotation subcommands) each write a `keyring_key_written` audit row recording the key purpose and, where applicable, the redacted public address. `enroll-signer` also writes a `signer_identity_enrolled` row, with the record's keyring coordinate, the redacted public address, and the role, after it writes the signer identity record; `enroll-signer --repair-identity` writes that row alone. `reset-window-state` writes the `keyring_key_written` row when the reset mints the window-state key on first use. `init` mints no key material and emits no audit row.

`profile list` lists all profile names and takes no profile selector. Every other `profile` subcommand accepts `--profile <NAME>`. `enable-mainnet` requires an explicit nondefault mainnet profile. For `init`, `enroll-signer`, `enroll-owner-key`, `enroll-rpc-credential`, and `sign-policy` it is the only form and resolves in the order the index documents: the flag, then `STELLAR_AGENT_PROFILE`, then `"default"`. For `show`, `migrate`, the `rotate-*` subcommands, `reset-window-state`, and `reset-mpp-state`, supply exactly one positional `<NAME>` or `--profile <NAME>`. These commands require an explicit selection. `reset-mpp-state` requires `--acknowledge`; the other profile verbs have no confirmation flag.

The name itself becomes a path component and is validated before any path is built — charset, length, no leading `-`, and no Windows reserved device name. The rules and the recovery path for a file that already carries a refused name are in [Profile names](../profiles.md#profile-names).

Every subcommand except `init`, `list`, `migrate`, and `show` also reconciles the selected name against the one the loaded file carries, refusing with `profile.name_mismatch` when the two disagree (see the [index](index.md#profile)). The key-writing commands are not exempt: `sign-policy` writes `<policy_dir>/<derived>.toml` and `enroll-owner-key` writes the `stellar-agent-owner-<derived>` keyring entry, so running either against a copied profile file would replace a DIFFERENT profile's root of trust. Neither is needed to repair a mismatch: the refusal names the recovery path, and `profile show <name>` still displays the file so the offending field can be read. `init` and `list` load no profile at all. `migrate` builds the v2 profile from the v1 file and the requested name, deriving the security-substrate key references from the name, not from the file's contents.

### `profile init`

```bash
stellar-agent profile init --profile default --network testnet
```

State-changing (writes the profile file; no network, no keyring). Creates and persists a new profile TOML with per-profile-derived keyring entry references, then reports the enrollment steps needed before the profile can sign. Mints no key material and emits no audit row — the key-writing commands documented below mint their own keys.

- `--profile <NAME>`: profile name to create (default: `STELLAR_AGENT_PROFILE`, else `default`). Loading a mainnet profile requires an explicit `--profile <NAME>`.
- `--network <testnet|mainnet>` — target network (default `testnet`).
- `--rpc-url <URL>`: optional on testnet, where an omitted value takes the testnet endpoint; required with `--network mainnet`, which has no default endpoint. The URL must use `http` or `https`, and `https` on mainnet. The flag parser refuses credentials.
- `--engine <v1|noop>`: policy engine (default `v1`). See the `[policy]` block in [profiles.md](../profiles.md). On a V1 profile, the MCP server starts once the owner key is enrolled and the owner-signed policy loads; the rest of the [V1 setup](../profiles.md#opt-in-to-v1) gates approvals and signing. For V1, `next_steps` adds `profile enroll-owner-key`, `profile rotate-attestation-key`, a step to [create the policy file](../profiles.md#create-the-v1-policy-file) `policies/<name>.toml`, then `profile sign-policy`. A testnet `noop` profile supports server startup and read access immediately. Mint the audit key with `profile rotate-audit-key` before `profile enroll-signer` so enrollment writes its audit row. Then run `profile rotate-nonce-key` before MCP payment simulation.

A mainnet profile is written with `classic_max_fee_per_op_stroops = 10000`.
A testnet profile is written without a cap.

CLI `pay` and `claim` check the cap in the full pipeline, `--build-only`,
`--sign-only`, and `--submit-only`. MCP pay, create-account, trustline, and
claim check it in both prepare and commit. CLI sponsored `accounts create`,
`trustline`, and every sending `pool init` path also check the cap.
Opaque, fee-bump, and multi-operation staged envelopes and the SEP-43 signing
tools remain outside this coverage.

The classic witness covers CLI `pay`, `claim`, sponsored `accounts create`,
`trustline`, and every sending `pool init` path. It also covers MCP
`stellar_pay_commit`, `stellar_create_account_commit`, `stellar_trustline_commit`,
and `stellar_claim_commit`. The x402 payment tools `stellar_x402_create_payment`
and `stellar_x402_authenticated_payment` are covered by a second simulation on
the oracle: before the payer signs, the oracle simulates the same unsigned
transfer, and the answers are compared. Opaque staged envelopes and the SEP-43
signing tools remain uncovered.

The signer and nonce keyring coordinates are named `stellar-agent-signer-<name>` / `stellar-agent-nonce-<name>`, each seeded with the placeholder account `"default"` — the signer's eventual G-strkey is not known until a seed is enrolled (see `profile enroll-signer` below). The five security-substrate references (`audit_log_hash_chain_key_id`, `policy_owner_key_id`, `attestation_key_id`, `counterparty_cache_key_id`, `policy_window_state_key_id`) are derived from the profile name the same way `profile migrate` derives them.

`init` writes the `audit_log_hash_chain_key_id` coordinate; `profile rotate-audit-key <name>` mints the key material. On both engines, `next_steps` lists `rotate-audit-key`, then `enroll-signer`, then `rotate-nonce-key`. The audit key must exist before the first key-writing command so its audit row is written. Every value-moving signing verb requires the audit key before signing or submitting, refusing `audit.chain_key_unavailable` otherwise. MCP payment simulation requires the commit-nonce key.

`init` refuses, without writing or modifying anything, if `<name>.toml` already exists; the write itself is no-clobber, so a file appearing concurrently is never overwritten either.

```json
{"ok":true,"data":{"profile":"default","path":"/home/user/.local/share/stellar-agent/profiles/default.toml","chain_id":"stellar:testnet","rpc_url":"https://soroban-testnet.stellar.org","engine":"v1","next_steps":["Run `stellar-agent profile rotate-audit-key default` to mint the audit-log hash-chain key (required before any signing verb will proceed).","Run `stellar-agent profile enroll-signer --profile default --secret-env <VAR>` to register the MCP signer seed.","Run `stellar-agent profile rotate-nonce-key default` to mint the commit-nonce key (required before MCP payment simulation).","Run `stellar-agent profile enroll-owner-key --profile default --secret-env <VAR>` to enroll the policy-file owner key.","Run `stellar-agent profile rotate-attestation-key default` to mint the approval-attestation key.","Create the V1 policy file `policies/default.toml` in the wallet's state directory, with `version = 1` and `scope = \"profile:default\"` (see \"Create the V1 policy file\" in the getting-started guide).","Run `stellar-agent profile sign-policy --profile default --secret-env <VAR>` to sign the V1 policy file."]},"request_id":"..."}
```

The flag parser refuses a malformed `--rpc-url`, or one that carries credentials, before the command runs: exit `1` with a `validation.usage_error` envelope whose message never repeats the rejected value. After the arguments parse, the refusals apply in this order:

1. `validation.config_invalid` if `--profile` is not a safe path component (see [Profile names](../profiles.md#profile-names)).
2. `validation.mainnet_rpc_url_required` if `--network mainnet` is selected without `--rpc-url`.
3. `validation.profile_already_exists` if the named profile already exists.
4. `validation.config_invalid` if the resolved `rpc_url` breaks the endpoint rule: it must use `http` or `https`, and on mainnet `https` with no username or password (see [Loader source order](../profiles.md#loader-source-order)).

Each exits `1` and writes nothing. A failed write (I/O error, unwritable directory) exits `1` with an internal error.

### `profile list`

```bash
stellar-agent profile list
```

Read-only. Reads the OS-conventional profile directory and returns the known profile names, sorted, as a JSON array. Takes no profile selector.

```json
{"ok":true,"data":["default","mainnet-ops"],"request_id":"..."}
```

### `profile show <NAME>`

```bash
stellar-agent profile show default
```

URL fields (`rpc_url`, `secondary_rpc_url`, `oracle_provider_url`) are printed as scheme, host, and port only.

Read-only. Loads the named profile (applying any environment-variable overlays) and prints its resolved configuration as a JSON envelope. Keyring entry references appear as opaque `{service, account}` objects; the secret material they name is never read or printed. Provider records print in full, including `credential` references and `placement`; the credential value is never read.

- `<NAME>` (positional) or `--profile <NAME>` — the profile to display. Supply exactly one; supplying both, or neither, is a usage error.

Exits `1` with `validation.profile_not_found` when the profile does not exist. A mainnet file without `rpc_url` exits with `validation.mainnet_rpc_url_required`. An invalid provider attestation exits with `validation.provider_attestation_invalid`; correct the named field in the profile file. An endpoint URL that breaks the endpoint rule (see [Loader source order](../profiles.md#loader-source-order)), an unsupported schema version, or another unreadable file exits with `validation.config_invalid`.

### `profile migrate <NAME>`

```bash
stellar-agent profile migrate default
```

State-changing (local file). Reads the named profile, applies any pending schema migrations, and writes the result atomically (temp-file plus rename). If the profile is already at the current version, the command is a no-op and the file is left untouched.

- `<NAME>` (positional) or `--profile <NAME>` — the profile to migrate. Supply exactly one; supplying both, or neither, is a usage error.

On a no-op it reports `status` `no_op` and the current version; on a migration it reports `status` `migrated` with `from_version`, `to_version`, and the file path:

```json
{"ok":true,"data":{"status":"no_op","version":2},"request_id":"..."}
```

```json
{"ok":true,"data":{"status":"migrated","from_version":1,"to_version":2,"path":"..."},"request_id":"..."}
```

A refused migration exits `1`, writes nothing, and leaves the v1 file unchanged:

- `validation.profile_not_found` if the profile file does not exist.
- `validation.mainnet_rpc_url_required` for a v1 mainnet file without `rpc_url`, because mainnet has no default endpoint. Add `rpc_url` to the v1 file and run the command again.
- `validation.config_invalid` for an endpoint URL that breaks the endpoint rule (see [Loader source order](../profiles.md#loader-source-order)), or for a file that cannot be read.

### `profile enroll-signer`

Run this line on its own, paste the signer seed when prompted, and press Enter. [Pass a secret seed](../getting-started.md#pass-a-secret-seed) covers other shells.

```bash
printf 'WALLET_SK seed: ' && read -rs WALLET_SK && echo && export WALLET_SK
```

```bash
stellar-agent profile enroll-signer --profile default --secret-env WALLET_SK
unset WALLET_SK
```

Imports an operator-held ed25519 seed into the profile's `mcp_signer_default`
keyring entry. MCP fund-movement tools and keyring-signing CLI verbs
(`trustline`, `trade`, `vault`) resolve this signer. On a clean install that
entry is absent, so those paths fail with `auth.keyring_not_found`.
This command populates the entry and updates the profile TOML on first signer
enrollment, without network access. It reads the seed from a named environment
variable through the shared mlock-protected ceremony and stores it verbatim.
The seed is never printed, logged, or returned.

- `--secret-env <VAR>` (required unless `--repair-identity`): name of the environment variable holding the signer's `S...` strkey. The flag takes the variable name, never the secret.
- `--profile <NAME>`: profile whose `mcp_signer_default` entry is written (default: `STELLAR_AGENT_PROFILE`, else `default`). Loading a mainnet profile requires an explicit `--profile <NAME>`.
- `--expected-address <G_STRKEY>` — refuse unless the seed derives to this address.
- `--force` — replace an already-enrolled entry (refused without it when one exists).
- `--repair-identity`: write only the signer identity record of an existing enrollment; see below. Excludes `--secret-env` and `--force`.

The coordinate's `account` field is the signer identity: `signer_from_keyring` verifies the loaded seed derives to it, so `account` must equal the seed's public address. Enrollment classifies the field from its raw on-disk value (environment overlays never influence what gets persisted) and resolves three cases. A profile fresh from `profile init`, or a v1-migrated profile, can hold the literal placeholder `"default"`. Enrollment pins the derived address into `account`, patching only that key in the profile TOML before writing the keyring entry. Once `account` holds a G-strkey, enrollment refuses on a mismatch and prints the address to set `account` to. The profile TOML is left untouched. Any other value (a typo'd or truncated pin) is refused with `enroll_signer.account_malformed` rather than replaced. Every refusal, including an unset secret variable, leaves the file unmodified. A keyring write that fails after the pin leaves the pinned address; a re-run retries the write. On success the data object reports the derived `public_address`, the `keyring_service`/`keyring_account` written, `replaced` (with `previous_address` when an entry was replaced), and `account_populated` (`true` when the placeholder was just pinned):

```json
{"ok":true,"data":{"profile":"default","enrolled":true,"public_address":"G...","keyring_service":"stellar-agent-signer-default","keyring_account":"G...","replaced":false,"account_populated":true,"identity_keyring_account":"enrolled-identity"},"request_id":"..."}
```

After the seed, enrollment writes the signer identity record `{"v":1,"public_key":"G...","role":"agent"}` at the same keyring service, account `enrolled-identity`. Mainnet authorization reads the enrolled key from this record, never from the seed. Success is reported only after the record is written. When that write fails, the seed and the pin stay as written and the command exits `1` with `profile.enroll_signer_identity_incomplete`, naming the repair below. A `--force` replacement removes the old record before it writes the seed. If the removal succeeds and the seed write fails, the command exits `1` with the same code and leaves the seed coordinate unchanged. A previous seed kept there can be repaired with the repair below when it derives to the pinned address, or replaced by a re-run with `--force`. With no previous seed, a plain re-run enrolls. When the removal finds no record, a failed seed write reports its keyring error code.

`--repair-identity` writes the record for an existing enrollment. It loads the stored seed, requires it to derive to the pinned `mcp_signer_default.account`, and writes only the record; the seed and the profile file are never written. A record that already names the pinned key is left as it is, and the command reports `written: false`. A stored record that names another key, another role, or contains malformed data refuses with `enroll_signer.identity_conflict` and is left as it is; remove that entry, then run the repair again. A keyring read failure retains its keyring error code.

```bash
stellar-agent profile enroll-signer --profile default --repair-identity
```

```json
{"ok":true,"data":{"profile":"default","public_address":"G...","keyring_service":"stellar-agent-signer-default","keyring_account":"enrolled-identity","written":true},"request_id":"..."}
```

Exits `1` on refusal:

- `validation.profile_not_found`: the profile does not exist.
- `enroll_signer.account_identity_mismatch`: the seed does not match a pinned signer account.
- `enroll_signer.account_malformed`: the stored account is neither the placeholder nor a valid G-strkey.
- `enroll_signer.expected_address_mismatch`: `--expected-address` does not match.
- `enroll_signer.entry_exists`: an entry exists without `--force`.
- `profile.enroll_signer_identity_incomplete`: the run ended without an identity record. Either the seed was enrolled and the record write failed, or a `--force` replacement removed the record and the seed write failed.
- `enroll_signer.repair_unpinned`: `--repair-identity` on a profile that pins no signer address.
- `enroll_signer.identity_conflict`: `--repair-identity` found a different identity record.
- `auth.signer_key_mismatch`: `--repair-identity` found a seed that does not derive to the pinned address.
- A keyring error: the platform keyring is unavailable, or `--repair-identity` found no stored seed.

Mainnet requires the signer identity to be enrolled, including when a command
selects `--secret-env` or Ledger. `profile enroll-signer` accepts `--secret-env`
only. A Ledger key cannot be enrolled as the mainnet signer.
`auth.enrolled_identity_unusable` identifies an unusable enrolled proof.

### `profile enroll-rpc-credential`

```bash
stellar-agent profile enroll-rpc-credential --profile default --role primary --header X-API-Key
```

Stores an RPC provider key in the keyring for one provider role and names it in the role's provider record. Without `--stdin`, the command prompts for the key on the terminal without echo and writes the prompt to standard error. With `--stdin`, it reads the key from standard input and removes one trailing line end. The key is never printed, logged, or written to the audit row.

- `--role <primary|secondary|oracle>` (required): the provider role.
- `--header <NAME>`, `--query <NAME>`, or `--path`: where requests carry the key; see [Provider credentials](../profiles.md#provider-credentials). Required when the record names no placement; when it names one, a flag must equal it.
- `--stdin`: read the key from standard input.
- `--force`: replace a key already stored at the entry.
- `--profile <NAME>`: the profile (default: `STELLAR_AGENT_PROFILE`, else `default`). Loading a mainnet profile requires an explicit `--profile <NAME>`.

The role's endpoint URL and its provider record must already be in the profile file. The entry is the record's `credential`, or the default `stellar-agent-rpc-<profile>` / `<role>` when the record names none. Before anything is written, the command runs the loader's credential checks on the record it would write, against the role's endpoint URL. It then refuses an existing entry without `--force`, before reading the key. The key is at most 1024 bytes and holds no control character. A record without a reference gains `credential` and `placement` before the keyring write, and nothing else in the file changes. A file with mixed line endings is written with LF endings. A keyring write that fails after that leaves the record patched; a re-run retries the write.

```json
{"ok":true,"data":{"profile":"default","role":"primary","keyring_service":"stellar-agent-rpc-default","keyring_account":"primary","placement":{"kind":"header","name":"X-API-Key"},"replaced":false,"record_patched":true},"request_id":"..."}
```

Exits `1` on refusal. Every refusal before the keyring write leaves the file and the keyring unchanged:

- `enroll_rpc_credential.record_missing`: the role has no endpoint URL or no provider record.
- `enroll_rpc_credential.placement_required`: neither the record nor a flag names a placement.
- `enroll_rpc_credential.placement_mismatch`: the flag differs from the record's placement.
- `validation.provider_attestation_invalid`: the record would break a loader rule; the message names the field.
- `enroll_rpc_credential.entry_exists`: a key is stored at the entry and `--force` is absent.
- `enroll_rpc_credential.terminal_required`: standard input is not a terminal and `--stdin` is absent.
- `enroll_rpc_credential.input_unreadable`: the input could not be read, or the standard input is not UTF-8 text.
- `network.rpc_credential_refused`: the key is empty, longer than 1024 bytes, or holds a control character.
- A keyring error: the platform keyring is unavailable or refused the write.

### `profile enroll-owner-key`

Run this line on its own, paste the owner seed when prompted, and press Enter:

```bash
printf 'WALLET_OWNER_SK seed: ' && read -rs WALLET_OWNER_SK && echo && export WALLET_OWNER_SK
```

```bash
stellar-agent profile enroll-owner-key --profile default --secret-env WALLET_OWNER_SK
unset WALLET_OWNER_SK
```

Enrolls the policy-file owner PUBLIC key into the profile's `policy_owner_key_id` keyring entry, the key the V1 policy engine verifies every policy file against. The owner key is the root of trust for policy: whoever can sign a policy file can authorize any action the policy permits. `enroll-owner-key` and `sign-policy` read the owner seed from the environment of the shell that runs them. Supply it with the read line only for those commands, as [Pass a secret seed](../getting-started.md#pass-a-secret-seed) describes, and unset it afterward. Of the policy owner key, the MCP server holds only the enrolled public key. It reads no seed from its environment. State-changing (keyring), no network. The command passes the seed through the shared mlock-protected ceremony, stores only the derived public key, and never prints, logs, or returns the seed.

- `--secret-env <VAR>` (required) — name of the environment variable holding the owner `S...` strkey. The flag takes the variable name, never the secret.
- `--profile <NAME>`: profile whose owner coordinate is written (default: `STELLAR_AGENT_PROFILE`, else `default`). Loading a mainnet profile requires an explicit `--profile <NAME>`.
- `--expected-address <G_STRKEY>` — refuse unless the seed derives to this address.
- `--force`: replace an enrolled owner key. When an enablement nonce or a policy pin exists at the profile's window-state entry, or an enablement nonce exists at its default entry (`stellar-agent-policy-window-<NAME>` / `default`), whatever chain the profile file names, a key other than the pinned owner requires an installed policy signed by that key with a valid statement from the pinned owner. Enrolling the pinned owner's key needs no statement and restores a lost owner entry.

The owner coordinate's `account` is the literal `"default"` (the value the engine reads); the stored value is the public key's G-strkey. A G-strkey decodes as URL-safe base64 to 42 bytes, so no 32-byte symmetric-key loader accepts it. Owner readers accept only the G-strkey form. Older base64 entries stay unchanged and refuse until the owner public key is enrolled again. Under `headless-dpapi`, enroll the owner public key again after upgrading: an older-form entry can be moved to a symmetric-key coordinate. On success the data object reports the derived `owner_address`, the `keyring_service`/`keyring_account` written, and `replaced`. The prior key's stored value is never decoded or reported. A prior entry at this coordinate may have held an owner seed in the older encoding, so rendering it could print a private key. `replaced: true` conveys that a prior entry existed.

```json
{"ok":true,"data":{"profile":"default","enrolled":true,"owner_address":"G...","keyring_service":"stellar-agent-owner-default","keyring_account":"default","replaced":false},"request_id":"..."}
```

Exits `1` on refusal:

- `validation.profile_not_found`: the profile does not exist.
- `enroll_owner_key.expected_address_mismatch`: `--expected-address` does not match.
- `enroll_owner_key.entry_exists`: an owner key exists without `--force`.
- `enroll_owner_key.rotation_statement_required`: the installed policy lacks a valid previous-owner statement or a signature from the key being enrolled. The message names the cause (`policy.owner_rotation_required`, `policy.owner_rotation_invalid`, or `policy.owner_signature_invalid`).
- `policy.pin_absent`: the installation holds a mainnet enablement nonce or a policy pin, but its policy-state lock file or its pin is missing. The message names which one. A command that builds the V1 policy engine recreates a missing lock file. For a missing pin, follow the recovery under [`profile enable-mainnet`](#profile-enable-mainnet).
- `profile.mainnet_enablement_invalid`: the enablement nonce cannot be read.
- `policy.state_lock_busy`, `policy.state_lock_io`, `policy.pin_unusable`, and the verified-load codes such as `policy.sequence_rollback` or `policy.policy_file_load_failed` keep their own codes.
- A keyring error: the platform keyring is unavailable.

Each refusal writes no owner entry.

### `profile sign-policy`

Run this line on its own, paste the owner seed when prompted, and press Enter:

```bash
printf 'WALLET_OWNER_SK seed: ' && read -rs WALLET_OWNER_SK && echo && export WALLET_OWNER_SK
```

```bash
stellar-agent profile sign-policy --profile default --secret-env WALLET_OWNER_SK
unset WALLET_OWNER_SK
```

Signs a v1 or v2 policy file so the engine accepts it. The engine loads `<state_dir>/policies/<profile>.toml`, recomputes the canonical form (the `[signature]` table excluded), and verifies the signature against the enrolled owner public key. This command produces that `[signature]` table: it computes the same canonical BLAKE3 digest the loader computes, signs it with the owner seed, and writes `owner_id` (the owner G-strkey) and `sig` (hex) back into the file. State-changing (writes the policy file), no network. The owner seed is read from a named environment variable and held only in zeroizing memory; it is never printed, logged, or written to disk.

- `--secret-env <VAR>` (required) — name of the environment variable holding the owner `S...` strkey.
- `--previous-owner-secret-env <VAR>`: authorize rotation with the previous seed through the same mlock-protected ceremony. `--secret-env` supplies the new owner seed. The previous seed must match the pinned owner, or the enrolled owner when no pin exists.
- `--profile <NAME>`: profile whose policy file is signed (default: `STELLAR_AGENT_PROFILE`, else `default`). Loading a mainnet profile requires an explicit `--profile <NAME>`.
- `--file <PATH>` — sign a policy file at a non-default path (default `<state_dir>/policies/<profile>.toml`, the only location the engine loads).

Without the rotation flag, the seed's derived public key is cross-checked against the enrolled owner key; a seed that does not match is refused (`sign_policy.owner_key_mismatch`) so a file the engine would reject is never produced. Before signing, the command also checks the body as the engine loads it, with the `scope` compared against the profile, and refuses a body the engine would reject. A refusal leaves the file unchanged. Mismatch errors identify stored owner bytes by a domain-separated SHA-256 fingerprint. They show the derived address and fingerprint; a previous owner from a verified pin keeps its address. Signing does not require a valid previous signature: re-signing a file with a stale or malformed `[signature]` table replaces that table in place, dropping any extra key in it, and reports `replaced: true` with the previous `owner_id`. On success the data object reports the `owner_address`, the `policy_path`, the `digest` (hex), and the `signature` (hex):

```json
{"ok":true,"data":{"profile":"default","signed":true,"owner_address":"G...","policy_path":".../policies/default.toml","digest":"<hex>","signature":"<hex>","replaced":false},"request_id":"..."}
```

Exits `1` on refusal:

- `validation.profile_not_found`: the profile does not exist.
- `sign_policy.owner_key_older_form`: enroll the owner public key again with `profile enroll-owner-key --force`.
- `sign_policy.owner_key_unavailable`: no owner key is enrolled; run `enroll-owner-key` first.
- `sign_policy.owner_key_mismatch`: the seed does not match the enrolled owner key, or the previous seed does not match the pinned owner (the enrolled owner when no pin exists).
- `sign_policy.policy_file_unreadable`: the policy file is missing.
- `sign_policy.canonicalization_failed`: the policy file is malformed, or its
  body holds a key outside the policy schema. The message names the key and
  its location.
- `sign_policy.policy_body_invalid`: the engine would refuse the policy body,
  for example an unsupported `version`, a `scope` for another profile, an
  unknown criterion kind or decision, or a `ttl_secs` out of range. The message
  carries the engine's detail.
- A keyring error: the platform keyring is unavailable.

The signature covers each rule's `reason`, `ttl_secs`, and
`allow_opaque_signing` when the rule carries them. When the signature does not
verify over the policy and rules carry these keys, the message names those
rules and asks you to review the policy and re-sign it with this command.
A `sig` value that is not 64 bytes of hex is refused without rule indexes.

For v2, signing assigns `sequence = max(pin, body) + 1` and returns
`sequence` and `previous_sequence`. An unsigned body may omit its sequence;
signing treats it as zero. Signing reads the pin under the state lock and
never advances it. It creates no window-state directory or lock file; when
the lock file is absent, it reads no pin. Loading a verified v2 policy
advances it.

A v1 policy on mainnet produces a warning that writes require v2 with
`[mainnet]`. If a pin exists, signing v1 also warns that its next load refuses
with `policy.sequence_rollback`.

To change the owner of a profile with a policy pin, follow
[Rotate the policy owner](../profiles.md#rotate-the-policy-owner).

Additional refusals:

- `sign_policy.sequence_exhausted`: the previous maximum is `i64::MAX`.
- `policy.mainnet_table_on_testnet`: a testnet profile carries `[mainnet]`.
- `policy.mainnet_minimum_unmet`: an enabled mainnet policy omits a restriction.
  A `[mainnet]` table without `approval_credentials` refuses with
  `requirement=approval_credentials` in either build.
- `sign_policy.canonicalization_failed` also reports an empty or malformed
  `approval_credentials` list with a fixed detail, such as
  `mainnet.approval_credentials contains an invalid P-256 public key`.
- `policy.state_lock_busy`: another writer holds the lock through three attempts.
- `policy.state_lock_io`: the lock file cannot be opened; the detail gives the I/O kind.
- `policy.pin_unusable`: the installation's policy pin cannot be read or is malformed.

Signing does not check owner continuity. The verified load that follows
refuses a signed policy with `policy.pin_absent` when the installation holds
an enablement nonce but no pin, with `policy.owner_rotation_required` when a
higher sequence changes the pinned owner without a rotation statement, and
with `policy.owner_rotation_invalid` when the statement names other keys or
its signature does not verify for this body.

After signing an enabled mainnet policy, restart the MCP server. A stale
startup binding refuses with `network.mainnet_write_forbidden` and
`enablement or policy changed, restart the server`. Missing startup authority
names its missing prerequisite instead. A mainnet approval recorded under the
previous policy needs fresh consent.

### `profile enable-mainnet`

```bash
stellar-agent profile enable-mainnet --profile operator
stellar-agent profile enable-mainnet --profile operator --check
stellar-agent profile enable-mainnet --profile operator --rotate
```

Requires an explicit, nondefault mainnet profile, matching stored and merged
chain and RPC URL, engine v1, an enrolled owner key and signer identity, an
oracle, and no key-scope findings. A profile without `oracle_provider_url` is
refused with `profile.mainnet_oracle_required` before any keyring entry is
read, and no nonce, pin, policy change, or audit row is written. A profile
that sets `oracle_provider_url` without its `providers.oracle` record does not
load, and the ceremony refuses it with `profile.enable_mainnet_precondition`
and the loader's message.
An enabled profile whose oracle is removed refuses every mainnet write, in the
CLI and in the MCP server, with `profile.mainnet_oracle_required` before any
signature, until the oracle is set again. The MCP server reads the profile at
startup, so it applies an oracle change from its next start. A process on a headless keyring backend
(`STELLAR_AGENT_KEYRING_BACKEND` set to `headless-env` or `headless-dpapi`)
is refused in every mode with `network.mainnet_keyring_backend_unsupported`
before any keyring entry is read: mainnet needs the platform keyring.
Before the first nonce is written, a signed v2 policy
establishes the pin with its verified sequence, digest, and owner.
Create and sign that policy before running the ceremony; it may omit `[mainnet]`.
A v1 policy refuses with `profile.enable_mainnet_precondition` and
`sign a v2 policy before enabling mainnet`; an unsigned policy refuses with
`policy.policy_file_parse_failed`. Neither writes a nonce, pin, or audit row.
An existing pin stays in place, including during nonce rotation.
The ceremony records `mainnet_enablement_minted` through the
strict audit writer, stores an installation nonce, then atomically rewrites
the policy with the profile, normalized endpoint host, and nonce digest.
The operator supplies the fee cap, optional authorization
TTL, thresholds, and at least one approval credential from
`approve credential enroll`, then signs the policy as the output's `next`
list directs.

See [the policy schema and minimum](../profiles.md#mainnet-policy-body) for
required signed fields and rules. After enablement, complete and sign the
policy, run `--check`, and restart the MCP server.

Binding failures name `mainnet_table`, `profile`, `source`, `default`, `on_disk`,
`chain_id`, `on_disk_host`, `merged_host`, or `nonce_digest`. The signed policy
field remains `endpoint_host`. Unreadable stored `chain_id` or `rpc_url`
reports `profile chain and endpoint unreadable` with the path and cause.

`--rotate` replaces the nonce and changes only the policy's nonce digest.
The old nonce is gone; sign the updated policy before using its binding.
On a policy without a `[mainnet]` table, `--rotate` binds in full, as the
first run does. This recovers a run that stored the nonce but could not
rewrite the policy. In a build without `mainnet-write`, the `next` list adds
that writes require such a build.

An installation that holds a nonce but no pin refuses every mainnet write,
and the ceremony refuses it with `policy.pin_absent`, with and without
`--rotate`, before writing anything: no wallet command establishes the pin of
an enabled installation. To recover, remove the keyring entry with service
`stellar-agent-policy-window-<NAME>` and account `default-mainnet-enablement`
with the platform keyring tool, such as Keychain Access on macOS, Seahorse on
Linux, or Credential Manager on Windows. Then run
`profile enable-mainnet --profile <NAME>`: it pins the installed signed
policy and stores a new nonce. Sign the rebound policy at a higher sequence;
mainnet writes stay refused until then. That enablement trusts the installed
signed policy and its owner, as the first enablement of a new installation
does, so review the installed policy and the enrolled owner key first.
When only the policy-state lock file is missing and the pin entry exists,
the refusal names the lock file instead: a command that builds the V1 policy
engine, such as starting the MCP server, recreates it, and the nonce stays.

`--check` reports every check with the status `passed`, `failed`, or
`not_evaluated` and a detail, and exits `1` when any check failed. The checks
are the preconditions, `verified_policy`, `pin`, `enablement`, every minimum
restriction in either build, and `oracle_provider_url`. A policy without
approval credentials fails `verified_policy` with
`requirement=approval_credentials`. The last fails when
the profile names no oracle, and its detail names what is missing. `--check`
reads the prerequisite state, keyring entries included, and writes no nonce,
pin, policy change, or audit row.
The restrictions are evaluated on the
document the verified load read. Without a `[mainnet]` table the fee cap and
every table restriction fail. When the policy does not verify, the
restrictions and `enablement` are `not_evaluated`. The `enablement` check
fails with `profile.mainnet_enablement_invalid` and the name of the binding
that does not match, such as `on_disk_host` or `nonce_digest`. The `pin`
check passes with the pinned sequence, or with `absent (first use)` when no
pin or window-state lock file exists and no enablement nonce exists.
An enablement nonce with no pin refuses with `policy.pin_absent`.
It fails when the pin cannot be read or
the comparison refuses, with `policy.sequence_rollback`,
`policy.sequence_fork`, `policy.owner_rotation_required`,
`policy.owner_rotation_invalid`, or the lock or pin error in its detail.
`--check` creates and changes nothing: no window-state directory or lock
file, and no policy, owner key, nonce, pin, or audit row.

Exits `1` on refusal:

- `profile.enable_mainnet_profile_flag_required`: supply `--profile`.
- `profile.enable_mainnet_default_refused`: select a dedicated profile.
- `profile.enable_mainnet_not_mainnet`: the selected chain is testnet.
- `profile.enable_mainnet_precondition`: a named precondition or effect failed.
- `profile.enable_mainnet_nonce_exists`: rerun with `--rotate` to replace the nonce.
- `policy.pin_absent`: the installation holds a nonce but no pin; see the recovery above.
- Strict audit errors retain their own codes.

### Key-rotation subcommands

The MCP server acquires its audit writer when an operation needs it, such as a commit preflight before signing. MCP balance reads do not acquire it. Under V1, payment simulations can reconcile overdue reservations, acquire the writer, and write settlement audit rows.

The registry normally caches the writer and holds its lock until process exit. A replaced-file refusal during acquisition marks the cached writer for eviction. After callers release it, the next acquisition drops it and checks the file at the path against the anchor.

While held, the lock blocks rotation with `audit.writer_locked` in the error
detail, even if the operation that acquired it later fails.

Each rotation subcommand generates a fresh 32-byte secret from the OS CSPRNG, encodes it as URL-safe base64 (no padding), and atomically replaces one keyring entry the profile names. The raw bytes never leave the keyring, are never logged, and are never returned. Every rotation subcommand takes the profile as either a positional `<NAME>` argument or a `--profile <NAME>` flag — exactly one of the two, and supplying both, or neither, is a usage error — changes keyring state (no network), and is not reversible. Rotate deliberately, because each one invalidates material minted under the old key. (The policy-file owner ed25519 key is not rotated here; it is enrolled with `enroll-owner-key`.)

| Subcommand | Keyring entry rotated | Key kind | Effect on outstanding material |
|---|---|---|---|
| `rotate-attestation-key` | approval-spine attestation HMAC key (`attestation_key_id`) | 32-byte HMAC | All pending approvals are invalidated; the simulate-and-approve round trip must be re-run. |
| `rotate-audit-key` | audit-log chain-root HMAC key (`audit_log_hash_chain_key_id`) | 32-byte HMAC | Rotation re-signs every existing per-file chain-root sidecar with the new key. `audit verify` passes under the new key, and the old key stops verifying. Takes the audit writer's exclusive lock, so it refuses while an MCP server holds that writer, and checks the tip anchor before touching the key. Checks the audit binding before it opens the writer: a changed binding refuses with `audit.log_binding_changed` and creates nothing at the path the profile names; an absent one is recorded. Mints a key only where no entry exists: a stored key it cannot read or decode refuses before anything is written, with the read failure's code or `internal.unexpected_state` (`audit.key_decode_failed`, `audit.key_length_error`). Investigate; if the stored audit key is corrupt, remove that keyring entry with the platform keyring tool, run `rotate-audit-key` to mint a new key, and run `audit reanchor --acknowledge-rollback` if the log's anchor is gone (see [Audit-log recovery](../maintainers/audit-log-recovery.md#10-unreadable-or-undecodable-audit-key)). |
| `rotate-nonce-key` | HMAC nonce key (`mcp_nonce_key_alias`) | 32-byte HMAC | All outstanding nonces minted with the old key are invalidated. |
| `rotate-policy-state-key` | policy-window-state HMAC key (`policy_window_state_key_id`) | 32-byte HMAC | The persisted window-state store is re-signed under the new key, so accumulated `per_period_cap` / `rate_limit` history is preserved, not invalidated. Rotation is refused if the store file does not verify under the current key (run `reset-window-state` instead). |

All of the above mint raw 32-byte HMAC keys.

```bash
stellar-agent profile rotate-attestation-key default
stellar-agent profile rotate-audit-key default
stellar-agent profile rotate-nonce-key default
stellar-agent profile rotate-policy-state-key default
```

Each returns the profile name and a `rotated` flag. The attestation-key and audit-key paths additionally report a `key_kind` (`hmac_32_bytes`); the audit-key path also reports `sidecars_resigned`, the count of per-file chain-root sidecars re-signed with the new key. `rotate-nonce-key` returns only `profile` and `rotated`:

```json
{"ok":true,"data":{"profile":"default","rotated":true,"key_kind":"hmac_32_bytes"},"request_id":"..."}
```

```json
{"ok":true,"data":{"profile":"default","rotated":true,"key_kind":"hmac_32_bytes","sidecars_resigned":2},"request_id":"..."}
```

A further rotation subcommand, `profile rotate-counterparty-key <NAME>`, rotates the `stellar.toml` cache-integrity HMAC key (`counterparty_cache_key_id`); it invalidates every cached counterparty binding. `counterparty refresh <domain>` rewrites the binding for that domain, and `counterparty warm-up` refreshes only the `HOME_DOMAIN` entries of the policy allowlist. Its data object adds `"key_kind": "hmac_32_bytes"` and `"cache_invalidated": true` to the `profile` and `rotated` fields. This rotates the same keyring entry as `stellar-agent counterparty rotate-hmac-key` (see [core operations](stellar-ops.md)); the two verbs are interchangeable.

Each rotation exits `1` with `validation.profile_not_found` if the profile does not exist, or with a keyring error if the platform keyring is unavailable.

The counterparty cache reads and mints its HMAC key at
`counterparty_cache_key_id`, the entry `profile rotate-counterparty-key` writes.
With an explicit reference, previously cached entries read as absent until
a refresh rewrites them. `counterparty refresh <domain>` rewrites the entry
for that domain. `counterparty warm-up` refreshes only the `HOME_DOMAIN`
entries of the policy allowlist.

Keyring references also pass the [profile key-scope check](../profiles.md#file-location-and-selection).
It refuses mainnet conflicts with `profile.key_scope_conflict` and warns on testnet.

### `reset-window-state <NAME> --reason <REASON>`

`profile reset-window-state` clears persisted policy-window history after
recovery from corruption or rollback. Stop the MCP server and repair the audit
log first. The command requires a usable keyed audit writer on every network,
including testnet. It acquires that writer before the window-store lock and
writes the reset row before minting a key, advancing the generation or replacing
the store. A reset whose row cannot be written does not happen.

An installation with a mainnet enablement nonce requires `--owner-secret-env <VAR>`
in every build, whatever chain the profile file names. The variable holds the
pinned policy owner's `S...` strkey; the flag takes its name, never the secret.
The seed is unlocked before audit acquisition. The nonce and pin are checked
under the window-store lock. A pin alone does not require the flag.
When supplied, the seed must match the pin even without an enablement nonce.

Missing owner authorization refuses with `profile.reset_window_state_owner_required`.
A different seed refuses with `profile.reset_window_state_owner_mismatch`.
A supplied seed without a pin refuses with `policy.pin_absent`; an unreadable
pin refuses with `policy.pin_unusable`. These refusals write no reset row and
change no store, generation or key. Seed input errors report
`validation.secret_env_not_set`, `validation.secret_env_invalid` or
`wallet_state.unlock_failed` before acquiring either writer or store lock.

With the flag, the row adds `owner_authorization`: a redacted owner,
`store_sha256` (lowercase hex, or null for a missing file), and a 128-character
lowercase hex signature. The pinned owner signs `window_reset_digest` over the
profile, chain, store digest, generation pair, bounded recorded reason and
request id. The recorded reason is bounded to 80 Unicode characters before
signing, and the signed and recorded bytes are identical.
A reset without the nonce or flag omits this field.

The reset requires a current tip anchor before and after its row. If repair
fails, `audit.chain_key_unavailable` carries `audit.tip_anchor_unavailable`,
and the window state and generation remain unchanged. A reset row can therefore
describe an attempted reset that did not take effect.

The `policy_window_state_reset` row carries the profile's chain, reason and
`wiped` record. The JSON result carries the same record. A verified store reports
live confirmed and pending counts and totals, scope specificity, bucket and
window, plus generations before and after. Pending records count regardless of
age. At most eight buckets appear, with bounded identifiers and a truncation flag;
the entry count covers all live records. Missing or unverifiable stores report
no totals. A store is unverifiable when its file fails its HMAC, does not parse,
breaks the supported format's invariants, or holds an authentic older generation.
It is also unverifiable without a usable key: an absent key, a key that is not
valid base64, or a key that is not 32 bytes. The reset replaces such a key after
the row. A store file that exists but cannot be read refuses before the row.
An authenticated newer format version refuses on every chain with
`profile.reset_window_state_newer_version` and changes nothing; use the build
that wrote it. The reset releases expired authorizations in memory before it
writes the row.

A running MCP server holds the audit writer. Reset then refuses with
`audit.chain_key_unavailable` and the message sub-code `audit.writer_locked`.
An append failure also refuses with its audit code, leaving the window file,
key and generation untouched. A first-use key mint is recorded through the held
writer after the reset row, including when the later store write fails.

A failure after the row but before the generation write leaves the store
unchanged; the row's `generation_after` exceeds the keyring generation.
After the generation write but before the file write, the generation matches
the row while the old body remains. Its next load refuses a generation mismatch.
Rerun reset after repairing the audit log and stopping the MCP server.
The reset is complete when the next command that opens the window store loads
the empty store at `generation_after`. On a V1 profile, a value-moving command
and the MCP server's start open it. Generation equality alone does not establish
completion.
A blank `--reason` refuses with `validation.reason_empty` before anything changes.

A reset row without `wiped` or `owner_authorization` retains its serialized form
and verifies unchanged. A row with either field verifies with this release or
later. An older binary drops both fields when computing the row hash. It refuses
a log once a checked root HMAC, successor row or tip anchor covers the new row.
An uncovered tail can still be read by that binary with both fields dropped.
If it then appends a row, this release refuses the extended log at that row.

```bash
stellar-agent profile reset-window-state default --reason "store file corrupted after disk failure"
stellar-agent profile reset-window-state operator --reason "store file corrupted after disk failure" --owner-secret-env WALLET_OWNER_SK
```

### `reset-mpp-state <NAME> --acknowledge --reason <REASON>`

Recovers MPP authorization state after rollback or an unrecoverable generation
mismatch. Supply exactly one of positional `<NAME>` or
`--profile <NAME>`. Both `--reason <REASON>` and `--acknowledge` are required.

The acknowledgement keeps every record of the state file on disk when it
authenticates, and closes charges not yet committed as `expired_unresolved`.
Authorized, indeterminate, and settled statuses survive. Reset holds the MPP
store lock, keeps the key, and publishes the carried history above both
generation counters. A state file rolled back to an older copy before the reset
loses the records written after that copy. When the generation counter proves
the rollback, the result sets `stale_carry` and names it in one `warnings` line.

When no snapshot authenticates, reset discards every replay marker, rotates the
key, removes the file, sets the committed counter to zero, deletes the intent,
and publishes an empty store. A charge settled before that discard loses its
settled status. A stale carry and a discard both refuse, with
`mpp.challenge_expired`, every challenge that expires no later than five minutes
after the reset, which covers every charge whose record the reset could not
keep. A
keyring access error, a file read error, or a state path that is not a regular
file refuses the reset before its audit row and changes nothing.

Reset requires a usable audit log and writes `mpp_state_reset` with the
profile, discarded generation, carried generation, stale flag, and reason before
mutation. The result adds `carried_records`, `carried_generation` (null on a
discard), `stale_carry`, and `warnings`. An absent or malformed committed
counter has a null discarded generation. A failed reset can be retried with
acknowledgement; each attempt records its request. A blank or whitespace-only
`--reason` exits `1` with `validation.reason_empty` before anything changes.

A discarding reset row has no `carried_generation` and retains its serialized
form. A carrying row adds `carried_generation`, and `stale_carry` when it is
true; it verifies with this release or later. An older binary drops those
fields when computing the row hash, with the same consequences as for the
`wiped` field of `reset-window-state`.

```sh
stellar-agent profile reset-mpp-state default --acknowledge --reason "MPP state recovery"
stellar-agent profile reset-mpp-state --profile default --acknowledge --reason "MPP state recovery"
```

Verified version 1 MPP state is adopted automatically on open and records
`mpp_state_adopted`, so an upgrade keeps its replay history. A profile whose
state key was minted but which never stored a charge has no history to adopt
and refuses with a missing anchor; resetting it discards nothing.

## `credentials`

The `credentials` group manages the WebAuthn passkey lifecycle for a profile. Passkeys are stored in a per-profile registry that holds only public metadata: credential name, a redacted credential ID, RP-ID, transports, and a registration timestamp. The private key never leaves the authenticator. Registered passkeys can be installed as WebAuthn signers on a context rule (see the `smart-account` commands).

Two flags are common to every subcommand:

- `--profile <NAME>` — the profile whose passkey registry to use. Optional; resolves from `--profile`, then `STELLAR_AGENT_PROFILE`, then `"default"`.
- `--rp-id <DOMAIN>` — the WebAuthn relying-party ID. Default `localhost`, the correct loopback value for a local wallet. For a self-hosted deployment, set the deployment domain (for example `wallet.example.com`). The RP-ID must be a valid DNS domain string; IP literals are rejected by browser WebAuthn implementations. Changing the RP-ID after registration renders existing passkeys unusable.

`credential_id` values are redacted to first-five-last-five base64url everywhere they are printed.

Every subcommand's failure `error.code` is one of a closed set: the verb-specific codes noted under each subcommand below, plus these codes shared across the whole group: `credentials.invalid_profile_name` (any subcommand given a malformed `--profile`), and, from the underlying `CredentialsError`, `credentials.not_found`, `credentials.duplicate_name`, `credentials.invalid_name`, `credentials.io_error`, `credentials.registry_parse_failed`, `credentials.registry_serialise_failed`, `credentials.state_dir_unavailable`, `credentials.approval_store_error`, `credentials.approval_store_unavailable`, `credentials.bridge_start_failed`, `credentials.bridge_shutdown_failed`, `credentials.atomic_write_failed`, `credentials.signing_failed`, `credentials.missing_public_key`, `credentials.malformed_public_key`, `credentials.registration_confirmation_mismatch`, `credentials.registration_confirmation_expired`, `credentials.audit_write_failed`, and a generic `credentials.error` fallback for any other internal variant. `add-passkey` additionally emits `credentials.registration_tty_required`, `credentials.registration_confirmation_canceled`, `credentials.approval_store_dir_unavailable`, `credentials.approval_store_open_failed`, and `credentials.unknown_registration_outcome`, plus the audit refusals `audit.chain_key_unavailable`, `audit.log_binding_changed`, `audit.tip_anchor_mismatch`, and `audit.tip_anchor_missing`. An agent can switch on `error.code` alone; `error.message` carries the human-readable detail only.

### `credentials add-passkey <NAME>`

State-changing (writes the registry; performs a browser WebAuthn ceremony). The command requires terminals on stdin and stderr for the confirmation code. Without both terminals it exits `1` with `credentials.registration_tty_required`. It also requires the profile's keyed audit writer. If the audit chain key, audit binding or tip anchor is not in order, it refuses with the matching `audit.*` code before the ceremony starts.

The command prints the wallet-owned bridge registration URL to stderr and opens it in the OS default browser. It polls the approval store until the bridge accepts the browser's response or the deadline elapses. The bridge verifies the response against the challenge it served on the page, the page's exact origin and the relying-party ID. It checks user presence and verification, and matches the posted credential ID and key against the authenticator's response. Once the bridge accepts the response, the page shows a confirmation code. The command asks for it at the terminal until the same deadline. Nothing is registered until the code typed at the terminal matches. The command then writes the `passkey_registered` audit row, followed by the credential metadata in the registry. A wrong code exits `1` with `credentials.registration_confirmation_mismatch`. The deadline at the prompt gives `credentials.registration_confirmation_expired`; end of input or Ctrl-C gives `credentials.registration_confirmation_canceled`. None of these refusals registers anything.

The browser opens through a private redirect file that only the current user can read. The browser launcher receives only that file's address, never the registration URL. The file is removed when the browser phase ends. If the browser cannot be launched, or does not show the page, open the printed URL yourself; polling continues either way. Anyone with the URL can attempt registration while the bridge accepts it. Registration requires the code from the operator's own page to match the code typed at the terminal. Keep the URL out of shared logs. Ctrl-C during polling stops the bridge, removes the redirect file, and exits `1` with `credentials.registration_user_canceled`.

- `<NAME>` (positional, required) — a name for the credential. 1 to 64 printable ASCII characters; `/`, `\`, and `:` are not allowed.
- `--profile <NAME>` — profile override (see above).
- `--rp-id <DOMAIN>` — relying-party ID (default `localhost`).
- `--timeout-seconds <SECS>` — registration deadline. Default `300`.
- `--accept-rp-id-binding-risk` — skip the first-registration RP-ID binding warning.

On the first registration for a profile (the registry is empty), the command prints an RP-ID binding warning and prompts `[y/N]` before starting the ceremony, unless `--accept-rp-id-binding-risk` is set. Declining exits `1`.

```bash
stellar-agent credentials add-passkey laptop-key --rp-id wallet.example.com
```

On success, `data` carries the registered credential's metadata. Timeout, user
cancellation, and a missing approval-store entry all surface as `ok:false`
with `error.code` of `credentials.registration_timeout`,
`credentials.registration_user_canceled`, or
`credentials.registration_entry_missing` respectively. A declined
first-registration prompt is `credentials.rp_id_binding_warning_declined`
(the message points to the RP-ID guidance in `docs/remote-approval.md`).

```json
{"ok":true,"data":{"credential_id":"AABBC...IJJKK","credential_name":"laptop-key","rp_id":"wallet.example.com","registered_at_unix_ms":0},"request_id":"..."}
```

### `credentials list`

```bash
stellar-agent credentials list
```

Read-only. Lists the registered passkeys for the resolved profile and RP-ID.

- `--profile <NAME>` — profile override.
- `--rp-id <DOMAIN>` — relying-party ID (default `localhost`).

```json
{"ok":true,"data":{"credentials":[{"credential_id":"AABBC...IJJKK","credential_name":"laptop-key","rp_id":"localhost","registered_at_unix_ms":0}]},"request_id":"..."}
```

### `credentials show <NAME>`

```bash
stellar-agent credentials show laptop-key
```

Read-only. Prints the metadata for one named passkey, including its transports. No secret material is included.

- `<NAME>` (positional, required) — the credential to show.
- `--profile <NAME>` — profile override.
- `--rp-id <DOMAIN>` — relying-party ID (default `localhost`).

Exits `1` with `error.code` `credentials.not_found` when the credential is not found.

### `credentials delete <NAME>`

```bash
stellar-agent credentials delete laptop-key --yes
```

State-changing (removes the registry entry). Verifies the credential exists, prompts `[y/N]` for confirmation, then deletes it. Deleting a passkey does not remove it as a signer from any on-chain rule.

- `<NAME>` (positional, required) — the credential to delete.
- `--profile <NAME>` — profile override.
- `--rp-id <DOMAIN>` — relying-party ID (default `localhost`).
- `--yes`, `-y` — skip the confirmation prompt.

Declining the prompt exits `1` with `error.code` `credentials.delete_canceled`; a missing credential exits `1` with `credentials.not_found`.

## `approve`

`approve` is the operator-side half of the approval spine. When a signing-adjacent action requires an out-of-band approval, the agent surface (the MCP server) records a pending approval and returns an approval nonce. The wallet owner runs `approve --id <NONCE> --profile <name>` in a separate, trusted context to inspect a wallet-controlled summary and consent.

The command renders the pending request alongside the serving profile context.
The recorded process uid must match the approving local user.
Consent records an HMAC attestation, or persists a toolset grant and consumes its pending request.
The versioned HMAC binds the profile name, CAIP-2 chain id, approval nonce, digest, and process uid.
The agent verifies it before executing.
On a mainnet profile, consent also requires a verified passkey assertion from an approval credential in the owner-signed policy, and this release refuses every mainnet consent with `approval.presence_required`; see [Mainnet write behavior](index.md#mainnet-write-behavior).
See [concepts](../concepts.md) for the attestation model and [toolsets](../toolsets.md) for first-invoke grants.

A `require_approval` rule's `ttl_secs` sets the pending entry's lifetime,
from 1 second to 604800 seconds (seven days); when omitted, the lifetime is 24
hours. Its optional `reason`, at most 512 characters, is shown in the
MCP approval response, `approve list` JSON and table output, and the trusted
CLI approval prompt. The reason is display text and grants no authority.

The CLI summary and both inbox detail pages show the profile name, CAIP-2 chain id, endpoint authority, and enrolled signer.
An enrollment placeholder appears as `(not enrolled)`.

Payment, claim, and trustline summaries are decoded from the transaction envelope the approval attests.
Every destination, amount, asset, memo, limit, balance id, fee, and sequence number shown is the envelope's.
The effective source is the operation source when the operation has one, otherwise the transaction source.
A muxed destination shows as its `M...` address.
A path payment shows the most the source pays and the least the destination receives.
Memos show their signed type: `none`, `text "<escaped value>"`, `id <n>`, `hash <hex>`, or `return <hex>`.
A claim names the balance by id only, so its asset and amount read `not part of the signed claim transaction`.
Trustline summaries show the holder account, asset code, issuer, limit, fee, and sequence number.
The CLI names the action `trustline change (ChangeTrust)`.
The CLI limit reads `unlimited`, `0 stroops (removes the trustline)`, or the exact
stroop count and decimal asset amount.
Both inboxes label it `TRUSTLINE` and offer `Approve trustline`.
An MPP charge summary shows the profile, network, payer, transport, authority, target, amount in the token's base units, token contract, recipient, challenge expiry, and fee.
Before the summary is shown and before consent is recorded, the profile, payer, amount, token contract, recipient, and challenge expiry are checked against the entry's authorization fingerprint, and the network against the passphrase digest the fingerprint binds.
A mismatch, or an entry that holds no binding digests, makes the entry inconsistent and prevents approval; an MPP entry without binding digests must be prepared again.
The charge commit refuses with `approval.entry_inconsistent`, and commits nothing, when the transport, authority, or target the entry shows differs from the prepared request.
The fee reads `not bound to this approval`.
MPP consent binds both the fingerprint and the prepared artifact.

Every value the summary shows is rendered with control characters visible: backslash, C0, DEL, C1, the line and paragraph separators, and every Unicode format character (category Cf) appear as escapes such as `\u{1b}` and `\u{202e}`.
The JSON that `approve list` and the other approval commands print carries the same characters as JSON `\uXXXX` escapes, so it parses to the same values.
Nothing is removed, so a value that holds such a character shows that it does.

A payment, claim, or trustline request is inconsistent when its stored digest is not the SHA-256 of its stored envelope, or its envelope does not decode as that kind of transaction.
An MPP charge request is inconsistent when the terms it shows do not match its authorization fingerprint.
The CLI shows such a request as `INCONSISTENT` with the reason and refuses it before the prompt, `--yes` included, with `approval.entry_inconsistent`.
Both inboxes label it `INCONSISTENT` and offer only Reject.
Nothing is attested for it on any surface.

The `approve`, `approve gc`, `approve list`, and `approve serve` commands return failures with `error.code` and a plain diagnostic message.
These failures carry `approval.*` codes: `approval.not_found`, `approval.expired`, `approval.already_attested`, `approval.user_mismatch`, `approval.clock_error`, `approval.sha256_hex_error`, `approval.key_decode_failed`, `approval.key_length_error`, `approval.binding_mismatch`, `approval.grant_persist`, `approval.wrong_kind`, `approval.rejected`, `approval.consumed`, `approval.record_failed`, `approval.uid_unavailable`, `approval.denied`, `approval.store_dir_error`, `approval.permission_denied`, `approval.invalid_nonce_length`, `approval.writer_locked`, `approval.store_open_failed`, `approval.gc_failed`, `approval.entry_inconsistent`, `approval.operator_credential_revoked`, `approval.remote_authorization_unavailable`, `approval.presence_required`, `approval.presence_policy_unavailable`, `approval.mainnet_remote_unsupported`.
`approval.presence_invalid`: The passkey assertion fails verification; start a fresh consent.
`approval.presence_changed`: The pending request or policy differs from the displayed consent; reload it.
`approval.presence_expired`: The presence deadline expires; start a fresh consent.
`approval.presence_consumed`: The challenge is consumed; start a fresh consent.
`approval.presence_unavailable`: The presence ceremony cannot complete; check the local browser and authenticator.
`approval.presence_canceled`: The presence ceremony is canceled; no approval is recorded.
`approval.presence_browser_required`: The ceremony requires a local browser; no approval is recorded.
`approval.gc_failed` reports a collection failure from `approve gc`.
`approval.operator_credential_revoked` reports a remote approval whose operator credential is missing from the profile's `allowed_credentials` list or from the operator-credential store; `approval.remote_authorization_unavailable` reports that the profile's remote-approval authorization or the operator-credential store could not be read, or that the profile does not enable remote approval for that chain.
`approval.entry_inconsistent` reports a payment, claim, or trustline request whose stored digest is not the digest of its stored envelope, or whose envelope does not decode, and an MPP charge request whose shown terms do not match what it would authorize.
Authentication, validation, and audit failures on approval paths carry their own codes.

### `approve --id <NONCE> --profile <name>`

State-changing (records an attestation or a grant in the on-disk pending-approval store).

- `--id <NONCE>` (required in this form) — the approval nonce printed in the agent surface's simulate response.
- `--profile <NAME>` — the profile whose attestation key and pending-approval store to use. Optional; resolves from `--profile`, then `STELLAR_AGENT_PROFILE`, then `"default"`.
- `--yes` — non-interactive auto-approve. Bypasses the stdin prompt; the wallet-controlled summary is still printed so there is a visible record. Intended for trusted automation and tests, not routine operator use.
  It applies to a testnet profile only: a mainnet profile refuses it before store access with `approve.yes_refused_on_mainnet`.

On a mainnet profile the command prints the summary, then refuses with `approval.presence_required` and records nothing; it reads no terminal input. On a testnet profile, interactively, the command prints the summary and prompts `Approve? [y/N]:`; anything other than `y`/`yes` denies. It exits `1` when the nonce is unknown, expired, already attested, created by a different local user, inconsistent, denied at the prompt, or on an I/O error.

The `approval_attested` audit row is written before the approval is persisted. When an MCP server or `approve serve` inbox holds that profile's audit writer, the row is queued in the audit outbox. The running process appends it to the log before any process loads a signing key for the approved action. The envelope's `audit` field says which happened: `"written"` or `"queued"`. The command refuses, persists nothing, and exits `1` when the writer is held by a process that does not drain the outbox (`audit.writer_locked`). It does the same on any other audit failure. Examples are a missing audit key, a rolled-back log (`audit.tip_anchor_mismatch`), and a busy outbox (`audit.outbox_busy`).

After upgrading, restart any running MCP server and `approve serve`: `approve --id` refuses beside an older one, which does not drain the outbox.

For a payment-style approval the response also returns `approval_attestation`: the HMAC blob the agent surface must present as the `approval_attestation` argument to the matching `*_commit` tool. The operator relays it to the agent over a trusted channel; the attestation binds the specific envelope, so it authorises only that one transaction. The field is omitted for approval kinds whose gate reads the recorded consent from the store directly (toolset first-invoke grants, trustline clawback opt-ins).

```bash
stellar-agent approve --id ABCxyzNonce --profile <name>
```

```json
{"ok":true,"data":{"approval_nonce":"ABCxyzNonce","attested":true,"process_uid":"501","expires_at_unix_ms":1717000000000,"approval_attestation":"q83vEjRWeJq83v...","audit":"written"},"request_id":"..."}
```

### `approve gc`

```bash
stellar-agent approve gc --profile default
```

State-changing (removes expired entries). Opens the pending-approval store and evicts every entry whose TTL has elapsed, then reports the count.

- `--profile <NAME>` — the profile whose store to garbage-collect. Optional; same resolution as above.

When the `gc` subcommand is present, any `--id` is ignored. Evicting zero entries is a success.

```json
{"ok":true,"data":{"profile":"default","evicted_count":3},"request_id":"..."}
```

### `approve list`

```bash
stellar-agent approve list --profile default
```

Read-only. Enumerates the profile's pending approvals with their
wallet-controlled summaries and expiry, so the operator does not depend on the
agent relaying a nonce.

- `--include-expired` — also show entries whose TTL has elapsed (they are
  counted in `expired_count` either way).
- `--output json|table` — envelope JSON (default) or one sanitized row per
  entry with an expires-in countdown.

```json
{"ok":true,"data":{"profile":"default","pending":[{"approval_nonce":"ABCxyzNonce","kind_name":"PaymentSimulated","created_at_unix_ms":1717000000000,"expires_at_unix_ms":1717086400000,"expired":false,"attested":false,"summary":{"kind":"payment","source":"GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY","to":"GDEST...","amount_stroops":"100000000","asset":"XLM","memo":null,"fee_stroops":"100","seq_num":12345}}],"expired_count":0},"request_id":"..."}
```

Trustline table rows read
`trustline CODE:ISSUER_REDACTED limit LIMIT for HOLDER`.
`LIMIT` is `unlimited`, `n stroops`, or `0 stroops (remove)`.
JSON uses `summary.kind: "trustline"` with the full holder and issuer.
Its `limit_stroops` is a decimal string, or `null` for unlimited.

For a consumed x402 approval, the tombstone's `tx_hash` holds the final-envelope
digest. It is not a chain transaction hash. The digest hashes the final
envelope's base64 text. JSON reports it redacted in `summary.tx_hash_redacted`.
Its table row reads
`spent (X402Payment), final-envelope digest <redacted digest>, outcome <outcome>`.

### `approve serve`

```bash
stellar-agent approve serve --profile default
```

Starts a resident, loopback-only approval inbox: a local web page that lists
pending approvals as they arrive, renders each wallet-controlled summary, and
offers Approve and Reject. Approve drives the same attestation path as
`approve --id <nonce> --profile <name>` and displays the attestation for copying back to the agent.
Reject replaces the entry with a short-lived rejection marker so the agent's
next commit attempt is refused with the distinct `policy.approval_rejected`
code. (`approve --id <nonce> --profile <name>` answering `n` keeps its
leave-to-expire behavior; only the inbox's Reject records an explicit
rejection.)

Each decision writes its audit row (`approval_attested` or `approval_rejected`)
before it takes effect. A decision whose row cannot be written is refused with
`unavailable` and the entry stays pending. A poisoned audit writer refuses
every later decision until the inbox restarts. `approve serve` itself refuses
to start while another process, such as a running MCP server, holds the audit
writer (`audit.writer_locked`).

On a mainnet profile, Approve answers HTTP 403 with `approval.presence_required`
and records nothing; Reject works.

The printed URL contains a single-use bootstrap token: the first visit
exchanges it for an HttpOnly session cookie and an origin-scoped session
proof, and the token dies. The page keeps the proof in the tab's session
storage. Mutating requests require the session cookie, an origin-scoped
session proof, and a CSRF value. The server binds `127.0.0.1` only and
refuses non-loopback hosts and origins.

The inbox session expires after 15 minutes without operator activity or 8 hours after bootstrap. Background polling does not extend it. Restart `approve serve` to establish a new session.

Browsers send a loopback cookie to every port on the same host, so another
local service the browser visits can receive the session cookie. That service
cannot read the proof, so the cookie alone cannot approve or reject. It can
still read what the cookie authorizes, the inbox listing and the approval
details, until the session expires.

Unless `--no-open` is passed, the browser opens the URL through a private
redirect file that only the current user can read. The browser launcher
receives only that file's address, never the bootstrap URL, and the file is
removed when the server stops. If the browser cannot be opened, open the
printed URL yourself. Until its first use or until the server stops, the
printed URL grants an inbox session to whoever opens it, so keep it out of
shared logs.

- `--port <PORT>` — fixed port (default: ephemeral). Use a fixed port when
  tunneling.
- `--no-open` — print the URL instead of opening a browser (default on
  headless hosts).
- `--notify on|off` — best-effort OS notification on new entries (count only,
  never amounts or addresses); `--bell` adds a terminal bell.
- `--include-expired` — grey-list expired entries in the inbox.

Run `serve` as the same OS user as the agent's MCP server: approvals are
bound to the user that parked them, and a different user's consent is
refused (`approval.user_mismatch`).

Remote operation (agent on a remote or headless host): keep the server
loopback-bound and reach it through an SSH local port-forward with the SAME
port on both ends, then open the printed `127.0.0.1` URL in the local
browser:

```bash
ssh -L 8791:127.0.0.1:8791 wallet-user@agent-host   # then start: approve serve --port 8791 --no-open
```

There is no OS-notification push for remote operators; the open inbox page
updates itself and the serve terminal prints a count line when new approvals
arrive.

### `approve serve --remote`

```bash
stellar-agent approve serve --remote --confirm-remote-exposure --profile default
```

Binds a TLS-protected, passkey-authenticated listener beyond loopback instead
of the local inbox above — for approving from a device other than the wallet
host, without an SSH tunnel. Requires the profile's `[remote_approval]` block
with `enabled = true` AND `--confirm-remote-exposure` as a separate, explicit
consent flag; either alone refuses to start. See
[Remote approval](../remote-approval.md) for the full setup, trust model, and
walkthrough. The remote listener approves testnet requests only: an approve of
a mainnet request answers HTTP 403 with `approval.mainnet_remote_unsupported`.

### `approve operator enroll`

Writes a WebAuthn credential to the profile's dedicated operator-approval
credential store, for use with `approve serve --remote`. Enrollment alone
never authorizes anything — the credential still has to be added to the
profile's `[remote_approval] allowed_credentials` list, a separate,
operator-controlled step. Runs entirely locally in both modes below; neither
touches the network.

A WebAuthn credential is bound to its `rp.id` at creation time, and that
binding is what decides which of the two modes applies:

- **`--interactive`** — for a loopback or SSH-tunnelled `approve serve
  --remote` listener. Needs a terminal on stdin and stderr, and refuses with
  `approve.operator_enroll_tty_required` otherwise. Starts a one-shot local
  server and prints (and by default opens) an enrollment page. The printed
  URL contains a single-use bootstrap token: the first visit exchanges it
  for an HttpOnly session cookie and an origin-scoped session proof that the
  page keeps in the tab, and the token dies. Serving the page requires the
  cookie; both POSTs of the ceremony require the session cookie, the session
  proof, and a CSRF value. The session expires after 15 minutes without
  operator activity or 8 hours after bootstrap.

  The ceremony runs in four steps:

  1. The page requests a registration challenge (`POST /enroll/challenge`).
     The server issues one random 32-byte challenge per ceremony; it expires
     after 300 seconds and is used once.
  2. Your authenticator creates the credential over that challenge for
     `rp.id` `localhost`, with user verification.
  3. The page posts the credential (`POST /enroll/credential`) with the
     authenticator's `clientDataJSON` and `attestationObject`. The server
     checks the type, the challenge, the exact origin, the relying-party
     hash, the user-presence, user-verification and attested-data flags, the
     credential id, and the ES256 P-256 key against what the page posted. It
     accepts only `none` attestation, so the check proves the response
     answers this ceremony's challenge, not the authenticator's make or
     model. A refused registration answers `registration_invalid`, an expired
     challenge `registration_expired`, an id already enrolled
     `duplicate_credential_id`, and a label that is empty, longer than 64
     bytes, or holds a control character `label_invalid`. The verified
     credential is staged; nothing is written yet.
  4. The page shows a confirmation code of 16 hex digits in four groups,
     computed from the challenge, the credential id and the public key it
     created. The command prompts for that code and names the label, with
     any control or format character shown as a visible escape. Only a
     matching code typed before the timeout writes the credential; the
     command never prints the expected code. One code is compared per
     ceremony.

  A wrong code (`approve.operator_enroll_confirmation_mismatch`), no code
  (end of input or Ctrl-C at the prompt,
  `approve.operator_enroll_confirmation_canceled`), or a code typed after
  the timeout (`approve.operator_enroll_confirmation_expired`) writes
  nothing and exits `1`. Ctrl-C before the page posts a credential stops the
  server, removes the redirect file, and exits `1` with
  `approve.operator_enroll_interactive_interrupted`; no registration before
  the timeout exits with `approve.operator_enroll_interactive_timeout`. The
  timeout covers the browser ceremony and the confirmation together.

  The confirmation code binds the terminal to the ceremony the page ran: a
  local process that obtains the session cannot enroll a credential of its
  own without the operator typing that credential's code. The browser opens
  through a private redirect file that only the current user can read, so
  the browser launcher never receives the bootstrap URL; the file is removed
  when the command ends. If the browser cannot be opened, open the printed
  URL yourself. Until its first use or until the command ends, the printed
  URL grants an enrollment session to whoever opens it, so keep it out of
  shared logs. The server binds `127.0.0.1` only and refuses non-loopback
  hosts and origins. Always produces a credential bound to
  `rp_id: "localhost"`, the only effective domain a loopback origin can
  claim. The stored sign count comes from the authenticator data the server
  verified.
- **`--credential-id` / `--public-key` / `--rp-id` / `--label`** (all four
  together) — for a domain-configured remote listener. Imports the id and
  public key from a WebAuthn ceremony run elsewhere: normally the remote
  listener's own `GET /enroll` page, which has to be served from
  `https://<rp_id>` for the resulting credential to bind to that domain. See
  [Remote approval](../remote-approval.md) for that page's walkthrough. The
  command checks the shape of the id and the key; the operator who runs it
  vouches that they came from their own ceremony.

```bash
# Local or SSH-tunnelled listener
stellar-agent approve operator enroll --interactive --label laptop

# Domain-configured remote listener: import a credential enrolled via its
# own /enroll page
stellar-agent approve operator enroll \
  --credential-id <B64URL> --public-key <B64URL> --rp-id <HOSTNAME> \
  --label laptop --sign-count <N>
```

- `--no-open` — print the enrollment URL instead of opening a browser
  (interactive mode only).
- `--timeout-seconds <SECS>`: interactive-ceremony timeout, covering the
  browser registration and the terminal confirmation (default: 300).
- `--sign-count <U32>` — seeds the clone-detection baseline from a counter
  read at enrollment time (argument mode only; interactive mode extracts
  this automatically). Advisory only — a caller reporting a false value only
  weakens that credential's own clone-detection baseline and never affects
  authorization, which is decided solely by `allowed_credentials`.

Every write to the operator-credential store (enrollment, removal, and the
sign-count update after each remote login) holds the store's lock file
(the store's path with `.lock` appended) across reading and replacing the
file, so concurrent
writers never lose an enrollment or lower a stored counter. A writer that
cannot take the lock writes nothing, and each path reports it in its own way:

- `approve operator enroll --interactive` and `approve operator remove`
  refuse with `approval.writer_locked`. Retry the command.
- `approve operator enroll` in argument mode refuses with
  `internal.unexpected_state`, whose message names
  `approve.operator_enroll_failed`. Retry the command.
- A remote login answers `400` `webauthn_assertion_invalid`, the answer
  every refused login gets, so the response does not reveal the contention.
  Log in again.

### `approve operator remove`

```bash
stellar-agent approve operator remove --credential-id <B64URL> --profile default
```

State-changing. Removes the enrolled operator credential with that id from
the profile's operator-credential store.

- `--credential-id <B64URL>` (required): the credential id to remove;
  values that start with `-` are accepted.
- `--profile <NAME>`: the profile whose store to edit. Resolves from
  `--profile`, then `STELLAR_AGENT_PROFILE`, then `"default"`. A name that
  is not a safe file name (an absolute path, a path separator, or `..`)
  refuses with `validation.config_invalid` before anything is read or
  written; `approve operator enroll` applies the same rule.

The command prints `{"removed": true}` when it removed a record and
`{"removed": false}` when none had that id, and exits `0` in both cases. It
never prints the credential id. It does not edit the profile. Lock
contention refuses with `approval.writer_locked`; any other store failure
refuses with `approve.operator_remove_failed`; neither writes anything.

To revoke an operator credential, remove its id from the profile's
`[remote_approval] allowed_credentials` list first, then run this command.
Either step alone already revokes the credential: a running listener reads
the list and the store at every login and decision and stops honoring the
credential at once. Doing both keeps a later edit of one of them from
authorizing the credential again. Operator credentials approve remote testnet
requests only and do not change the mainnet approval credentials of the
signed policy.

```json
{"ok":true,"data":{"removed":true},"request_id":"..."}
```

### `approve credential enroll`

```bash
stellar-agent approve credential enroll --profile operator --label laptop
```

Enrolls a WebAuthn approval credential for the owner-signed mainnet policy and
prints its policy entry. It writes nothing: no profile, policy, keyring entry,
or operator-credential store changes. The credential approves mainnet consent
only after the owner adds the entry to `mainnet.approval_credentials` and signs
the policy; see [Approval credentials](../profiles.md#approval-credentials).

- `--profile <NAME>` (required): a persisted mainnet profile. Neither an
  enabled installation nor a mainnet policy is required, so a credential can be
  enrolled before the policy that lists it.
- `--label <LABEL>`: pre-fills the page's label field. The label stays on the
  page and is absent from the output.
- `--timeout-seconds <SECS>`: one deadline for the browser registration and
  the terminal code, from 1 to 600 (default 300).

The command needs a terminal on stdin and stderr and a local browser. It
starts a one-shot server on `127.0.0.1` and opens the page at
`http://localhost:<port>` through a private redirect file; the bearer URL is
never printed. The page creates a passkey with relying-party ID `localhost`
over the server's single-use challenge, and the server verifies the
registration as `approve operator enroll --interactive` does, user presence
and user verification included. The page then shows a 16-hex-digit
confirmation code derived from the credential under a mainnet-approval domain,
so a code from a remote-operator enrollment page never matches. Type it at the
terminal before the deadline. On success stdout carries one envelope and
stderr a reminder to add the entry, review the key, and sign the policy:

```json
{"ok":true,"data":{"profile":"operator","rp_id":"localhost","credential_id_b64url":"<id>","public_key_sec1_b64url":"<key>","credential_fingerprint":"sha256:<hex>","policy_entry_toml":"{ credential_id_b64url = \"<id>\", public_key_sec1_b64url = \"<key>\" }"},"request_id":"..."}
```

`credential_fingerprint` is the SHA-256 of a domain tag, the length-prefixed
credential ID, and the public key; mainnet audit rows name a credential by it.

Exits `1` on refusal, and exports nothing:

| Code | Message |
|---|---|
| `approve.credential_enroll_tty_required` | `Approval credential enrollment needs a terminal on stdin and stderr to type the code shown by the browser.` |
| `approve.credential_enroll_profile_required` | `Approval credential enrollment requires a persisted mainnet profile selected with --profile.` |
| `approval.presence_browser_required` | `Mainnet consent requires a local browser with WebAuthn user verification; no approval is recorded.` No display, or the browser did not open. |
| `approve.credential_enroll_confirmation_mismatch` | `The confirmation code does not match the browser credential; no policy credential is exported.` |
| `approve.credential_enroll_expired` | `The approval credential enrollment deadline has passed; no policy credential is exported.` |
| `approve.credential_enroll_canceled` | `Approval credential enrollment is canceled; no policy credential is exported.` Ctrl-C, or the prompt ended without a code. |
| `approve.credential_enroll_unavailable` | `The approval credential enrollment cannot start or complete; no policy credential is exported.` |

A profile that does not load for a safety reason keeps the loader's refusal.
To revoke an approval credential, remove its entry from the policy and sign
the policy at a higher sequence.

## `audit`

The `audit` group verifies the per-profile audit log, an append-only, hash-chained JSONL record of transaction submissions, signed authorizations, approvals, and explicit key-management and lifecycle events, and repairs its tip anchor. MCP balance reads and payment simulations produce no automatic invocation row. Under V1, payment simulations can reconcile overdue reservations and write settlement audit rows. Raw argument values are never logged; only argument key names are recorded. Typed value events retain each leg's amount, asset, and redacted destination. The chain links each entry to the SHA-256 of the prior entry's canonical body, so any external modification breaks verification.

The chain and the per-file chain-root signatures verify a PREFIX of the log, so an older copy of the active file, or a truncated one, passes both. What pins the END of the chain is the tip anchor: the active file's entry count, last-entry hash, and byte offset, held in the platform keyring per log path. Every value-moving verb checks it before signing, and `audit verify --profile` checks it too.

### `audit verify <LOG_PATH>`

Read-only. Walks the log at `<LOG_PATH>`, following rotation manifests across rotated files, and verifies that the hash chain is intact end to end. When `--profile` is supplied, it additionally loads that profile's audit chain-root HMAC key and verifies the chain-root sidecars; without `--profile`, only the hash chain is checked and `hmac_verified` is reported as `false`.

The tip anchor is checked only when `--profile` is supplied AND `<LOG_PATH>` is the log that profile configures. The anchor names a path, not a profile, so comparing it against a file it does not describe would report a mismatch that means nothing. Every other case reports `anchor.status` as `"not_checked"` with the reason and still verifies the chain in full. A log that moved forward past its anchor passes; a log behind it, or one whose tip is not the anchored tip, fails with `audit.tip_anchor_mismatch`.

When no anchor is stored for the profile's own log, the command checks for evidence of prior anchoring. Each of these shows the log was anchored: an audit binding recorded for the profile, a chain-root sidecar beside the active file, or an `audit_tip_anchored` row in it. With any of them the command fails with `audit.tip_anchor_missing`, and the message says `anchor: missing` and names the evidence. For an empty active file, only the sidecar counts as evidence. Profile verification checks the hash chain and HMAC sidecars before reporting anchor agreement, unless this missing-anchor rule applies. The missing-anchor check follows an unkeyed chain walk and precedes HMAC verification. Without evidence, a log reports `anchor.status` as `"not_checked"` only if its chain and HMAC checks pass.

Verifier failures use `audit.chain_broken`, `audit.rotation_gap`, `audit.hmac_mismatch`, `audit.hmac_sidecar_missing`, `audit.too_many_rotated_files`, `audit.non_regular_file_log_path`, `audit.parse_error`, `audit.path_contract`, `audit.log_not_found`, `audit.io_error`, `audit.signer_set_canonical_body`, `audit.partial_rotation`, `audit.tip_anchor_mismatch`, `audit.tip_anchor_missing`, `audit.outbox_rows_missing`, `audit.outbox_busy`; see [security internals](../maintainers/security-internals.md#audit-hash-chain).
Profile and ownership pre-checks carry their own codes.

- `<LOG_PATH>` (positional, required) — path to the audit log file. By default this is `~/.local/share/stellar-agent/audit/<profile>.jsonl` on Linux, `~/Library/Application Support/Soneso.stellar-agent/audit/<profile>.jsonl` on macOS, and `%LOCALAPPDATA%\Soneso\stellar-agent\data\audit\<profile>.jsonl` on Windows.
- `--profile <NAME>`: the profile whose chain-root HMAC key verifies the sidecars. Optional; when omitted, only the hash chain is verified. The profile's audit binding is read and never written: a changed or unparseable binding exits `1` with `audit.log_binding_changed`.
- `--output <FORMAT>` — output format. `json` is the default and only stable format.

On Unix, the command refuses to verify a log whose parent directory is owned by a different user, since such a directory could be used to substitute log files or sidecars. It exits `0` when the chain is intact and `1` on any integrity violation (a broken chain, a rotation gap, an HMAC mismatch, a missing sidecar, an unparseable line, a tip-anchor mismatch, or a missing tip anchor), a path-contract failure, or an I/O error.

A `pruned_prefix` warning reports `first_file`, the oldest file walked, and
`pruned_files`, the count in `<log>.pruned`. The marker seeds that file's first
entry and is authenticated when an audit key is supplied. Verification checks
every retained entry and bridge, and the warning leaves the verdict successful.

`outbox_pending` counts complete queued consent lines. With `--profile` and the profile's log path, verification checks the keyring commitment under the outbox lock after the chain walk. A missing or changed committed prefix fails with `audit.outbox_rows_missing`; a held lock fails with `audit.outbox_busy`. Without a profile, no commitment is checked. The separate count inspection can report `outbox_torn_tail`, `outbox_unparseable`, or `outbox_unreadable` warnings.

An `outbox_loss_acknowledged` warning names each loss acknowledgement's file, line, `expected_rows`, and `found_rows`. It leaves the chain verdict unchanged.

```bash
stellar-agent audit verify ~/.local/share/stellar-agent/audit/default.jsonl --profile default
```

```json
{"ok":true,"data":{"entries_verified":42,"files_walked":2,"hmac_verified":true,"per_file":[],"warnings":[],"audit_writer_degraded":false,"anchor":{"status":"verified","reason":null},"outbox_pending":0},"request_id":"..."}
```

### `audit reanchor --profile <NAME> --acknowledge-rollback`

State-changing (writes the keyring anchor, appends one or two audit rows, then drains the audit outbox; no network). The only way out of an `audit.tip_anchor_mismatch`, `audit.tip_anchor_missing`, or `audit.log_binding_changed` refusal. Operator-only: an agent must never run it on its own initiative.

- `--profile <NAME>` (required): the profile whose configured `audit_log_path` and audit keyring coordinate identify the anchor.
- `--acknowledge-rollback` (required to act on a rolled-back log): accept the log's current tip as authoritative.
- `--acknowledge-binding-change` (required to act on a changed binding): accept a log path or audit key that differs from the profile's recorded audit binding.

| Recorded binding | Current path's anchor | Flags required | Rows appended |
|---|---|---|---|
| Equal or absent | Any | `--acknowledge-rollback` | `rollback_acknowledged` |
| Changed or unreadable | Agrees, or absent without prior anchoring evidence | `--acknowledge-binding-change` | `binding_changed` |
| Changed or unreadable | Disagrees, cannot be parsed, or absent with prior anchoring evidence | Both | `rollback_acknowledged`, then `binding_changed` |

The first row covers both anchor refusals: an anchor that disagrees with the log (`audit.tip_anchor_mismatch`), and an absent anchor on a log that shows it was anchored before (`audit.tip_anchor_missing`). In the binding-changed rows, an absent anchor disagrees when a chain-root sidecar or an `audit_tip_anchored` row shows prior anchoring. Without evidence it agrees.

A flag the matrix does not require is ignored. The binding is checked before the repair writer opens, and the anchor's disagreement is decided again under the writer's lock. A missing flag changes nothing and exits `1` with `validation.acknowledgement_required`, naming the flag. Without `--acknowledge-rollback` on an equal or absent binding the command reports the anchor in force and the anchor it would write, both as `<entry count>:<byte offset>`, changes nothing, and exits `1` with `validation.acknowledgement_required`. Moving the anchor forgives whatever made the log disagree with it, and the command cannot tell a restored backup from tampering. That judgement is the operator's, and it wants to be made before the evidence moves.

After the operator investigates, reanchor accepts an intact prefix with the required flags. It replays the whole log first and refuses a broken chain. It writes the current tip as the anchor, bumps the current path's re-anchor counter held in the keyring once, and appends the rows, each carrying that count. `rollback_acknowledged` names the superseded anchor. `binding_changed` names the anchor of the log path the previous binding named, or none when the record was unreadable. The rows are permanent: the log carries its own record that a rollback or a binding change was accepted. The new binding is stored last, so a run that stops earlier leaves the refusal in place, and an absent binding is recorded after a rollback repair. The envelope lists the conditions acknowledged and how the recorded binding compared.

Queued consent rows follow the repair rows and are counted in `outbox_drained`. A drain refusal leaves the repair in force and exits `0`. It omits `outbox_drained`, since every queued row stays queued, and lists the refusal under `warnings`: `audit.outbox_unusable`, `audit.outbox_busy`, `audit.outbox_rows_missing`, or the condition an append refused on, such as `audit.io_error`.

The command takes the audit writer's exclusive lock. Stop an MCP server that holds this profile's writer before a rollback repair. See [Key-rotation subcommands](#key-rotation-subcommands) for acquisition and replacement eviction. A binding change needs no stop: a server running the edited profile refuses before it opens the new path, so it holds no lock there. A server still running the old profile refuses after the acknowledgement until it restarts.

```bash
stellar-agent audit reanchor --profile default                          # report only, exits 1
stellar-agent audit reanchor --profile default --acknowledge-rollback
stellar-agent audit reanchor --profile default --acknowledge-binding-change
```

```json
{"ok":true,"data":{"profile":"default","previous_anchor":"42:18104","current_anchor":"39:16820","reanchor_count":1,"acknowledged":["rollback"],"recorded_binding":"equal","previous_binding_anchor":null,"outbox_drained":0},"request_id":"..."}
```

For the causes worth ruling out before acknowledging, see [Audit-log recovery](../maintainers/audit-log-recovery.md).

### `audit acknowledge-outbox-loss --profile <NAME> --reason <TEXT>`

Operator-only recovery for `audit.outbox_rows_missing`; an agent must not run it on its own initiative.
Stop the process holding the profile's writer and inspect the queued rows first.
`--reason` is required, non-empty, and recorded with the audit string bound.

The command checks the tip anchor, checks that the loss holds and that every remaining queued row parses, and then revokes every decided, unexpired, unconsumed approval and every toolset grant.
Mainnet confirmations and recorded passkey assertions count as decided approvals.
It records `audit_outbox_loss_acknowledged`, drains the remaining complete rows, resets the commitment, and empties the outbox.
Approve affected actions again to record fresh consent.

The result contains `profile`, `expected_rows`, `found_rows`, `drained`, `revoked_approvals`, and `revoked_grants`.
No loss returns `audit.outbox_loss_not_found` without an acknowledgement; a held writer returns `audit.writer_locked`; a log rolled back behind its tip anchor returns `audit.tip_anchor_mismatch`.
A remaining row that does not parse returns `audit.outbox_unusable` before anything is revoked or written.
A row that cannot append leaves the queue and commitment in place for inspection and retry.

```bash
stellar-agent audit acknowledge-outbox-loss --profile default --reason "Queue inspected; fresh approval required"
```

## The governance loop

`approve` and `audit verify` are the operator's two touch points in the guardrail loop:

1. The agent surface evaluates an action against the policy engine. An action that needs operator consent records a pending approval and returns its nonce instead of executing.
2. The wallet owner runs `approve --id <NONCE> --profile <name>` in a trusted context, reads the wallet-controlled summary, and consents. The command writes an HMAC attestation (or a toolset grant) bound to the profile name, chain id, approval nonce, envelope digest, and local user.
3. The agent surface verifies the attestation and executes. The commit writes its transaction audit events to the hash-chained audit log.
4. The operator periodically runs `audit verify` to confirm the log has not been tampered with, supplying `--profile` to check the chain-root HMAC sidecars and the tip anchor as well as the hash chain.

Key rotation backs this loop: `rotate-attestation-key` invalidates outstanding approvals, and `rotate-audit-key` re-keys the chain root and re-signs every existing per-file sidecar. See [concepts](../concepts.md) for the full model.
