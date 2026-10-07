# CLI reference: profiles, credentials, approvals, and audit

This page documents four `stellar-agent` command groups: `profile`, `credentials`, `approve`, and `audit`. Together they configure a profile, manage its WebAuthn passkeys, and operate the operator-side governance loop: recording out-of-band approvals, verifying the tamper-evident audit log, and repairing its tip anchor.

For the conventions shared by every command (profile and network resolution, the signer-source flags, the JSON output envelope, exit codes, and the mainnet-write refusal), see the [CLI reference index](index.md). For the underlying concepts (the policy engine, the approval spine, attestations, the audit log, and toolset gating), see [concepts](../concepts.md). For profile file structure, see [profiles](../profiles.md), and for toolset gating see [toolsets](../toolsets.md).

All four groups operate on local state — TOML files and platform-keyring entries. None of them submits a Stellar transaction, so the network flags and the mainnet-write gate do not apply here. Every command prints JSON on stdout and exits `0` on success or `1` on any error, using the standard `{ok, data, request_id}` envelope.

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
| `profile.mainnet_requires_explicit_profile` | A mainnet profile was selected by the environment or the default source. Supply `--profile <name>`. |

Unset the `STELLAR_AGENT_*` variable the refusal names. On every chain that covers `STELLAR_AGENT_CHAIN_ID`, `STELLAR_AGENT_AUDIT_LOG_PATH`, every `*_KEY_ID` variable, and every other key outside the overlay classes. On mainnet it also covers `STELLAR_AGENT_RPC_URL`, `STELLAR_AGENT_SECONDARY_RPC_URL`, `STELLAR_AGENT_ORACLE_PROVIDER_URL`, `STELLAR_AGENT_MCP_SIGNER_DEFAULT`, and the other testnet-only keys. Remove refused keys from programmatic overlays too, and set needed values in the profile file. Then run `stellar-agent profile show --profile <name>` to confirm the file's chain and endpoint. Correct the profile file if either value differs from the intended configuration.

## `profile`

The `profile` group creates, lists, shows, and migrates profiles, and rotates the keyring-backed keys a profile names. A profile is a per-environment TOML config (schema version 2) binding a CAIP-2 chain id, an RPC endpoint, keyring entry references, thresholds, and the active policy engine. It holds no secrets; it only names keyring entries.

The seven key-writing commands — `enroll-signer`, `enroll-owner-key`, and the five key-rotation subcommands — each write a `keyring_key_written` audit row recording the key purpose and, where applicable, the redacted public address. `reset-window-state` writes the same row when the reset mints the window-state key on first use. `init` mints no key material and emits no audit row.

`profile list` lists all profile names and takes no profile selector. Every other `profile` subcommand accepts `--profile <NAME>`. For `init`, `enroll-signer`, `enroll-owner-key`, and `sign-policy` it is the only form and resolves in the order the index documents: the flag, then `STELLAR_AGENT_PROFILE`, then `"default"`. For `show`, `migrate`, the `rotate-*` subcommands, `reset-window-state`, and `reset-mpp-state`, supply exactly one positional `<NAME>` or `--profile <NAME>`. These commands require an explicit selection. `reset-mpp-state` requires `--acknowledge`; the other profile verbs have no confirmation flag.

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

Read-only. Loads the named profile (applying any environment-variable overlays) and prints its resolved configuration as a JSON envelope. Keyring entry references appear as opaque `{service, account}` objects; the secret material they name is never read or printed.

- `<NAME>` (positional) or `--profile <NAME>` — the profile to display. Supply exactly one; supplying both, or neither, is a usage error.

Exits `1` with `validation.profile_not_found` when the profile does not exist. A mainnet file without `rpc_url` exits with `validation.mainnet_rpc_url_required`. An endpoint URL that breaks the endpoint rule (see [Loader source order](../profiles.md#loader-source-order)), an unsupported schema version, or another unreadable file exits with `validation.config_invalid`.

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

- `--secret-env <VAR>` (required) — name of the environment variable holding the signer's `S...` strkey. The flag takes the variable name, never the secret.
- `--profile <NAME>`: profile whose `mcp_signer_default` entry is written (default: `STELLAR_AGENT_PROFILE`, else `default`). Loading a mainnet profile requires an explicit `--profile <NAME>`.
- `--expected-address <G_STRKEY>` — refuse unless the seed derives to this address.
- `--force` — replace an already-enrolled entry (refused without it when one exists).

The coordinate's `account` field is the signer identity: `signer_from_keyring` verifies the loaded seed derives to it, so `account` must equal the seed's public address. Enrollment classifies the field from its raw on-disk value (environment overlays never influence what gets persisted) and resolves three cases. A profile fresh from `profile init` (and a v1-migrated profile that still carries it) holds the literal placeholder `"default"`: enrollment pins the derived address into `account` — patching only that key in the profile TOML — before writing the keyring entry. Once `account` holds a G-strkey — from that first enrollment, or set by hand — enrollment refuses on a mismatch and prints the address to set `account` to, and the profile TOML is left untouched. Any other value (a typo'd or truncated pin) is refused with `enroll_signer.account_malformed` rather than replaced. Every refusal leaves the file unmodified. On success the data object reports the derived `public_address`, the `keyring_service`/`keyring_account` written, `replaced` (with `previous_address` when an entry was replaced), and `account_populated` (`true` when the placeholder was just pinned):

```json
{"ok":true,"data":{"profile":"default","enrolled":true,"public_address":"G...","keyring_service":"stellar-agent-signer-default","keyring_account":"G...","replaced":false,"account_populated":true},"request_id":"..."}
```

Exits `1` on refusal:

- `validation.profile_not_found`: the profile does not exist.
- `enroll_signer.account_identity_mismatch`: the seed does not match a pinned signer account.
- `enroll_signer.account_malformed`: the stored account is neither the placeholder nor a valid G-strkey.
- `enroll_signer.expected_address_mismatch`: `--expected-address` does not match.
- `enroll_signer.entry_exists`: an entry exists without `--force`.
- A keyring error: the platform keyring is unavailable.

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
- `--force` — replace an already-enrolled owner key (refused without it when one exists; replacing invalidates every policy file signed by the previous owner key).

The owner coordinate's `account` is the literal `"default"` (the value the engine reads); the stored value is the public key's G-strkey. A G-strkey decodes as URL-safe base64 to 42 bytes, so no 32-byte symmetric-key loader accepts it. Every owner reader also accepts the older form, URL-safe base64 of the 32 key bytes. The V1 engine build rewrites an older-form entry as its G-strkey, best effort, and the first build in a process also rewrites every other profile's older-form owner entry in the profile directory. This command rewrites them too. Under `headless-dpapi` an older-form owner entry can be moved to another coordinate until it is rewritten, so run one V1 verb or this command after upgrading. On success the data object reports the derived `owner_address`, the `keyring_service`/`keyring_account` written, and `replaced`. The prior key's stored value is never decoded or reported. A prior entry at this coordinate may have held an owner seed in the older encoding, so rendering it could print a private key. `replaced: true` conveys that a prior entry existed.

```json
{"ok":true,"data":{"profile":"default","enrolled":true,"owner_address":"G...","keyring_service":"stellar-agent-owner-default","keyring_account":"default","replaced":false},"request_id":"..."}
```

Exits `1` on refusal:

- `validation.profile_not_found`: the profile does not exist.
- `enroll_owner_key.expected_address_mismatch`: `--expected-address` does not match.
- `enroll_owner_key.entry_exists`: an owner key exists without `--force`.
- A keyring error: the platform keyring is unavailable.

### `profile sign-policy`

Run this line on its own, paste the owner seed when prompted, and press Enter:

```bash
printf 'WALLET_OWNER_SK seed: ' && read -rs WALLET_OWNER_SK && echo && export WALLET_OWNER_SK
```

```bash
stellar-agent profile sign-policy --profile default --secret-env WALLET_OWNER_SK
unset WALLET_OWNER_SK
```

Signs a V1 policy file so the engine accepts it. The engine loads `<state_dir>/policies/<profile>.toml`, recomputes the canonical form (the `[signature]` table excluded), and verifies the signature against the enrolled owner public key. This command produces that `[signature]` table: it computes the same canonical BLAKE3 digest the loader computes, signs it with the owner seed, and writes `owner_id` (the owner G-strkey) and `sig` (hex) back into the file. State-changing (writes the policy file), no network. The owner seed is read from a named environment variable and held only in zeroizing memory; it is never printed, logged, or written to disk.

- `--secret-env <VAR>` (required) — name of the environment variable holding the owner `S...` strkey.
- `--profile <NAME>`: profile whose policy file is signed (default: `STELLAR_AGENT_PROFILE`, else `default`). Loading a mainnet profile requires an explicit `--profile <NAME>`.
- `--file <PATH>` — sign a policy file at a non-default path (default `<state_dir>/policies/<profile>.toml`, the only location the engine loads).

Before writing, the seed's derived public key is cross-checked against the enrolled owner key; a seed that does not match is refused (`sign_policy.owner_key_mismatch`) so a file the engine would reject is never produced. Re-signing an already-signed file replaces the `[signature]` table in place and reports `replaced: true` with the previous `owner_id`. On success the data object reports the `owner_address`, the `policy_path`, the `digest` (hex), and the `signature` (hex):

```json
{"ok":true,"data":{"profile":"default","signed":true,"owner_address":"G...","policy_path":".../policies/default.toml","digest":"<hex>","signature":"<hex>","replaced":false},"request_id":"..."}
```

Exits `1` on refusal:

- `validation.profile_not_found`: the profile does not exist.
- `sign_policy.owner_key_unavailable`: no owner key is enrolled; run `enroll-owner-key` first.
- `sign_policy.owner_key_mismatch`: the seed does not match the enrolled owner key.
- `sign_policy.policy_file_unreadable`: the policy file is missing.
- `sign_policy.canonicalization_failed`: the policy file is malformed.
- A keyring error: the platform keyring is unavailable.

### Key-rotation subcommands

The MCP server acquires its audit writer when an operation needs it, such as a commit preflight before signing. MCP balance reads do not acquire it. Under V1, payment simulations can reconcile overdue reservations, acquire the writer, and write settlement audit rows.

The registry normally caches the writer and holds its lock until process exit. A replaced-file refusal during acquisition marks the cached writer for eviction. After callers release it, the next acquisition drops it and checks the file at the path against the anchor.

While held, the lock blocks rotation with `audit.writer_locked` in the error
detail, even if the operation that acquired it later fails.

Each rotation subcommand generates a fresh 32-byte secret from the OS CSPRNG, encodes it as URL-safe base64 (no padding), and atomically replaces one keyring entry the profile names. The raw bytes never leave the keyring, are never logged, and are never returned. Every rotation subcommand takes the profile as either a positional `<NAME>` argument or a `--profile <NAME>` flag — exactly one of the two, and supplying both, or neither, is a usage error — changes keyring state (no network), and is not reversible. Rotate deliberately, because each one invalidates material minted under the old key. (The policy-file owner ed25519 key is not rotated here; it is enrolled with `enroll-owner-key`.)

| Subcommand | Keyring entry rotated | Key kind | Effect on outstanding material |
|---|---|---|---|
| `rotate-attestation-key` | approval-spine attestation HMAC key (`attestation_key_id`) | 32-byte HMAC | All pending approvals are invalidated; the simulate-and-approve round trip must be re-run. |
| `rotate-audit-key` | audit-log chain-root HMAC key (`audit_log_hash_chain_key_id`) | 32-byte HMAC | Rotation re-signs every existing per-file chain-root sidecar with the new key. `audit verify` passes under the new key, and the old key stops verifying. Takes the audit writer's exclusive lock, so it refuses while an MCP server holds that writer, and checks the tip anchor before touching the key. Checks the audit binding before it opens the writer: a changed binding refuses with `audit.log_binding_changed` and creates nothing at the path the profile names; an absent one is recorded. |
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

A further rotation subcommand, `profile rotate-counterparty-key <NAME>`, rotates the `stellar.toml` cache-integrity HMAC key (`counterparty_cache_key_id`); it invalidates every cached counterparty binding, which the wallet re-fetches on the next counterparty-allowlist check. Its data object adds `"key_kind": "hmac_32_bytes"` and `"cache_invalidated": true` to the `profile` and `rotated` fields. This rotates the same keyring entry as `stellar-agent counterparty rotate-hmac-key` (see [core operations](stellar-ops.md)); the two verbs are interchangeable.

Each rotation exits `1` with `validation.profile_not_found` if the profile does not exist, or with a keyring error if the platform keyring is unavailable.

### `reset-window-state <NAME> --reason <REASON>`

Not a rotation: the fail-closed recovery path for the persisted policy-window-state store. An unreadable, tampered, or unparseable store file makes the stateful criteria (`per_period_cap`, `rate_limit`, and their bundle forms) refuse every matched call until the store is re-initialised. `reset-window-state` re-initialises it to empty (minting the HMAC key if absent), discards all accumulated window history, and writes a `policy_window_state_reset` audit row recording the profile and the required `--reason`. The reset is audited BEFORE the mutation, so the audit trail records the request even if the re-initialisation fails midway. A blank or whitespace-only `--reason` exits `1` with `validation.reason_empty` before anything changes.

```bash
stellar-agent profile reset-window-state default --reason "store file corrupted after disk failure"
```

### `reset-mpp-state <NAME> --acknowledge --reason <REASON>`

Resets MPP authorization state after rollback, an interrupted write, or an
unrecoverable generation mismatch. Supply exactly one of positional `<NAME>` or
`--profile <NAME>`. Both `--reason <REASON>` and `--acknowledge` are required.

The acknowledgement discards replay markers for every prepared, authorized,
indeterminate and settled charge; a charge settled before reset is no longer
recognized as settled. Reset requires a usable audit log and writes one
`mpp_state_reset` request row naming the profile, discarded generation and reason.
It takes the MPP store lock, rotates the HMAC key, removes the file, and sets the
counter to zero. The next prepare starts from an empty store. A failed reset can
be retried with acknowledgement; each attempt records its request before changing
state. An absent or malformed counter has a null discarded generation.
A blank or whitespace-only `--reason` exits `1` with `validation.reason_empty`
before anything changes.

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

Every subcommand's failure `error.code` is one of a closed set: the verb-specific codes noted under each subcommand below, plus these codes shared across the whole group: `credentials.invalid_profile_name` (any subcommand given a malformed `--profile`), and — from the underlying `CredentialsError` — `credentials.not_found`, `credentials.duplicate_name`, `credentials.invalid_name`, `credentials.io_error`, `credentials.registry_parse_failed`, `credentials.registry_serialise_failed`, `credentials.state_dir_unavailable`, `credentials.approval_store_error`, `credentials.approval_store_unavailable`, `credentials.bridge_start_failed`, `credentials.bridge_shutdown_failed`, `credentials.atomic_write_failed`, `credentials.signing_failed`, `credentials.missing_public_key`, `credentials.malformed_public_key`, and a generic `credentials.error` fallback for any other internal variant. `add-passkey` additionally emits `credentials.approval_store_dir_unavailable`, `credentials.approval_store_open_failed`, and `credentials.unknown_registration_outcome`. An agent can switch on `error.code` alone; `error.message` carries the human-readable detail only.

### `credentials add-passkey <NAME>`

State-changing (writes the registry; performs a browser WebAuthn ceremony). Opens the OS default browser to the wallet-owned bridge registration URL and polls the approval store until the browser-side ceremony completes or the deadline elapses. On success it writes the credential metadata to the registry. If the browser cannot be launched, the URL is printed to stderr and polling continues.

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
(the message names the recovery runbook).

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

The command renders stored request data alongside the serving profile context.
The recorded process uid must match the approving local user.
Consent records an HMAC attestation, or persists a toolset grant and consumes its pending request.
The versioned HMAC binds the profile name, CAIP-2 chain id, approval nonce, digest, and process uid.
The agent verifies it before executing.
See [concepts](../concepts.md) for the attestation model and [toolsets](../toolsets.md) for first-invoke grants.

A `require_approval` rule's `ttl_secs` sets the pending entry's lifetime,
from 1 second to 604800 seconds (seven days); when omitted, the lifetime is 24
hours. Its optional `reason`, at most 512 characters, is shown in the
MCP approval response, `approve list` JSON and table output, and the trusted
CLI approval prompt. The reason is display text and grants no authority.

The CLI summary and both inbox detail pages show the profile name, CAIP-2 chain id, endpoint authority, and enrolled signer.
An enrollment placeholder appears as `(not enrolled)`.
Payment, claim, and trustline rows show the envelope's effective source; an operation source overrides the transaction source.
An undecodable envelope appears as `(undecodable envelope)`.
A claim whose stored summary source differs also shows `Source (stored summary)`.
Trustline summaries show the full holder account, asset code, issuer, limit,
simulated fee, and sequence number.
The CLI names the action `trustline change (ChangeTrust)`.
The CLI limit reads `unlimited`, `0 stroops (removes the trustline)`, or the exact
stroop count and decimal asset amount.
Both inboxes label it `TRUSTLINE` and offer `Approve trustline`.

The `approve`, `approve gc`, `approve list`, and `approve serve` commands return failures with `error.code` and a plain diagnostic message.
These failures carry `approval.*` codes: `approval.not_found`, `approval.expired`, `approval.already_attested`, `approval.user_mismatch`, `approval.clock_error`, `approval.sha256_hex_error`, `approval.key_decode_failed`, `approval.key_length_error`, `approval.binding_mismatch`, `approval.grant_persist`, `approval.wrong_kind`, `approval.rejected`, `approval.consumed`, `approval.record_failed`, `approval.uid_unavailable`, `approval.denied`, `approval.store_dir_error`, `approval.permission_denied`, `approval.invalid_nonce_length`, `approval.writer_locked`, `approval.store_open_failed`, `approval.gc_failed`.
`approval.gc_failed` reports a collection failure from `approve gc`.
Authentication, validation, and audit failures on approval paths carry their own codes.

### `approve --id <NONCE> --profile <name>`

State-changing (records an attestation or a grant in the on-disk pending-approval store).

- `--id <NONCE>` (required in this form) — the approval nonce printed in the agent surface's simulate response.
- `--profile <NAME>` — the profile whose attestation key and pending-approval store to use. Optional; resolves from `--profile`, then `STELLAR_AGENT_PROFILE`, then `"default"`.
- `--yes` — non-interactive auto-approve. Bypasses the stdin prompt; the wallet-controlled summary is still printed so there is a visible record. Intended for trusted automation and tests, not routine operator use.

Interactively, the command prints the summary and prompts `Approve? [y/N]:`; anything other than `y`/`yes` denies. It exits `1` when the nonce is unknown, expired, already attested, created by a different local user, denied at the prompt, or on an I/O error.

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

The printed URL contains a single-use bootstrap token: the first visit
exchanges it for an HttpOnly session cookie and the token dies. All state
mutation requires that cookie plus a per-action CSRF header; the server binds
`127.0.0.1` only and refuses non-loopback hosts and origins.

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
walkthrough.

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
  --remote` listener. Starts a one-shot local server, prints (and by default
  opens) an enrollment page, and persists the credential automatically once
  your authenticator completes the ceremony. The printed URL contains a
  single-use bootstrap token: the first visit exchanges it for an HttpOnly
  session cookie and the token dies, and both serving the page and the POST
  that persists the credential require that cookie, so a local non-browser
  process cannot drive the ceremony. The server binds `127.0.0.1` only and
  refuses non-loopback hosts and origins. Always produces a credential bound
  to `rp_id: "localhost"` — the only effective domain a loopback origin can
  claim.
- **`--credential-id` / `--public-key` / `--rp-id` / `--label`** (all four
  together) — for a domain-configured remote listener. Imports the id and
  public key from a WebAuthn ceremony run elsewhere: normally the remote
  listener's own `GET /enroll` page, which has to be served from
  `https://<rp_id>` for the resulting credential to bind to that domain. See
  [Remote approval](../remote-approval.md) for that page's walkthrough.

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
- `--timeout-seconds <SECS>` — interactive-ceremony timeout (default: 300).
- `--sign-count <U32>` — seeds the clone-detection baseline from a counter
  read at enrollment time (argument mode only; interactive mode extracts
  this automatically). Advisory only — a caller reporting a false value only
  weakens that credential's own clone-detection baseline and never affects
  authorization, which is decided solely by `allowed_credentials`.

## `audit`

The `audit` group verifies the per-profile audit log, an append-only, hash-chained JSONL record of transaction submissions, signed authorizations, approvals, and explicit key-management and lifecycle events, and repairs its tip anchor. MCP balance reads and payment simulations produce no automatic invocation row. Under V1, payment simulations can reconcile overdue reservations and write settlement audit rows. Argument values are never logged; only argument key names are recorded. The chain links each entry to the SHA-256 of the prior entry's canonical body, so any external modification breaks verification.

The chain and the per-file chain-root signatures verify a PREFIX of the log, so an older copy of the active file, or a truncated one, passes both. What pins the END of the chain is the tip anchor: the active file's entry count, last-entry hash, and byte offset, held in the platform keyring per log path. Every value-moving verb checks it before signing, and `audit verify --profile` checks it too.

### `audit verify <LOG_PATH>`

Read-only. Walks the log at `<LOG_PATH>`, following rotation manifests across rotated files, and verifies that the hash chain is intact end to end. When `--profile` is supplied, it additionally loads that profile's audit chain-root HMAC key and verifies the chain-root sidecars; without `--profile`, only the hash chain is checked and `hmac_verified` is reported as `false`.

The tip anchor is checked only when `--profile` is supplied AND `<LOG_PATH>` is the log that profile configures. The anchor names a path, not a profile, so comparing it against a file it does not describe would report a mismatch that means nothing. Every other case reports `anchor.status` as `"not_checked"` with the reason and still verifies the chain in full. A log that moved forward past its anchor passes; a log behind it, or one whose tip is not the anchored tip, fails with `audit.tip_anchor_mismatch`.

Verifier failures use `audit.chain_broken`, `audit.rotation_gap`, `audit.hmac_mismatch`, `audit.hmac_sidecar_missing`, `audit.too_many_rotated_files`, `audit.non_regular_file_log_path`, `audit.parse_error`, `audit.path_contract`, `audit.log_not_found`, `audit.io_error`, `audit.signer_set_canonical_body`, `audit.partial_rotation`, `audit.tip_anchor_mismatch`; see [security internals](../maintainers/security-internals.md#audit-hash-chain).
Profile and ownership pre-checks carry their own codes.

- `<LOG_PATH>` (positional, required) — path to the audit log file. By default this is `~/.local/share/stellar-agent/audit/<profile>.jsonl` on Linux, `~/Library/Application Support/Soneso.stellar-agent/audit/<profile>.jsonl` on macOS, and `%LOCALAPPDATA%\Soneso\stellar-agent\data\audit\<profile>.jsonl` on Windows.
- `--profile <NAME>`: the profile whose chain-root HMAC key verifies the sidecars. Optional; when omitted, only the hash chain is verified. The profile's audit binding is read and never written: a changed or unparseable binding exits `1` with `audit.log_binding_changed`.
- `--output <FORMAT>` — output format. `json` is the default and only stable format.

On Unix, the command refuses to verify a log whose parent directory is owned by a different user, since such a directory could be used to substitute log files or sidecars. It exits `0` when the chain is intact and `1` on any integrity violation (a broken chain, a rotation gap, an HMAC mismatch, a missing sidecar, an unparseable line, or a tip-anchor mismatch), a path-contract failure, or an I/O error.

`outbox_pending` counts the consent rows queued in the audit outbox beside the log (`<LOG_PATH>.outbox`) and not yet drained into it, read without taking the outbox lock. Queued rows sit outside the tip anchor until a draining writer appends them. A torn outbox adds an `outbox_torn_tail` warning and unparseable lines add `outbox_unparseable`. An unreadable outbox adds `outbox_unreadable` and omits `outbox_pending`, since no count is known. None of them changes the chain verdict.

```bash
stellar-agent audit verify ~/.local/share/stellar-agent/audit/default.jsonl --profile default
```

```json
{"ok":true,"data":{"entries_verified":42,"files_walked":2,"hmac_verified":true,"per_file":[],"warnings":[],"audit_writer_degraded":false,"anchor":{"status":"verified","reason":null},"outbox_pending":0},"request_id":"..."}
```

### `audit reanchor --profile <NAME> --acknowledge-rollback`

State-changing (writes the keyring anchor, appends one or two audit rows, then drains the audit outbox; no network). The only way out of an `audit.tip_anchor_mismatch` or `audit.log_binding_changed` refusal. Operator-only: an agent must never run it on its own initiative.

- `--profile <NAME>` (required): the profile whose configured `audit_log_path` and audit keyring coordinate identify the anchor.
- `--acknowledge-rollback` (required to act on a rolled-back log): accept the log's current tip as authoritative.
- `--acknowledge-binding-change` (required to act on a changed binding): accept a log path or audit key that differs from the profile's recorded audit binding.

| Recorded binding | Current path's anchor | Flags required | Rows appended |
|---|---|---|---|
| Equal or absent | Any | `--acknowledge-rollback` | `rollback_acknowledged` |
| Changed or unreadable | Absent, or agrees with the log | `--acknowledge-binding-change` | `binding_changed` |
| Changed or unreadable | Disagrees with the log, or cannot be parsed | Both | `rollback_acknowledged`, then `binding_changed` |

A flag the matrix does not require is ignored. The binding is checked before the repair writer opens, and the anchor's disagreement is decided again under the writer's lock. A missing flag changes nothing and exits `1` with `validation.acknowledgement_required`, naming the flag. Without `--acknowledge-rollback` on an equal or absent binding the command reports the anchor in force and the anchor it would write, both as `<entry count>:<byte offset>`, changes nothing, and exits `1` with `validation.acknowledgement_required`. Moving the anchor forgives whatever made the log disagree with it, and the command cannot tell a restored backup from tampering. That judgement is the operator's, and it wants to be made before the evidence moves.

With the required flags, the command replays the whole log first, so a log whose own chain is broken is refused rather than blessed. It writes the current tip as the anchor, bumps the current path's re-anchor counter held in the keyring once, and appends the rows, each carrying that count. `rollback_acknowledged` names the superseded anchor. `binding_changed` names the anchor of the log path the previous binding named, or none when the record was unreadable. The rows are permanent: the log carries its own record that a rollback or a binding change was accepted. The new binding is stored last, so a run that stops earlier leaves the refusal in place, and an absent binding is recorded after a rollback repair. The envelope lists the conditions acknowledged and how the recorded binding compared.

Queued consent rows follow the repair rows and are counted in `outbox_drained`. A drain refusal leaves the repair in force and exits `0`. It omits `outbox_drained`, since every queued row stays queued, and lists the refusal under `warnings`: `audit.outbox_unusable`, `audit.outbox_busy`, or the condition an append refused on, such as `audit.io_error`.

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

## The governance loop

`approve` and `audit verify` are the operator's two touch points in the guardrail loop:

1. The agent surface evaluates an action against the policy engine. An action that needs operator consent records a pending approval and returns its nonce instead of executing.
2. The wallet owner runs `approve --id <NONCE> --profile <name>` in a trusted context, reads the wallet-controlled summary, and consents. The command writes an HMAC attestation (or a toolset grant) bound to the profile name, chain id, approval nonce, envelope digest, and local user.
3. The agent surface verifies the attestation and executes. The commit writes its transaction audit events to the hash-chained audit log.
4. The operator periodically runs `audit verify` to confirm the log has not been tampered with, supplying `--profile` to check the chain-root HMAC sidecars and the tip anchor as well as the hash chain.

Key rotation backs this loop: `rotate-attestation-key` invalidates outstanding approvals, and `rotate-audit-key` re-keys the chain root and re-signs every existing per-file sidecar. See [concepts](../concepts.md) for the full model.
