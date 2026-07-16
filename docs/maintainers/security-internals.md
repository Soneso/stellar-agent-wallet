# Security internals

This document describes the cryptographic primitives behind the Stellar Agent Wallet guardrail spine: the approval attestation, the hash-chained audit log, the wallet unlock window, the nonce scheme, the V1 policy evaluator, and the smart-account auth digest. It is written for a maintainer or security reviewer who needs the byte-level detail, not the operator-facing model. For the model itself see [Concepts](../concepts.md); for how the crates fit together see [Architecture](architecture.md).

Both surfaces — the `stellar-agent` CLI and the `stellar-agent-mcp` server — share the attestation, audit hash-chain, nonce, policy-evaluator, and auth-digest primitives below. The wallet unlock window (mlock plus TTL) is the exception: it protects the CLI's `--secret-env` signing path, where the seed is loaded into pinned memory. The MCP server does not call `Wallet::unlock`; its signing goes through keyring signer handles, so the [Wallet unlock lifecycle](#wallet-unlock-lifecycle) section below applies to the CLI surface only. testnet (`stellar:testnet`) is the default; every write or signing command structurally refuses mainnet (`stellar:mainnet`) with wire code `network.mainnet_write_forbidden` — `--network` commands before any RPC call or signing, profile-driven flows at the network submit layer before any transaction is sent.

## Attestation primitive

When the operator runs `approve`, the wallet records an HMAC-SHA256 attestation that proves the keyring holder ran the command. The primitive lives in `crates/stellar-agent-core/src/approval/attestation.rs`.

### Canonical input

`compute_attestation(key, approval_nonce, envelope_sha256, process_uid)` feeds the HMAC in this order:

```text
mac.update(u32_be(len(approval_nonce)))   // 4-byte length prefix
mac.update(approval_nonce)                // variable-length UTF-8
mac.update(envelope_sha256)               // 32 bytes, fixed-length, no prefix
mac.update(u32_be(len(process_uid)))      // 4-byte length prefix
mac.update(process_uid)                   // variable-length UTF-8
```

The two variable-length fields carry a big-endian `u32` length prefix; the 32-byte envelope digest is fixed-width and needs none. The prefixes prevent boundary-collision attacks: without them two different `(nonce, uid)` pairs whose bytes concatenate identically would produce the same tag. A known-answer test pins the exact layout so an accidental change to the preimage is caught.

### Key custody

The key is the profile's `attestation_key_id` keyring entry, a 32-byte secret. The module takes the key as `&[u8; 32]` and implements only the HMAC. The caller loads it from the platform keyring into a `Zeroizing<[u8; 32]>`, passes `&*key`, and drops the guard immediately after the call. No key bytes are returned, transmitted, or written to disk.

### Constant-time verify

`verify_attestation(...)` recomputes the expected tag and compares with `subtle::ConstantTimeEq` to avoid timing side-channels. It returns a plain `bool`; the consumer never branches on partial-match progress.

### Process-uid binding and non-replay

`process_uid` is the numeric OS uid of the approving process. Binding it into the HMAC gives cross-account-on-host non-replay: a blob minted by uid `1000` does not verify when presented by uid `2000`, because the recomputed tag differs. The attestation proves the keyring holder ran `approve`; it is not a proof that a human clicked "yes" in an agent UI.

### Key rotation invalidates pending approvals

The attestation tag is keyed by the live `attestation_key_id` entry. Rotating that key changes the HMAC key, so every already-minted attestation in the pending store fails verification on the next `_commit`. Rotation therefore invalidates all outstanding approvals; the operator must re-approve.

### Kind-specific digests

Two approval kinds bind extra fields by hashing them into the 32-byte slot that `compute_attestation` treats as `envelope_sha256`. Each uses a versioned domain-separation tag so a layout change forces old blobs to fail closed rather than cross-validate:

- `ToolsetFirstInvokeGate` — `compute_toolset_gate_digest` hashes `TOOLSET_GATE_DOMAIN_TAG` (`stellar-agent-toolset-grant:v1`) followed by length-prefixed `toolset_name`, `capability`, `destination` (G-strkey), `asset`, then the fixed-width `amount_min_stroops` and `amount_max_stroops` as big-endian `i64`. `verify_toolset_gate_attestation` recomputes this digest and feeds it through `verify_attestation`.
- `TrustlineClawbackOptIn` — `compute_trustline_clawback_opt_in_digest` hashes `TRUSTLINE_CLAWBACK_OPT_IN_DOMAIN_TAG` (`stellar-agent-trustline-clawback-opt-in:v1`) followed by length-prefixed `network`, `code`, `issuer`.

The first-invoke gate is a re-prompt suppressor only. The per-action `PaymentSimulated` approval still fires unconditionally on every toolset-routed payment and binds the actual executed envelope through `envelope_sha256`, so a forged or tampered grant can suppress at most the re-prompt — it cannot bypass the per-action approval, whose tag the keyring-only HMAC key protects.

## Audit hash-chain

The audit log is a per-profile append-only JSONL file (`~/.local/share/stellar-agent/audit/<profile>.jsonl` on Linux; `~/Library/Application Support/Soneso.stellar-agent/audit/<profile>.jsonl` on macOS; `%LOCALAPPDATA%\Soneso\stellar-agent\data\audit\<profile>.jsonl` on Windows — see `stellar_agent_core::profile::schema::canonical_data_root` for the derivation). The entry schema and canonical-JSON rules live in `crates/stellar-agent-core/src/audit_log/entry.rs`; the chain primitives in `audit_log/chain.rs`; verification in `audit_log/verify.rs`.

### Per-entry hash

```text
current_entry_hash = SHA-256( canonical_json(entry without previous_entry_hash) || previous_entry_hash )
```

`canonical_json` is `serde_json` output with fields in struct-declaration order. The `previous_entry_hash` field is set to `""` (empty string, never JSON `null`) in the hashed body so the hash does not depend on itself; the real predecessor hash is concatenated separately. Hashes are stored as `sha256:<hex>` strings.

### Genesis and rotation handoff

The very first file's first entry chains off `ZERO_BLOCK_HASH`, which is `SHA-256([0u8; 32])` — `sha256:66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925`. The zero-block hash is used only for that one entry.

On rotation, the outgoing file's last entry is an `AuditRotationHandoff { next_file_name }`. The next file's first entry chains off that handoff entry's hash, not the zero-block hash, bridging the chain across files. The `next_file_name` records the rotated archive name of the file the handoff is written into, binding the rotation to a specific filename.

### Writer lock and reader concurrency

The writer's mutual exclusion lives on a sidecar lock file (`<log>.lock`), never on the log file itself: `AuditWriter::open` acquires an exclusive OS lock on the sidecar before touching the log, holds it for the writer's whole life (including across rotation, whose archive rename and exclusive create rely on it), and the OS releases it on drop or process death. The log file carries no OS lock on any platform, so readers (`audit verify`, the `find_*` scans) never contend with a live writer — load-bearing on Windows, where an exclusive file lock is enforced against reads through every other handle. The writer keeps a single handle for every read and write of the active log as a consistency invariant.

Readers can observe two transient states: a torn last line during an in-flight append (reported as a parse error on that entry, exactly as a genuine truncation would be), and a briefly absent active file between rotation's rename and create. For the latter, readers and `verify_log` re-scan within a small bounded window, gated on the sidecar lock being observably held by a live writer; an unheld lock reports the gap immediately, and the tolerance can only delay — never suppress — a `RotationGap`, chain-break, or HMAC failure. The lock-liveness probe momentarily acquires the sidecar lock, so `verify` may create the `.lock` file (and can, in a microsecond window, surface spurious contention to a concurrently STARTING writer — fail-closed and retryable); verification of a copied-off audit directory is therefore not strictly side-effect-free on that anomalous path.

### Per-file root HMAC sidecar

Each log file gets a `<file>.root_hmac` sidecar holding an HMAC-SHA256 tag (`sha256:<hex>`) over the chain root, keyed by the profile's `audit_log_hash_chain_key_id`. `sign_chain_root` mints it; `verify_chain_root` checks it with a constant-time comparison (`subtle::ConstantTimeEq`) against the supplied key. The sidecar is renamed alongside the log file on rotation.

### What `audit verify` checks

`verify_log(log_path, hmac_key)` collects the file chain (rotated siblings oldest-first by filename, then the active file) and walks it. Per file it enforces:

1. Each entry's `previous_entry_hash` equals the recomputed hash of the prior entry's canonical body; a mismatch is `ChainBroken`.
2. The first entry of each non-first file chains off the preceding file's last entry (the cross-file bridge).
3. Each rotated file's `AuditRotationHandoff.next_file_name` matches that file's actual basename, defeating file-substitution attacks; a mismatch, a missing handoff in a rotated file, or a handoff appearing in the active file is `RotationGap` / `ChainBroken`.
4. When `hmac_key` is supplied, each file's `.root_hmac` sidecar verifies on its first entry; a wrong tag is `HmacMismatch` and a missing sidecar is `HmacSidecarMissing` (with a key configured, a sidecar must exist for every file).

The `EventKind` match in the verifier is exhaustive with no wildcard arm, so adding an event variant forces a compile error until the verifier is updated.

A backward timestamp jump larger than `BACKWARD_TS_WARN_THRESHOLD_MS` (60000 ms) is reported as a warning, not a failure, because NTP corrections can move wall-clock time backward.

### Closed wire-code set

Every `VerifyError` maps to one code from a fixed set; the line number and file basename go in the envelope `detail`, never the code, keeping cardinality bounded:

`audit.chain_broken`, `audit.rotation_gap`, `audit.hmac_mismatch`, `audit.hmac_sidecar_missing`, `audit.too_many_rotated_files`, `audit.non_regular_file_log_path`, `audit.parse_error`, `audit.path_contract`, `audit.log_not_found`, `audit.io_error`, `audit.signer_set_canonical_body`, `audit.partial_rotation`.

A missing primary log surfaces `audit.log_not_found` and is classified validation-class (user-actionable: nothing has been written yet, or the path is wrong), distinct from an integrity violation.

The non-regular-file check rejects directories and symlinks before open, closing a symlink-redirect surface. A detected mid-rotation crash state (`PartialRotation`) is surfaced as an error and requires operator intervention; it is never auto-recovered, because silent recovery could mask a tamper attempt that manufactured the same directory state.

### Value-action emission sites

Every verb that moves value writes a `value_action_submitted` row after — and only after — the on-chain action confirms, carrying the SAME value legs the policy gate sized (single-derivation invariant: the legs are the `ValueEffects` the gate evaluated, never re-derived at the emission site). The redacted transaction hash (first-8-last-8) and confirmed ledger are recorded; the row never carries key material. Emission is non-fatal: a row-write failure after a confirmed submit logs a warning and never changes the result. A DeFi adapter that instead FAILS at submit records a `sa_raw_invocation` row (with the mapped `SaInvocationResult`) in its error arm. x402 authorization signing is the exception to the row kind: it writes `x402_payment_authorized` — its own `EventKind` carrying legs, network, and scheme — rather than `value_action_submitted`, because the wallet signs the payment authorization without submitting.

| Surface | Verb / tool | Row |
| --- | --- | --- |
| MCP | `stellar_pay_commit`, `stellar_create_account_commit`, `stellar_claim_commit`, `stellar_trustline_commit` | `value_action_submitted` (sized legs) |
| MCP | `stellar_blend_lend`, `stellar_dex_trade`, `stellar_defindex_vault_deposit`, `stellar_defindex_vault_withdraw` | `value_action_submitted` on success; `sa_raw_invocation` on submit failure |
| MCP | `stellar_x402_create_payment`, `stellar_x402_authenticated_payment` | `x402_payment_authorized` (its own `EventKind` carrying legs, network, and scheme) |
| MCP | `stellar_sep43_sign_and_submit_transaction` | `value_action_submitted` (opaque: empty legs + `opaque_reason`) |
| CLI | `pay`, `claim`, `accounts create` (sponsored mode only), `trustline`, `trade` | `value_action_submitted` (sized legs) |

The value descriptor reaches the emission site through the policy engine's `evaluate_full` / `evaluate_with_value_full`, which surface the sized `ValueEffects` on the allow path; the decision-only `evaluate` / `evaluate_with_value` views discard it and must never gate a value-moving dispatch (see the rustdoc on those methods). Rows are written under the profile's `audit_log_hash_chain_key_id`, loaded through the single `stellar_agent_network::keyring::load_hmac_key_32` source, so `audit verify` covers them.

The emission layer differs by surface. The CLI `pay`, `claim`, `accounts create`, and `trustline` verbs and the CLI `trade` verb emit at the CLI layer. The Blend, DEX, and DeFindex submits emit inside the shared DeFi adapters, so both the MCP and CLI DeFi paths route through the same emission site rather than each surface emitting its own row.

### Key-write emission sites

Each profile command that writes long-lived key material to the keyring records a `keyring_key_written` row after the write succeeds, naming the key slot (`key_purpose`) and the keyring coordinates. The two enroll commands additionally record a redacted (first-5-last-5) public address; HMAC-key rotations record none. The row NEVER carries a key value, seed, base64 material, or any derived secret.

| Command | `key_purpose` | Public address |
| --- | --- | --- |
| `profile enroll-signer` | `mcp_signer_seed` | redacted derived address |
| `profile enroll-owner-key` | `owner_public_key` | redacted owner address |
| `profile rotate-nonce-key` | `nonce_hmac` | none |
| `profile rotate-attestation-key` | `attestation_hmac` | none |
| `profile rotate-counterparty-key` | `counterparty_cache_hmac` | none |
| `profile rotate-audit-key` | `audit_hash_chain_hmac` | none |

`rotate-audit-key` is ordered persist-before-resign: it (1) writes the new key, (2) re-signs every per-file chain-root sidecar with the new key so `audit verify` stays green across the rotation, then (3) emits the `keyring_key_written` row under the new key. Emitting the row before the re-sign would append a row the freshly rotated key cannot verify.

## Wallet unlock lifecycle

The unlock window holds a 32-byte signing seed in pinned, zeroize-on-drop memory for a bounded TTL. It is entered by the CLI secret-env signing path; the MCP server signs through keyring signer handles and never enters it. The lifecycle manager is `Wallet` in `crates/stellar-agent-core/src/wallet/lifecycle.rs`; the locked seed holder is `LockedSeed` in `wallet/mlock.rs`.

### Zeroizing seed and eager pin

`Wallet::unlock(profile_name, seed, ttl_seconds, mlock_required)` is async (Tokio). The seed is moved into a `Zeroizing<[u8; 32]>` and its backing page is pinned with `region::lock`, which calls plain `mlock(2)` (POSIX) or `VirtualLock` (Windows). Plain `mlock(2)` eagerly populates and pins pages at lock time; for a small, immediately-read seed this is at least as strong as `mlock2(MLOCK_ONFAULT)` and closes the pre-first-fault swap-disclosure window that the on-fault variant would leave open.

### MlockRequired postures

`MlockRequired` has three postures controlling behaviour when `mlock` fails:

| Value | Behaviour on `mlock` failure |
|-------|------------------------------|
| `true` (default Linux/macOS) | Fail closed: `WalletLifecycleError::MlockUnavailable`; unlock aborted, seed zeroed. |
| `"warn"` (default Windows) | Proceed with unprotected memory; emit `tracing::warn!`. |
| `false` | No lock attempted; no warning (operator accepts swap-disclosure risk). |

On `mlock` failure the module emits a structured `tracing::warn!` carrying `profile`, `reason`, and `errno` — never the seed. The `EventKind::WalletMlockFailed` audit emission is wired at the calling CLI surface; this module's handover point is the tracing span.

### TTL cap and RAII dispose

The default TTL is `DEFAULT_TTL_SECONDS` (30); the hard cap is `MAX_TTL_SECONDS` (600). `unlock` rejects `ttl_seconds == 0` or `ttl_seconds > 600` with `WalletLifecycleError::TtlInvalid`. The profile field `wallet.unlock_ttl_seconds` is validated against that range when the window is constructed: a value of 0 or above 600 is refused, never clamped.

A background `tokio` task sleeps for the TTL and then marks the wallet disposed. A shared `AtomicBool` cancel flag lets an early `dispose()` short-circuit the timer. On every drop path — normal return, `?` propagation, or panic-unwind — `Drop` calls `dispose()` unconditionally, zeroizing the seed and releasing the lock. `Wallet` is intentionally **not** `Send + Sync`; callers needing shared access wrap it in `Arc<Mutex<Wallet>>` or use the MCP server's per-request ownership model.

## Headless keyring store

Windows Credential Manager requires an interactive logon session; a Windows service, an SSH/WinRM session, or a scheduled task fails every keyring read/write with `auth.keyring_interactive_session_required`. The `stellar-agent-headless-keyring` crate provides an opt-in, file-backed alternative for exactly this deployment shape. It implements `keyring_core::api::CredentialStoreApi` / `CredentialApi` and slots in behind the SAME `KeyringEntryRef` (service, account) coordinates every existing enroll/rotate/sign call site already uses — `keyring_core::Entry::new(service, account)` is unchanged everywhere; only which concrete store answers it differs.

### Activation surface

`stellar_agent_network::keyring::init_platform_keyring_store` — called unchanged at every existing keyring-consuming call site across the CLI and MCP server (~25 sites) — checks the `STELLAR_AGENT_KEYRING_BACKEND` environment variable FIRST. Unset: the platform keyring (unchanged default). Set to `"headless-env"` or `"headless-dpapi"`: the headless store is registered as the process default instead, and initialisation NEVER falls back to the platform keyring on any failure (missing/invalid key, unsupported platform, or state-directory resolution failure all refuse). There is no profile-file `[keyring] backend = ...` surface: threading a `Profile` reference through every `init_platform_keyring_store()` call site (most of which have no loaded profile in scope at that point) was judged not worth it against an env var that already fully serves the deployment shape this feature targets.

### Protection modes and trust model

| Mode | Env var | Primitive | Trust boundary |
|------|---------|-----------|-----------------|
| `headless-env` | `STELLAR_AGENT_HEADLESS_KEYRING_KEY` (32-byte URL-safe base64, no padding) | XChaCha20-Poly1305 (`chacha20poly1305` crate) | The env var is the root of trust: any reader of it can decrypt every entry. Targets Linux services and CI where a secret manager already injects env vars under trusted access control. |
| `headless-dpapi` (Windows only) | none | `CryptProtectData` / `CryptUnprotectData`, CurrentUser scope, via `stellar-agent-windows-identity`'s `dpapi_protect` / `dpapi_unprotect` (`CRYPTPROTECT_UI_FORBIDDEN` — never blocks on a UI prompt) | The SAME trust boundary as Windows Credential Manager (any process running as the same Windows user can decrypt), minus the interactive-logon-session requirement DPAPI CurrentUser scope does not have. |

Both modes are tamper-evident and fail closed: XChaCha20-Poly1305 carries its own Poly1305 authentication tag (a tampered ciphertext fails to decrypt); DPAPI blobs are self-authenticating (`CryptUnprotectData` fails on a modified blob). The `env-key` mode additionally binds `service`||`\0`||`account` as AEAD associated data, so a ciphertext relocated to a different entry coordinate fails to open — DPAPI has no AAD concept, so this binding does not apply to `headless-dpapi` (documented scope limitation, same as Credential Manager's own lack of one).

### Storage

One JSON file for the whole host/user (not one per profile — the `(service, account)` coordinate space inside the file is already profile-scoped by convention, mirroring the platform keyring's own single-shared-store shape) at `<canonical_data_root>/headless-keyring/store.keyring`. Written atomically: temp-file + `sync_data` + rename + parent-directory fsync (`0600` on Unix), the same discipline `PersistedWindowStore` (policy window-state) and the audit-log sidecar writer use. A corrupted or unparseable file fails every subsequent read closed (`keyring_core::Error::BadStoreFormat`) rather than silently behaving as an empty store. This store does not coordinate concurrent writers across OS processes beyond the atomic rename's own last-writer-wins guarantee — out of scope for the target deployment shape (one long-lived MCP server process, or one-shot CLI invocations that do not overlap).

### Audit and logging

Enrollments/rotations through this store emit the SAME `KeyringKeyWritten` audit row every existing profile command already emits (that emission is keyed off `keyring_core::Entry::set_password` succeeding, which is backend-agnostic — no code change was needed for this to work). The store additionally emits a `headless_keyring.write` tracing log line naming the active protection mode (`backend = "headless-env" | "headless-dpapi"`), so the backend kind is visible in logs without a hash-chained audit-schema change.

## Nonce scheme

The nonce primitive lives in the `stellar-agent-nonce` crate (`crates/stellar-agent-nonce/src/lib.rs`). The MCP server mints a nonce at simulation time and verifies it at commit time through a replay window.

### Wire format and salt

A `Nonce` is 48 bytes, transmitted as URL-safe base64 with no padding:

```text
bytes[0..16]  = random salt (OsRng)
bytes[16..48] = HMAC-SHA256 tag (32 bytes)
```

The salt does not feed either side of the HMAC. Its role is uniqueness (two calls with the same envelope in the same millisecond still produce different nonces) and serving as the HashMap key for the replay window.

### HMAC input domain

```text
HMAC-SHA256( profile_nonce_key,
    boot_nonce              ||   // 16 bytes, process-scoped
    SHA-256(envelope_xdr)   ||   // 32 bytes
    expiry_unix_ms          ||   // 8 bytes big-endian u64
    u32_be(len(tool_name))  ||   // 4-byte length prefix
    tool_name               ||   // variable-length UTF-8
    u32_be(len(chain_id))   ||   // 4-byte length prefix
    chain_id )                   // variable-length UTF-8
```

The length prefixes on `tool_name` and `chain_id` prevent boundary collisions between different `(tool_name, chain_id)` pairs.

### In-memory replay window and boot_nonce fail-closed

`ReplayWindow` is a `HashMap`-backed single-use tracker with TTL eviction; it is not persisted across process restarts. The fail-closed-on-restart property comes from `boot_nonce`: a 16-byte `OsRng` value initialised once per process and never persisted. A nonce minted before a restart carries the old `boot_nonce` baked into its HMAC tag, so after restart the recomputed tag differs and the nonce is rejected (`HmacMismatch`). An in-memory-map-only design was rejected because an empty post-restart map would accept a pre-restart nonce on first presentation; a persistent counter was rejected because it would let an operator opt out of fail-closed-on-restart.

### Key residency and rotation

The HMAC key is the profile's `mcp_nonce_key_alias` keyring entry, stored as URL-safe-no-pad base64 (platform keyrings accept UTF-8 passwords; raw bytes can fail on some backends). `NonceMint` holds no key bytes: every `mint` / `verify` lazy-loads the key into a `Zeroizing` guard for a single stack frame, copies the first 32 bytes into a `Zeroizing<[u8; 32]>`, and drops the intermediates immediately. `rotate_nonce_key` generates 32 fresh `OsRng` bytes, base64-encodes them, and atomically swaps the keyring entry; the CLI exposes this as `profile rotate-nonce-key`.

## Policy V1 evaluator

`PolicyEngineV1` (`crates/stellar-agent-core/src/policy/v1/mod.rs`) is the signature-verified typed-criteria engine, active when `profile.policy.engine = V1` (the default for newly-minted profiles). The alternative, `NoopPolicyEngine` (`policy/mod.rs`), is selected by `engine = "noop"` and is the binding mainnet write gate: testnet allows all tools; mainnet read-only (`destructive_hint = false`) allows; mainnet destructive returns `Err(PolicyError::NotImplemented)`, surfaced as `policy.engine_required`.

### First-match default-deny

`PolicyEngineV1` wraps one `PolicyDocument` whose owner ed25519 signature is verified at load. `evaluate` resolves the rules whose `ScopeId` matches `(profile_name, project_id)`, then walks them in declaration order. The first rule whose `RuleMatch` (tool name + chain-id filter) matches is selected; its criteria run in order; the first criterion returning `Ok(Some(reason))` produces `Decision::Deny`. If every criterion passes, the rule's `decision` is returned. If no rule matches, the engine returns `Decision::Deny(DenyReason::NoMatchingRule)` — default-deny.

### Criteria catalog

Each criterion is a `Box<dyn Criterion>` (`Send + Sync`) with a snake_case kind tag. The catalog (`policy/v1/criteria/mod.rs`):

| Kind tag | Purpose |
|----------|---------|
| `per_tx_cap` | Per-transaction value cap |
| `per_period_cap` | Sliding-window per-period value cap |
| `rate_limit` | Sliding-window call-rate limit |
| `counterparty_allowlist` | Destination allowlist (`G_ACCOUNT` / `C_ACCOUNT` / `KNOWN_ISSUER` / `HOME_DOMAIN`; `SEP10_IDENTITY` and `ONE_TIME_ADDRESS` are reserved, not evaluated); `KNOWN_ISSUER` checks debit legs only unless the criterion's `gate_inflows = true` opt-in extends it to inflow legs too |
| `minimum_reserve` | Minimum-reserve guard (classic-account tools only — see below) |
| `inner_invocation_count_cap` | Multicall inner-count cap |
| `bundle_aggregate_cap` | Multicall aggregate-value cap (implicitly enforces the Generic-rejection check below, on any rule that carries it) |
| `restrict_bundle_to_recognised_kinds` | Reject generic / unrecognised inner kinds |
| `bundle_per_period_cap` | Per-period cap across a bundle (implicitly enforces the Generic-rejection check above, on any rule that carries it) |
| `bundle_per_tx_cap` | Per-tx cap applied to each inner (implicitly enforces the Generic-rejection check above, on any rule that carries it) |
| `bundle_rate_limit` | Rate limit across a bundle |
| `quorum_satisfied` | Smart-account signer-group quorum |
| `home_domain_resolved` | Counterparty `stellar.toml` resolved/cached (contract counterparties only — see below) |
| `sep10_session_active` | Active SEP-10 session for the account |
| `sep45_session_active` | Active SEP-45 session for the contract |

Multicall bundles also carry a hard floor independent of policy: `evaluate_bundle` denies any bundle with more than 50 inners (`DEFAULT_INNER_INVOCATION_COUNT_CAP`) before rule resolution. Policy authors may configure a lower cap but cannot raise it above the floor.

### Persisted window-state store

`per_period_cap`, `rate_limit`, `bundle_per_period_cap`, and `bundle_rate_limit` are stateful: their evaluation reads accumulated history from `PolicyStateStore` (`policy/v1/criteria/state_store.rs`), an in-memory `Mutex<HashMap<StateKey, VecDeque<(timestamp_ms, amount)>>>`. In-memory state alone would reset to empty on every process start (and every CLI invocation is its own process), so a durable backing store is required for these criteria to actually accumulate across calls.

`PersistedWindowStore` (`stellar-agent-network::policy_state`, not `stellar-agent-core` — see the crate-placement rationale in that module's rustdoc: the store needs the keyring primitives that live in `stellar-agent-network`, and `stellar-agent-core` must not depend on `stellar-agent-network`) is one file per profile at `<canonical_data_root>/policy/<profile>.window`.

- **Format**: `[32-byte HMAC-SHA256 tag] || [canonical JSON body]`, an embedded-tag layout mirroring the counterparty `stellar.toml` cache's v2 format. `i128` amounts serialise as decimal strings, never a bare JSON number.
- **Key**: the profile's `policy_window_state_key_id` keyring coordinate (`stellar-agent-policy-window-<profile>` by convention), lazily minted on first write.
- **Lock**: `WindowStoreLock`, an OFD-advisory exclusive flock at `<store-file>.lock`, structurally identical to the counterparty cache's `CacheLock` — serialises every read-modify-write (record, reset, resign) across concurrent MCP-server and CLI processes.
- **Atomic write**: temp file + `sync_data` + rename + parent-directory fsync, the same discipline as the audit log's rotation `write_sidecar_atomic`.
- **Retention**: entries older than the largest supported window (`1w` = 604,800s) are pruned on every write.
- **Failure posture**: an unreadable, tampered (HMAC mismatch), or unparseable store file is fail-closed — `PolicyEngineV1`'s construction site hydrates the store BEFORE the engine is usable, and a hydration failure refuses engine construction (`policy.engine_unavailable` / `BuildRegistryError::PolicyEngineError`) rather than silently starting with an empty store. Recovery: `stellar-agent profile reset-window-state <name> --reason <reason>`, which re-initialises the file to empty and audits the reset (`PolicyWindowStateReset`).
- **Rotation**: `stellar-agent profile rotate-policy-state-key <name>` mints a fresh key and re-signs the store file's existing body under it (no old-key read required — the same "recompute the tag over the unchanged body" shape as `rotate-audit-key`'s chain-root sidecar re-sign), so accumulated history survives rotation.

Recording is the write side: `Criterion::record_confirmed` (default no-op; overridden by the four stateful criteria) and `PolicyEngineV1::record_confirmed` / `record_confirmed_bundle` append into the in-memory store using the identical `StateKey` derivation `evaluate` uses, then the dispatch site persists the same entries via `stellar_agent_network::policy_state::record_confirmed_window_state`. Every value-moving dispatch site (MCP `stellar_pay_commit` / `stellar_claim_commit` / `stellar_trustline_commit` / `stellar_create_account_commit`, the CLI `pay` / `claim` / `trustline` / `accounts create` verbs, `stellar_blend_lend`, `stellar_dex_trade`, `stellar_defindex_vault_deposit` / `_withdraw`, the x402 authorizers, and the multicall bundle path) calls this after a confirmed on-chain submit (or, for x402, at authorization signing — there is no on-chain submit on that path), using the SAME `ValueEffects` the paired `value_action_submitted` / `x402_payment_authorized` audit row carries (single-derivation invariant). Recording is non-fatal: a failure logs `tracing::warn!` rather than disturbing the already-committed result, at the cost of the next call under-counting against the window.

### Injected views fail closed when absent

Several criteria need state the core crate cannot fetch itself (account reserves, identity, counterparty cache, SEP-10/SEP-45 sessions, quorum). To avoid a circular dependency on the network and smart-account crates, these arrive as optional trait objects on `EvalContext` — `AccountReservesView`, `AccountIdentityView`, `CounterpartyCacheView`, `Sep10SessionView`, `Sep45SessionView`, `QuorumView` — populated by adapters in `stellar-agent-mcp` at the dispatch site. When a configured criterion's required view is `None`, the criterion returns `Err(PolicyError::CriterionEvaluationFailed)` rather than silently passing: `minimum_reserve` with no `account_view`, `sep10_session_active` with no session view, and `home_domain_resolved` with no counterparty cache all fail closed. `AccountIdentityView` is deliberately a separate trait with no default methods so a missing `home_domain` cannot become a silent allow.

### HOME_DOMAIN allowlist verification

`HOME_DOMAIN` matching in `counterparty_allowlist` requires the domain to be verified through the counterparty cache, not merely asserted. The destination's self-asserted on-chain `home_domain` must be resolved in the cache, AND the cached `stellar.toml`'s `ACCOUNTS` list must contain the account (`CounterpartyCacheView::is_account_listed`, default `false`, fail-closed). A domain absent from the cache, or present but not listing the account, denies. Operators populate the cache with `stellar-agent counterparty warm-up` / `counterparty refresh <domain>`. The deny detail distinguishes an unverified domain (not resolved in the cache) from an unlisted account (resolved, but the account is absent from `ACCOUNTS`).

### `minimum_reserve` is inapplicable to smart-account verbs

`account_view` is populated only for classic-account tools (`stellar_pay`, `stellar_create_account`, `stellar_claim`) whose acting account is a plain Stellar account with a classic `AccountEntry`. The smart-account verbs — MCP `stellar_blend_lend` / `stellar_dex_trade` / `stellar_defindex_vault_deposit` / `stellar_defindex_vault_withdraw`, and the corresponding CLI `lend` / `trade` / `vault` commands — act through a deployed smart-account contract (C-strkey); a contract has no classic `AccountEntry`, so there is no reserve state to fetch and `account_view` stays `None` on these tools by design. A rule that configures `minimum_reserve` on one of them fails closed on every call via the criterion's own `CriterionEvaluationFailed` path. The same applies to `identity_view` on these tools: the DeFi counterparty (pool / router / vault) is a contract, so a configured identity-class criterion (`home_domain_resolved`) is equally unanswerable and fails closed. Operators should not configure `minimum_reserve` or identity-class criteria on rules matching the smart-account verbs.

### Fail-closed registry construction

The policy loader (`policy/v1/loader.rs`) is fail-closed at parse time. An unknown criterion kind, a malformed criterion definition, an empty `match.tool` or `match.chain`, or any item the dispatcher cannot fully type returns `PolicyError::PolicyFileParseFailed` — the document does not load and the engine does not start with a partially-understood ruleset. Tool-registry construction is likewise fatal on duplicate registrations or an unknown engine variant, preventing a `destructive_hint = false` shadow of a destructive tool.

## MPP sponsored authorization

The testnet MPP path adds a one-shot authorization lifecycle on top of the
existing value policy, approval, signer, and audit substrates. The complete
module map and state graph live in [MPP internals](mpp.md).

The versioned authorization fingerprint length-prefixes profile, network
passphrase digest, payer, normalized request-context digest, exact challenge
digest, method, intent, sponsored mode, amount, token, recipient, and expiry.
The MPP approval additionally binds the prepared-artifact hash and every
operator-visible term. Attestation expiry is capped by both five minutes and the
challenge lifetime.

The per-profile state file is authenticated by a dedicated keyring HMAC key and
serialized under a sibling-file cross-process lock. Reads reject symlinks,
non-regular/oversized files, invalid HMAC, invalid records, reconstructed-XDR
mismatch, and duplicate identities. Writes use a bounded temporary regular file,
flush, atomic rename, and parent sync. Credentials, raw receipts, and exact
transaction hashes are never persisted.

Commit claims durable state before policy accounting or key access. Policy usage
is recorded before signing and is never refunded from an absent receipt. The
signer handle loads the secret only at the actual sign call. Mandatory signed
re-simulation precedes the authorization audit delivery gate. Any ambiguous
post-claim path becomes `indeterminate` or `authorized_withheld` and cannot sign
again. The configured RPC therefore observes signed authorization and is part of
the trust boundary.

Mainnet refusal occurs at every public MPP adapter and again in the sponsored
library boundary before RPC, state creation, keyring access, or signing. MPP is
also absent from the toolset capability router.

## Smart-account auth digest

The auth digest binds a Soroban signing payload to the context-rule ids that govern it. The primitive is `compute_auth_digest` in `crates/stellar-agent-core/src/smart_account/auth_digest.rs`.

### Computation

```text
auth_digest = SHA-256( signature_payload || context_rule_ids_xdr )
```

`signature_payload` is the 32-byte hash produced by the Soroban host (`HashIdPreimageSorobanAuthorization`). `context_rule_ids_xdr` is the XDR serialisation of `AuthPayload::context_rule_ids` — an `ScVal::Vec(Some(ScVec([ScVal::U32(...)])))`: a 4-byte `SCV_VEC` discriminant (`0x00000010`), a 4-byte `Some` marker (`0x00000001`), a 4-byte big-endian element count, then per element a 4-byte `SCV_U32` discriminant (`0x00000003`) and the 4-byte big-endian `u32` value. The result is the 32-byte `AuthDigest`, rendered as 64 lowercase hex chars by `Display`.

### Canonical rule-id encoding

Callers MUST produce `context_rule_ids_xdr` via `encode_context_rule_ids`, which emits exactly the bytes the on-chain contract hashes. Hand-assembling a length-prefixed `u32::to_be_bytes` sequence (or any other layout) computes a digest that passes `compute_auth_digest` off-chain but is rejected on-chain. The layout matches the OpenZeppelin `stellar-accounts` v0.7.2 `__check_auth` computation.

### Downgrade-attack closure and on-chain failure

Signing the digest rather than the raw `signature_payload` closes the rule-id downgrade attack by a malicious transaction sponsor: because the rule ids are inside the hashed preimage, swapping them changes the digest and invalidates the signature. A signer that signs the raw payload, or that builds a non-canonical `context_rule_ids_xdr`, produces a signature the contract rejects during `__check_auth`. The failure is on-chain at submission, not at off-chain digest computation — the silent off-chain success that breaks on submit is exactly what this primitive exists to prevent. The function logs only input byte-lengths and the one-way output digest at debug level; the raw payload and rule-id XDR are never logged.

## Redaction discipline

Audit and policy wire output never carry argument values or secrets:

- The audit log records argument key names only (`arg_keys`); values are never logged at any level.
- Strkeys (`G` / `C` / `T` / `M` / `P`) in `decision_reason` are redacted to first-5-last-5 (for example `GABC...WXYZ`).
- Transaction hashes are redacted to first-8-last-8.
- The `envelope_hash` is recorded unredacted because it is a SHA-256 digest with no user data.

Smart-account audit constructors require their strkey and hash fields to be pre-redacted at the call site (first-5-last-5 for addresses, first-8-last-8 for hashes) before the entry is built; the constructors do not redact internally. Policy `DenyReason` strkey/contract-id fields are redacted to first-5-last-5 at the MCP boundary, and the `_commit` verifier collapses `Expired` / `NotFound` / `AlreadyAttested` into the single wire code `policy.approval_required` so the caller cannot distinguish those internal states.
