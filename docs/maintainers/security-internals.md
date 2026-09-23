# Security internals

This document describes the cryptographic primitives behind the Stellar Agent Wallet guardrail spine: the approval attestation, the hash-chained audit log, the wallet unlock window, the nonce scheme, the V1 policy evaluator, and the smart-account auth digest. It is written for a maintainer or security reviewer who needs the byte-level detail, not the operator-facing model. For the model itself see [Concepts](../concepts.md); for how the crates fit together see [Architecture](architecture.md).

Both surfaces — the `stellar-agent` CLI and the `stellar-agent-mcp` server — share the attestation, audit hash-chain, nonce, policy-evaluator, and auth-digest primitives below. The wallet unlock window (mlock plus TTL) is the exception: it protects the CLI's `--secret-env` signing path, where the seed is loaded into pinned memory. The MCP server does not call `Wallet::unlock`; its signing goes through keyring signer handles, so the [Wallet unlock lifecycle](#wallet-unlock-lifecycle) section below applies to the CLI surface only. testnet (`stellar:testnet`) is the default; every write or signing command structurally refuses mainnet (`stellar:mainnet`) with wire code `network.mainnet_write_forbidden` — `--network` commands before any RPC call or signing, and at the submit layer both a declared mainnet network passphrase and a known mainnet RPC URL, each at zero RPC cost. The submit layer additionally establishes the endpoint's own network identity and binds every signature on the envelope to it; see [Submit-layer network binding](#submit-layer-network-binding).

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
5. When an anchor is supplied, the active file's tip is the anchored tip, or ahead of it; anything else is `TipAnchorMismatch`. The CLI supplies one only when `--profile` is given AND the positional path is the log that profile configures, since the anchor names a path; every other case reports `anchor.status = "not_checked"` with the reason and verifies the chain alone.

The `EventKind` match in the verifier is exhaustive with no wildcard arm, so adding an event variant forces a compile error until the verifier is updated.

A backward timestamp jump larger than `BACKWARD_TS_WARN_THRESHOLD_MS` (60000 ms) is reported as a warning, not a failure, because NTP corrections can move wall-clock time backward.

### Keyring-held tip anchor

The chain walk and the per-file root signature both verify a PREFIX. An older copy of the active log, or a truncated one, satisfies them. The tip anchor closes that gap by holding the tip's coordinates outside the file.

For each log PATH the platform keyring holds `<entry count>:<tip hash hex>:<end offset>` — the number of entries in the active file, the SHA-256 entry hash of its last entry, and the byte offset just past that entry. The writer advances all three inside `write_entry`, after the entry's `sync_data` and before the in-memory tip moves, under the sidecar lock the writer already holds. The advance is best-effort by contract: the entry is already durable, so an anchor-write failure must not be reported as a failed append.

Check semantics, applied at writer open and again on every keyed acquisition by the writer registry (which caches one writer per profile for the process lifetime, so a check only at open would miss a file replaced underneath a live writer). The check sits in the registry rather than in each caller because the registry is the only way a keyed writer is reached, and a caller that omitted it would append to a log nothing had proved current:

| Observed | Verdict |
| --- | --- |
| The file at the path is not the file this writer's handle holds | `audit.tip_anchor_mismatch`; refuse, and drop the cached writer — see **File identity** below |
| File length equals the anchored offset and the entry ending there hashes to the anchored tip | Current; accept |
| File length exceeds the anchored offset, anchored entry intact | Accept, replay the appended tail, re-anchor on the new tip |
| File length exceeds the anchored offset, anchored entry absent | `audit.tip_anchor_mismatch`; refuse — a longer internally consistent chain that does not contain the anchored entry is a substitution, and it passes the chain walk exactly as an honest log does |
| The anchored tip is the newest archive's rotation handoff | Accept: the anchor names the generation this file succeeded. Re-derive from the file, which must chain from that handoff |
| File length below the anchored offset, or the entry at the anchored offset is not the anchored one | `audit.tip_anchor_mismatch`; refuse |
| No anchor, chain verifies | Adopt the current tip, write the anchor, append `audit_tip_anchored { reason: adopted }` |
| No anchor, chain broken | Refuse |

The ahead-of-anchor case is the ordinary one, not an exception: unkeyed writers (the CLI startup advisory, the zero-config best-effort path, the read-only smart-account verbs) receive no anchor handle and append freely, and the crash window between an entry's `fsync` and the anchor write lands in the same place. Adoption with no operator action is the upgrade path for every log written before the anchor existed.

**Only a file with entries is ever anchored.** There is no anchor value meaning "this file is empty". Offset 0 is a prefix of every file, so such a value would classify every file at the path as ahead of it and a rollback — including a restore of the whole audit directory to an earlier snapshot — would be absorbed rather than refused. An absent anchor says the same thing honestly, and the adoption rule already covers it. A stored zero entry count is rejected on read rather than treated as "nothing anchored", so a corrupted value cannot disarm the guard.

**Rotation.** The anchor is advanced onto the outgoing file's handoff entry before the renames and is then left there. The file the rotation creates has no entry of its own to name, so it inherits nothing: until its first append the anchor still names the previous generation, and the rollback guard is armed on that value throughout.

That state is recognised rather than guessed. An anchor whose tip hash equals the newest archive's last entry — which `initial_chain_seed` already reads and already requires to be a rotation handoff naming that archive — describes the generation this file succeeded. Only the rotation itself writes that value: an attacker who appends a handoff to a copy of the log produces a new tip hash the anchor does not name, so the match cannot be manufactured from filesystem access. On the match the anchor is re-derived from the file at the path, which must chain from that handoff or the replay refuses. Restoring the pre-rotation directory state, or an older archive-and-active pair, therefore refuses: neither contains an archive whose handoff is the anchored one. The check runs before the length comparison, because such an anchor's count and offset describe the archive and comparing them against the file now at the path is meaningless in either direction.

**Anchored offset.** The offset is read from the file after the entry's `sync_data`, not computed as "previous offset plus bytes written". Every reader here tolerates blank lines between entries and at end of file, so a log that picked any up outside this writer has more bytes than the writer accounted for; an arithmetic offset would then name a position inside an entry and the next open would report a rollback on an untouched log. `O_APPEND` plus the exclusive lock make end of file the entry's end, which is where the reader's replay ends too.

**File identity.** Every read the anchor check makes except this one goes through the writer's single handle, which is the right source for the bytes it will append after. The file at the PATH is a different question: a `mv` over the log leaves the handle on the previous, now unnamed file, whose tail is exactly the anchored one, so every content comparison passes while the appends land where nothing can read them and the log an operator sees stays behind the anchor. The check therefore resolves the file at the path and compares its identity — device and inode on Unix, volume serial and file index on Windows, both through `same-file` — against the handle, and reads the length through the path rather than the handle. A mismatch, and a path holding no file at all, refuse under `audit.tip_anchor_mismatch`, and the refusal's detail names the log as replaced underneath the writer rather than as shorter than the anchor. The replacement is never adopted.

**The append is checked too.** A caller acquires the writer, signs, submits, and appends afterwards, so a check made only at acquisition leaves that whole span uncovered. Every append by an anchored writer therefore proves three things about the file at the path before it writes: that it is the same file the handle holds, that it is no shorter than where this writer last appended, and that the entry ending there is still the one this writer wrote. Those are the three shapes a divergence takes — a rename moves the identity, an in-place truncation moves the end, an in-place overwrite of the same length moves neither — and each refuses under `audit.tip_anchor_mismatch` with its own reason in the message. The cost is one identity comparison, one `stat`, and one entry read plus hash per row, with no keyring round trip.

A refused append is durable, not merely in-process. The action the row was going to prove has already committed, so a refusal that lived only in the writer's memory would be erased by a restart, and the file at the path — an attacker's byte-identical copy included — would satisfy the anchor again. The writer therefore anchors the row it was owed: entry count plus one, the hash that row would have carried, and the offset it would have ended at. Every file at that path is then short of the anchor by exactly that row, so every later open refuses until an operator runs `audit reanchor --acknowledge-rollback`, whose report shows one more anchored entry than the file holds and whose row records the superseded anchor permanently. An anchor exactly one entry ahead of a log whose own chain verifies is that signature. The anchor write is best-effort like every other: if the keyring rejects it, the refusal still stands for this writer and for every caller still holding it, and the next refused append retries it, but that refusal does not survive the process.

The writer is also latched: every later acquisition and every later append through that instance refuses, whatever the path holds afterwards, because its caller has already been told the append failed and a file that looks right again would only hide that. A writer's own rotation is not a divergence — the check precedes the rotation decision, and `finish_rotation` puts the handle on the file it created at the path before anything checks again — and a rotation that failed after the rename reports `audit.partial_rotation`, which is a directory state an operator repairs by hand.

The registry evicts a writer that fails the check. The entry is kept as a tombstone rather than removed, because the evicted writer holds the sidecar lock until its last holder drops it and a fresh open in that window would report `audit.writer_locked` and name the wrong remedy; while a holder remains the tombstone answers the replacement, and once the writer is unreferenced the next acquisition opens what is at the path and checks it against the anchor on its own terms.

**Scope.** The anchor names one path inside one profile's keyring namespace: its keyring service is the profile's own audit service and its account is `<audit key account>-tip-<first 16 hex of SHA-256 of the lexically normalized path>`. Repointing `audit_log_path` therefore starts a fresh anchor, which adopts. Normalization is lexical, never `canonicalize`, because the coordinate must be derivable before the log file exists; paths differing only by `.` or `..` share an anchor, paths differing through a symlink do not. Two profiles pointed at ONE log path do not share an anchor — each holds its own under its own service, each advances only on its own appends, and a rollback to the lagging one is absorbed there and refused by the other. That configuration is unsupported; `profile show` on each profile is what reveals it.

**Keyed opens always carry the anchor.** A keyed writer's rows are the ones `audit verify` covers and the ones worth removing, so a keyed open that did not advance the anchor would leave its rows unguarded. The registry's keyed entry point and the writer constructor both take a type that pairs the chain-root key with the anchor store and cannot be built without both, and one helper in the network crate produces the pair from the profile's audit keyring coordinate. The unkeyed entry point takes neither, and the anchored constructor the rotation verb uses takes the store as a required argument with the key optional, since a profile that has not minted a chain-root key yet still anchors. There is no way, at either level, to present a key without a handle.

**Residual: the replacement between the append's check and its write syscall.** The append proves the three things above and then issues the write; a replacement landing between the two still lands the row in the file that was displaced. The window is those adjacent syscalls rather than the whole sign-and-submit span, and closing it entirely would need the write and the proof to be one operation, which no filesystem offers. Detection is unaffected: the append advances the anchor to describe the displaced file, so the next acquisition refuses and every one after it refuses the file at the path as shorter than the anchor, until `audit reanchor`. Nothing is laundered — a file at the path that satisfied the advanced anchor would have to contain the very row being removed.

**Residual: the best-effort append window.** The anchor write inside `write_entry` is best-effort by contract — the entry is already fsynced, so failing the append would misreport a row that was written. A failed write latches a flag, and the NEXT append re-writes the anchor for the writer's current state before appending anything, so one transient keyring failure costs one entry of lag rather than every append thereafter.

The residual has two shapes, and they are not equally weak. Stated precisely:

| State | What is accepted |
| --- | --- |
| The anchor names an entry of this file but is behind it — between an entry's fsync and its anchor write landing | Any state at or ahead of the anchored entry. The guard LAGS: everything before the anchored entry is still refused. One entry per transient failure; a keyring outage widens it to the appends made during the outage, bounded by the next successful write |
| No anchor has ever been written for this path — a new log, a repointed `audit_log_path`, or the first keyed use of a log that predates the anchor | Anything at the path whose chain verifies. The guard is OFF: adoption takes the file as it finds it, so a rollback performed before that first acquisition becomes the baseline. There is no earlier anchored state to compare against, which is why this cannot be closed rather than why it is harmless |
| A file a rotation created, until its first append's anchor write lands — the anchor still names the archive's handoff | Any prefix of that file, down to empty, provided it chains from the handoff. The guard is OFF for that file: the rotation-completed rule re-derives from whatever is at the path. Normally one append wide, since the first append moves the anchor onto this file; a keyring outage spanning that append holds it open for the outage |

The two OFF states share a shape: the anchor names nothing in the file at the path, so there is no tip to compare a candidate against. Entries in an ARCHIVE stay guarded throughout — a rolled-back prefix of the pre-rotation file cannot chain from the archive's handoff, so it is refused, and `audit verify` walks every file regardless.

Closing all three would need the anchor written BEFORE the entry it covers — an upper-bound reservation stored in the keyring ahead of each append. That is one keyring round trip per audit row and makes a keyring outage block or unaudit appends, which is a worse failure than the window it removes. The entry stays durable first.

**Non-goal: forgery.** The anchor detects rollback, truncation, and substitution. It does not detect appended forgeries. The entry-to-entry chain hash is unkeyed, so anyone who can write the file can append a well-formed entry chaining off the current tip; the tip moves forward, which is indistinguishable from an honest append. Only each file's first entry carries a keyed tag. Detecting appended forgeries would need a per-entry keyed tag, which this substrate does not have.

`audit verify --profile` applies the same three-way rule in the same order as the writer — shorter than the anchor, then the anchored entry's intactness, then the tip at the anchored offset — reading through the writer's own backward scan rather than a second implementation, so the two surfaces cannot disagree about a given file.

**Cross-file seed.** Opening the active file needs the hash its first entry chains from: the zero block for the first file of a chain, the outgoing file's handoff entry once the log has rotated. `initial_chain_seed` reads only the newest archive's last line and requires it to BE a rotation handoff naming that archive, refusing with `audit.rotation_bridge_unusable` otherwise, so a file dropped into the audit directory under a later timestamp cannot redirect the bridge. That check is structural, not cryptographic: it does not walk the archive's chain or verify its root signature. The bridge's integrity is established by `audit verify`, which walks every file, threads the tip from one into the next, and requires each file's chain-root signature under the profile's key. Every replay inside the writer seeds through this one function; none names the zero block directly.

**Repair.** `stellar-agent audit reanchor --profile <name> --acknowledge-rollback` is the only way out of a mismatch. It replays the whole log first (a broken chain is refused, not blessed), writes the current tip as the anchor, increments a monotonic per-path re-anchor counter in the keyring, and appends an `audit_tip_anchored { reason: rollback_acknowledged, previous_anchor }` row. Without the flag it reports both anchors and exits 1 with `validation.acknowledgement_required`, changing nothing. See [Audit-log recovery](audit-log-recovery.md).

### Closed wire-code set

Every `VerifyError` maps to one code from a fixed set; the line number and file basename go in the envelope `detail`, never the code, keeping cardinality bounded:

`audit.chain_broken`, `audit.rotation_gap`, `audit.hmac_mismatch`, `audit.hmac_sidecar_missing`, `audit.too_many_rotated_files`, `audit.non_regular_file_log_path`, `audit.parse_error`, `audit.path_contract`, `audit.log_not_found`, `audit.io_error`, `audit.signer_set_canonical_body`, `audit.partial_rotation`, `audit.tip_anchor_mismatch`.

The writer adds two of its own outside that set, carried in the envelope detail rather than as `VerifyError` codes: `audit.writer_locked` when another process holds the writer lock, and `audit.rotation_bridge_unusable` when the newest archive cannot supply the cross-file chain seed.

The value-verb pre-flight surfaces those and the rest of the writer's failure classes the same way. It stays fail-closed for all of them; what it does not do is tell the operator to rotate a key that is not the problem. A tip-anchor mismatch carries `audit.tip_anchor_mismatch` and names the repair verb; a condition about the LOG — held lock, unusable bridge, broken chain, unreadable anchor, I/O — carries `audit.chain_key_unavailable` with the specific `audit.*` sub-code at the head of the detail and a pointer to the recovery runbook; only a registry path or key registration conflict keeps the wording about a conflicting registration. `audit verify`'s tip-anchor refusal carries the verifier's own message under `audit.tip_anchor_mismatch`, with the anchored and observed counts and offsets, rather than the signing-path wording.

A missing primary log surfaces `audit.log_not_found` and is classified validation-class (user-actionable: nothing has been written yet, or the path is wrong), distinct from an integrity violation.

The non-regular-file check rejects directories and symlinks before open, closing a symlink-redirect surface. A detected mid-rotation crash state (`PartialRotation`) is surfaced as an error and requires operator intervention; it is never auto-recovered, because silent recovery could mask a tamper attempt that manufactured the same directory state.

### Value-action emission sites

Every verb that moves value writes a `value_action_submitted` row after — and only after — the on-chain action confirms, carrying the SAME value legs the policy gate sized (single-derivation invariant: the legs are the `ValueEffects` the gate evaluated, never re-derived at the emission site). The redacted transaction hash (first-8-last-8) and confirmed ledger are recorded; the row never carries key material. Emission is non-fatal: a row-write failure after a confirmed submit logs a warning and never changes the result. A DeFi adapter that instead FAILS at submit records a `sa_raw_invocation` row (with the mapped `SaInvocationResult`) in its error arm. x402 authorization signing is the exception to the row kind: it writes `x402_payment_authorized` — its own `EventKind` carrying legs, network, and scheme — rather than `value_action_submitted`, because the wallet signs the payment authorization without submitting.

| Surface | Verb / tool | Row |
| --- | --- | --- |
| MCP | `stellar_pay_commit`, `stellar_create_account_commit`, `stellar_claim_commit`, `stellar_trustline_commit` | `value_action_submitted` (sized legs) |
| MCP | `stellar_dex_trade`, `stellar_defindex_vault_deposit`, `stellar_defindex_vault_withdraw` | `value_action_submitted` on success; `sa_raw_invocation` on submit failure |
| MCP | `stellar_x402_create_payment`, `stellar_x402_authenticated_payment` | `x402_payment_authorized` (its own `EventKind` carrying legs, network, and scheme) |
| MCP | `stellar_sep43_sign_and_submit_transaction` | `value_action_submitted` (opaque: empty legs + `opaque_reason`) |
| CLI | `pay`, `claim`, `accounts create` (sponsored mode only), `trustline`, `trade` | `value_action_submitted` (sized legs) |

The value descriptor reaches the emission site through the policy engine's `evaluate_full` / `evaluate_with_value_full`, which surface the sized `ValueEffects` on the allow path; the decision-only `evaluate` / `evaluate_with_value` views discard it and must never gate a value-moving dispatch (see the rustdoc on those methods). Rows are written under the profile's `audit_log_hash_chain_key_id`, loaded through the single `stellar_agent_network::keyring::load_hmac_key_32` source, so `audit verify` covers them.

The emission layer differs by surface. The CLI `pay`, `claim`, `accounts create`, and `trustline` verbs and the CLI `trade` verb emit at the CLI layer. The DEX and DeFindex submits emit inside the shared DeFi adapters, so both the MCP and CLI DeFi paths route through the same emission site rather than each surface emitting its own row.

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

`rotate-audit-key` takes the audit writer's exclusive sidecar lock first and holds it throughout, so no other process can append or rotate while the per-file sidecars are being rewritten; a running MCP server holds that lock for its lifetime, making the verb refuse with `audit.writer_locked` rather than race it (the envelope carries that code in its detail, as the `approval.*` and `counterparty.*` lock codes do). Acquiring the writer also runs the tip-anchor check before the key is touched, so a rolled-back log is refused with the profile's key left alone. It then (1) persists the new key, (2) appends the `keyring_key_written` row, and (3) re-signs every per-file chain-root sidecar with the new key. Re-signing last is what covers a row that happened to open a new file: its chain root is brought onto the new key by the same pass. Re-signing before persisting would leave sidecars signed by a key the keyring no longer holds.

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

## Submit-layer network binding

A Stellar signature commits to a network: the SEP-23 `TransactionSignaturePayload` the signer hashes carries `network_id = SHA-256(network_passphrase)`, so the same transaction signed for two networks produces two different signatures. Nothing in the wire format records which network a signature was made for; it can only be recovered by re-deriving the payload under a candidate network id and checking the signature against it. The check lives in `crates/stellar-agent-network/src/signing/verify_binding.rs`; the endpoint probe it rests on is `StellarRpcClient::verify_network_passphrase`.

### Order of operations at every submit entry point

1. A caller-declared mainnet network passphrase is refused with `network.mainnet_write_forbidden`. Zero RPC calls.
2. An RPC URL matching a known mainnet host is refused the same way. Zero RPC calls.
3. The envelope is decoded locally. A malformed envelope, or a legacy `TxV0` envelope, is refused with no round trip: V0 is not part of the SEP-23 tagged-transaction set, so neither the signing path nor this one can construct a payload for it.
4. The endpoint is asked which network it serves (`getNetwork`), on the same client instance that will send.
5. The ed25519 signer sets of the accounts whose authority the transaction invokes are fetched in one `getLedgerEntries` call.
6. Every decorated signature is verified under the network id the endpoint reported.
7. `sendTransaction`, then poll `getTransaction`.

Steps 4 and 5 are two reads ahead of the send, so every submission makes two round trips before the send.

### Endpoint identity is authoritative

The declaration states which network the caller intends; the probe states which network the endpoint is, and the second decides. Transport failures are retried with bounded exponential backoff under the caller's own submission deadline, using the same retryability classification as `sendTransaction`; a passphrase mismatch is a verdict rather than a transport fault and is not retried. The probe is fail-closed — it never falls back to the declaration.

- endpoint reports the mainnet passphrase: `network.mainnet_write_forbidden`, the one mainnet refusal that costs a round trip
- endpoint reports a different network than the caller declared: `network.endpoint_network_mismatch`
- identity not established within the submission timeout: `network.endpoint_identity_unavailable`

The probe runs on the client instance that will carry `sendTransaction`, not on a fresh one, so the identity that was established is the identity of the connection the transaction goes out on.

### Which accounts answer for which signatures

For a `Tx` envelope: the transaction's own source account and every distinct operation-level source account, because an operation-level source contributes its own authority and is signed for separately. For a `TxFeeBump` envelope: the fee source answers for the outer signatures and the inner transaction's sources for the inner ones. Muxed accounts resolve to the underlying G-account, which is where the signer set lives. The distinct set is fetched in a single `getLedgerEntries` call; an account absent from the ledger is `network.account_not_found`, refused before anything is sent.

One class of operation source is absent from the ledger by construction: an account that an earlier operation of the same transaction creates. It exists when the operation applies but not when the envelope is submitted, and its signer set at that point is exactly its own master key, which is the account id. Such an account is therefore not requested from the ledger and its candidate key is derived locally. The CAP-33 sponsored-creation sandwich is built this way, with the new account signing the `EndSponsoringFutureReserves` operation that names it as source. Deriving the key locally is not an escape hatch: the signature still has to verify under the endpoint's network id, and a mainnet-bound signature by that same account is refused like any other.

### Per-signature verdict

Each `DecoratedSignature` carries a four-byte hint, the trailing four bytes of the signer's public key. The hint narrows the gathered signers to those whose key bytes `28..32` match it; the signature must then verify against one of those candidates under the payload rebuilt for the endpoint's network id.

- verifies under the endpoint's network id: accepted
- verifies under the mainnet network id: `network.envelope_signed_for_mainnet` — a mainnet authorisation, refused whatever endpoint it was relayed to
- verifies under neither: `network.envelope_signature_unverifiable`
- a signature set carries no decorated signatures at all: `network.envelope_unsigned`, refused before the round trip. The sets are checked separately, so a fee-bump with a signed outer and an unsigned inner is refused here rather than on chain

Every signature must pass, and each signature set must have at least one. Hash-x and pre-auth-tx signers contribute no ed25519 key, so a signature only such a signer could account for has no candidate to match against and is refused rather than waved through. The posture is closed by construction: an envelope carrying a signature this layer cannot account for is not submitted.

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

`per_period_cap`, `rate_limit`, `bundle_per_period_cap`, and `bundle_rate_limit` are stateful: their evaluation reads accumulated history from `PolicyStateStore` (`policy/v1/criteria/state_store.rs`), an in-memory `Mutex<HashMap<StateKey, VecDeque<StateEntry>>>` of timestamp, amount, and pending flag. A pending entry counts whatever its age; a confirmed entry is dated from the close time of the ledger that applied it and leaves the window from there. In-memory state alone would reset to empty on every process start (and every CLI invocation is its own process), so a durable backing store is required for these criteria to actually accumulate across calls.

`PersistedWindowStore` (`stellar-agent-network::policy_state`, not `stellar-agent-core` — see the crate-placement rationale in that module's rustdoc: the store needs the keyring primitives that live in `stellar-agent-network`, and `stellar-agent-core` must not depend on `stellar-agent-network`) is one file per profile at `<canonical_data_root>/policy/<profile>.window`.

- **Format**: `[32-byte HMAC-SHA256 tag] || [canonical JSON body]`, an embedded-tag layout mirroring the counterparty `stellar.toml` cache's v2 format. `i128` amounts serialise as decimal strings, never a bare JSON number.
- **Key**: the profile's `policy_window_state_key_id` keyring coordinate (`stellar-agent-policy-window-<profile>` by convention), lazily minted on first write.
- **Lock**: `WindowStoreLock`, an OFD-advisory exclusive flock at `<store-file>.lock`, structurally identical to the counterparty cache's `CacheLock` — serialises every read-modify-write (record, reset, resign) across concurrent MCP-server and CLI processes.
- **Admission**: `record_pending` (the write that reserves a submission's spend, immediately before the send) re-applies the governing criterion's comparison under the lock it already holds, against the file it has just read and verified. Each entry carries the limit that governs its bucket (`WindowLimit::Amount { asset, window, max_stroops }` or `WindowLimit::Count { window, max_calls }`), derived from the same fields the criterion's `evaluate` compares against and never persisted. A batch any bucket can no longer admit is refused as `WindowStoreError::PolicyDenied`, carrying the `DenyReason` the criterion produces for that condition, and nothing is written; entries of one batch on one key accumulate against each other. A same-key pending record dated more than 30 seconds past the entry's own clock fails the gate's query closed, and admission refuses it as `policy.deny.evaluation_error`; the diagnostic names the host-clock offset. Confirmed ledger close times count toward the cap even when they are ahead of the host clock. The recorder maps that refusal to `WalletError::PolicyDenied`, which reports the gate's own `policy.deny.*` code at every surface, and unwinds the receipt, the pending audit row and the held sequence exactly as any other pre-send refusal does. The gate reads the window before the transaction is built and signed, so without this recheck two callers on one profile could each pass the gate against the same state and both spend against it.
- **Atomic write**: temp file + `sync_data` + rename + parent-directory fsync, the same discipline as the audit log's rotation `write_sidecar_atomic`.
- **Retention**: confirmed entries older than the largest supported window (`1w` = 604,800s) are pruned on every write. A pending entry is kept until it settles, whatever its age.
- **Failure posture**: an unreadable, tampered (HMAC mismatch), or unparseable store file is fail-closed — `PolicyEngineV1`'s construction site hydrates the store BEFORE the engine is usable, and a hydration failure refuses engine construction (`policy.engine_unavailable` / `BuildRegistryError::PolicyEngineError`) rather than silently starting with an empty store. Recovery: `stellar-agent profile reset-window-state <name> --reason <reason>`, which re-initialises the file to empty and audits the reset (`PolicyWindowStateReset`).
- **Rotation**: `stellar-agent profile rotate-policy-state-key <name>` mints a fresh key and re-signs the store file's existing body under it (no old-key read required — the same "recompute the tag over the unchanged body" shape as `rotate-audit-key`'s chain-root sidecar re-sign), so accumulated history survives rotation.

Stateful criteria derive window entries from the same `ValueEffects` used by evaluation and audit. Network submissions reserve those entries before sending and settle them from the ledger result. MPP and x402 authorizers use `record_authorized_window_state`, which applies the reservation comparison under the file lock before signing or signed RPC re-simulation. Refusal records no entries, withholds the credential, and carries the governing policy denial to the caller. Admitted authorization spend consumes window headroom even if subsequent signing or delivery fails. `record_confirmed_window_state` remains an unconditional post-confirmation recorder: spend already applied on-chain must be counted, and a persistence failure is logged.

### Injected views fail closed when absent

Several criteria need state the core crate cannot fetch itself (account reserves, identity, counterparty cache, SEP-10/SEP-45 sessions, quorum). To avoid a circular dependency on the network and smart-account crates, these arrive as optional trait objects on `EvalContext` — `AccountReservesView`, `AccountIdentityView`, `CounterpartyCacheView`, `Sep10SessionView`, `Sep45SessionView`, `QuorumView` — populated by adapters in `stellar-agent-mcp` at the dispatch site. When a configured criterion's required view is `None`, the criterion returns `Err(PolicyError::CriterionEvaluationFailed)` rather than silently passing: `minimum_reserve` with no `account_view`, `sep10_session_active` with no session view, and `home_domain_resolved` with no counterparty cache all fail closed. `AccountIdentityView` is deliberately a separate trait with no default methods so a missing `home_domain` cannot become a silent allow.

### HOME_DOMAIN allowlist verification

`HOME_DOMAIN` matching in `counterparty_allowlist` requires the domain to be verified through the counterparty cache, not merely asserted. The destination's self-asserted on-chain `home_domain` must be resolved in the cache, AND the cached `stellar.toml`'s `ACCOUNTS` list must contain the account (`CounterpartyCacheView::is_account_listed`, default `false`, fail-closed). A domain absent from the cache, or present but not listing the account, denies. Operators populate the cache with `stellar-agent counterparty warm-up` / `counterparty refresh <domain>`. The deny detail distinguishes an unverified domain (not resolved in the cache) from an unlisted account (resolved, but the account is absent from `ACCOUNTS`).

### `minimum_reserve` is inapplicable to smart-account verbs

`account_view` is populated only for classic-account tools (`stellar_pay`, `stellar_create_account`, `stellar_claim`) whose acting account is a plain Stellar account with a classic `AccountEntry`. The smart-account verbs — MCP `stellar_dex_trade` / `stellar_defindex_vault_deposit` / `stellar_defindex_vault_withdraw`, and the corresponding CLI `trade` / `vault` commands — act through a deployed smart-account contract (C-strkey); a contract has no classic `AccountEntry`, so there is no reserve state to fetch and `account_view` stays `None` on these tools by design. A rule that configures `minimum_reserve` on one of them fails closed on every call via the criterion's own `CriterionEvaluationFailed` path. The same applies to `identity_view` on these tools: the DeFi counterparty (pool / router / vault) is a contract, so a configured identity-class criterion (`home_domain_resolved`) is equally unanswerable and fails closed. Operators should not configure `minimum_reserve` or identity-class criteria on rules matching the smart-account verbs.

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
