# Security internals

See [Mainnet configurations and scope](../getting-started.md#mainnet-configurations-and-scope)
for build configuration, admitted operations, and exclusions.

This document describes the cryptographic primitives behind the Stellar Agent Wallet guardrail spine: the approval attestation, the hash-chained audit log, the wallet unlock window, the nonce scheme, the V1 policy evaluator, and the smart-account auth digest. It is written for a maintainer or security reviewer who needs the byte-level detail, not the operator-facing model. For the model itself see [Concepts](../concepts.md); for how the crates fit together see [Architecture](architecture.md).

The CLI and MCP server share attestation, audit, nonce, policy, and auth-digest primitives. The unlock window protects CLI `--secret-env` seeds. MCP signs through keyring handles without `Wallet::unlock`. Testnet is the default. Mainnet operation admission depends on build configuration and installation setup. Policy evaluation, sealed authorization, signing checks, and submit checks are independent boundaries. The wallet's own signing paths sign mainnet payloads only under mainnet authorization. The library signers enforce it too: every `Signer`, the public keyring handle included, signs a mainnet transaction or Soroban authorization payload only under a mainnet authorization. Code running as the same OS user with access to a keyring entry can read its seed directly. The keyring entry is the custody boundary. Ordinary submission refuses the declared mainnet passphrase or known mainnet host before RPC. Authorized consumers bind each action to its endpoint, signer, policy, approval, audit state, and window reservation.

## Two sessions on one profile

Here, a host means one data root and one OS keyring user.
Profiles under another data root on the same platform keyring are not compared.
The table distinguishes tested properties from operational claims that are not pinned.

| Mechanism | Scope | Lock lifetime | Result under contention | Across a restart | Exceptions and evidence per claim |
|---|---|---|---|---|---|
| Nonce replay window | Per `WalletServer` instance; one server per process. Instance scope: not pinned. | In-process mutex for replay-window access; lifetime: not pinned. | Reusing a nonce refuses: `replay_rejected` in nonce `replay_rejected.rs`. Mint and verify: `mint_verify_round_trip_happy_path` in `crates/stellar-agent-nonce/tests/nonce/mint_verify_round_trip.rs`. | Every mint in one process shares one boot salt: `boot_nonce_stable_within_process` and `boot_nonce_must_be_identical_across_instances` in `crates/stellar-agent-nonce/tests/nonce/boot_nonce_invalidates_pre_restart.rs`. A fresh salt per process: not pinned. | A different boot salt changes the HMAC: `mint::tests::compute_tag_differs_on_boot_nonce`. A nonce from another boot therefore fails authentication; an actual process restart is not pinned. |
| Sequence floor | Advisory per MCP server and source account. Scope: not pinned. | In-process mutex during tracker access; lifetime: not pinned. | Bounded catch-up never invents a sequence: `sequence_floor::tests::proceeds_with_stale_value_after_window_exhausted` in network. An outer bad sequence maps to `submission.sequence_number_stale`: `get_failed_outer_tx_bad_seq_yields_sequence_number_stale` in network `submit_integration.rs`. | The advisory floor is lost; restart behavior: not pinned. | A race between processes can still reach submission and fail stale; that process race is not pinned. |
| Pool allocator | One shared `ChannelPool` instance. | Exclusive in-process lease until release: `n4_m8_exactly_n_succeed_m_minus_n_exhausted_immediately` in `crates/stellar-agent-pool/tests/concurrency.rs`. | Full pool refuses immediately: `acquire_returns_exhausted_immediately_when_full` in the same file. | Two processes using one pool state can lease the same channel; not pinned. | A collision surfaces as a sequence refusal at submit, with no authorization effect; cross-process behavior: not pinned. |
| Keyring store registration and entries | Registration is per process, last writer wins; not pinned. Persistent entries are shared. | Backend registration has no cross-process exclusion; not pinned. | A rotation through one headless handle is read by another at its next read: network `keyring::tests::a_rotation_is_visible_to_another_headless_store_handle`. | Entries persist; an actual restart is not pinned by the two-handle test. | Platform-keyring rotation visibility is not pinned by the headless test. |
| Receipt store | Per receipt file. | Advisory sidecar lock during mutation, with bounded retries: core `profile::receipt::tests::a_held_sidecar_lock_refuses_a_write_after_the_bounded_retry`. | Duplicate envelope: `the_same_envelope_twice_reports_already_present`; source and sequence: `a_second_submission_at_the_same_sequence_is_refused`; approval: `approval_hold_survives_reopen_and_refuses_another_sequence`, all in core `profile::receipt::tests`. Wire mapping under lock contention: not pinned here. | Approval identity survives reopen: the approval-hold test. Actual restart: not pinned. | A receipt settled as failed frees its sequence: `a_settled_receipt_does_not_block_the_same_sequence`. |
| Audit writer | Per audit log sidecar, across sessions. | A held sidecar lock refuses a second acquire: core `audit_log::lock::tests::second_acquire_returns_file_locked`. After a rotation the active path stays locked: core `audit_log::writer::tests::post_rotation_active_path_is_locked`; a second session interleaving with the rotation itself is not pinned. The lock held for the writer's whole lifetime: not pinned. | A held writer lock maps to `audit.chain_key_unavailable` with message sub-code `audit.writer_locked`: CLI `commands::value_audit::tests::writer_locked_refusal_names_the_holder_and_recovery_without_a_path`. A second session's value pre-flight end to end: not pinned. Reset refuses with that code: CLI `profile_window_reset::audit_writer_contention_keeps_window_state_unchanged`. | The OS releases the lock when its holder exits; actual process death is not pinned. | Reset acquires the audit writer first: `profile_window_reset::both_locks_refuse_with_the_audit_code_first`. The key-scope check reserves the tip-anchor entry the writer reads: network `keyring::tests::key_scope_reserves_the_audit_writer_tip_anchor`. Readers do not take the writer lock; this table does not pin that claim. |
| Operator-credential store | Per store path. Enrollment, removal, and the sign-count update after a remote login are its writers. | Advisory sidecar lock (the store path plus `.lock`) held across load and atomic replacement, with bounded retries; the sidecar is never deleted. | Concurrent writers keep every enrollment and never lower a counter: core `approval::operator_credentials::tests::concurrent_enrollments_preserve_both_entries` and `concurrent_counter_updates_never_regress`. A stale writer cannot restore a removed record: `removal_cannot_be_undone_by_stale_writer`. A held lock refuses every writer with `approval.writer_locked` and writes nothing: `held_lock_refuses_every_mutation_without_writing`. | The store file persists; actual restart is not pinned. | Reads take no lock and see either the old or the new file. That claim is not pinned. |
| Approval and MPP stores | Per store path. | Approval lifetime lock; MPP operation lock. | Exclusion refuses without waiting: core `approval::store::tests::second_opener_returns_writer_locked`; MPP `store::tests::lock_contention_fails_without_mutation`. Codes are `approval.writer_locked` and `mpp.state_unavailable`; wire mapping is not pinned by those store tests. | Durable state remains; actual restart is not pinned by these contention tests. | These locks do not authorize a transaction. That negative claim is not pinned. |
| Counterparty cache | Per profile cache; default TTL is one hour on the host clock. Default duration: one hour (`DEFAULT_TTL`) in the four production callers; not pinned by a test. An entry whose fetch time lies more than five minutes in the future counts as expired. | Per refresh cache lock; `concurrent_refresh_second_gets_writer_locked` in network `counterparty_cache_integration.rs`. | Fetch time is authenticated: network `counterparty::cache::tests::hmac_v2_different_fetched_at_returns_mismatch`. The file time does not change it: `counterparty::cache::tests::touch_mtime_does_not_change_fetched_at`. Listing skips expired entries: `expired_cache_entry_is_skipped_by_list_cached`. Expiry at equality and the five-minute future-fetch tolerance: the `is_expired_*` unit tests and `future_fetch_tolerance_is_five_minutes`. Snapshot filtering: `snapshot_keeps_only_live_bindings`. | The disk cache persists; listing and snapshot construction enforce expiry on every read. Actual restart is not pinned. | The stale-return API has no production caller. Opt-in fallback on a transient failure until one TTL past expiry, the deadline included: `stale_if_error_returns_expired_hmac_verified_cache_entry` and `stale_fallback_permitted_at_grace_deadline`; caller absence is not pinned. Refusals: `stale_fallback_refused_one_nanosecond_past_grace_deadline`, `stale_if_error_refuses_entry_past_grace_bound`, `stale_if_error_refuses_permanent_fetch_failure`, `stale_read_refuses_an_entry_fetched_in_the_future`, and `stale_if_error_false_ignores_stale_cache_on_failure`. `stale_if_error_false_fail_closed_no_stale_return` pins that a failed fetch without a cached entry refuses. Expired fallback evidence cannot enter policy snapshots. |
| Per-period admission | Classic reservations and testnet x402 authorization usage share persisted window accounting. Mainnet x402 intent minting reserves window headroom. Intent consumption records the debit before signed re-simulation. | Comparison and persistence under the window lock; not pinned. | Classic refusal: network `submission_record_integration::a_reservation_the_window_cannot_admit_is_refused_as_a_policy_denial`; testnet x402 refusal before signing: MCP `x402_audit_gate_integration::window_admission_refusal_precedes_signing`. | State is persisted; actual restart is not pinned by these admission tests. | A second reset handle cannot enter during the recorder: network `policy_state::store::tests::reset_holds_window_lock_during_recorder`. |
| x402 usage after a later failure | On testnet, admitted usage stays charged; this is the beta contract. A consumed mainnet payment intent retains its debit after a later failure. An unconsumed intent releases its holds through invalidation or expiry. | The admission lock ends before the later payment attempt. Lifetime: not pinned. | A later testnet failure does not refund usage: MCP `x402_audit_gate_integration::post_admission_failure_keeps_spend`. | Actual restart after that failure: not pinned. | The admission-refusal test in the preceding row pins the before-signing boundary separately. |
| Authorization per process with a durable single-use record | Per-profile authorization records and holds persist in the window store. `a_mint_records_the_authorization_its_holds_and_its_reservation` in network `policy_state::ledger`. | Mint, consume, and invalidation run under the state lock. Mint contention: `a_held_lock_refuses_a_mint`. Consume pin reread: `a_consume_rereads_the_pin_under_its_lock`. Invalidation under the lock: not pinned. | A second consume refuses without rewriting the file: `a_second_consume_refuses`. Approval nonces are single-use within retention: `an_approval_nonce_is_single_use_within_retention`. | Records are persisted. Actual process restart: not pinned. | Concurrent mints produce one open record: `concurrent_mints_of_one_content_yield_one_open_record`. Invalidation releases holds without reopening authority: `an_invalidation_releases_the_holds_and_never_reopens`. All named tests are in network `policy_state::ledger`. |

The receipt store remains an unanchored map; a missing file reads as empty.
It backs duplicate source-and-sequence refusal, duplicate-envelope refusal,
approval-nonce checks, reconciliation identity, approval-consumption repair,
and operator-clear state. The chain refuses a reused source sequence after
receipt loss or rollback. At the MCP gate's approval-nonce check, the
approval-store consumption tombstone refuses first. The receipt covers the
window in which a tombstone write is still owed, and the approval's lifetime,
the single-use commit nonce and the chain bound that window. The CLI has no
approval-nonce gate.

Under a policy with a stateful criterion, the window store refuses an envelope
hash that any pending or confirmed record carries, and a release removes
pending records only. Without window entries, a byte-identical resend after a
lost receipt can reach the chain, which does not apply the consumed sequence
twice. After receipt loss, if a byte-identical resend is refused after its
pending row for a reason other than duplicate reservation, the recorder
attempts to close the row. The attempt is best-effort. If written, the
settlement lookup reads that row for the original submission too, unless the
original's outcome row is newer.

Automatic reconstruction needs a retained pending reservation and either a
definitive chain answer or release evidence. It restores the transaction
identity before the reservation settles, and an operator clear after an
acknowledged `NOT_FOUND` beyond retention restores it too. Without a retained
reservation, a lost receipt loses the reconciliation identity. Reconstruction
does not recover the approval nonce, so the owed approval-consumption repair is
lost, and the previous operator-clear state is lost. The pending audit row
carries the approval nonce but not the time bound or the submission ledger.

## Attestation primitive

When the operator runs `approve`, the wallet records an HMAC-SHA256 attestation that proves the keyring holder ran the command. The primitive lives in `crates/stellar-agent-core/src/approval/attestation.rs`.

### Canonical input

`compute_attestation(key, binding, approval_nonce, envelope_sha256, process_uid)` feeds the HMAC in this order:

```text
mac.update(b"stellar-agent-approval-attestation:v2")
mac.update(u32_be(len(profile_name)))   mac.update(profile_name)
mac.update(u32_be(len(chain_id)))       mac.update(chain_id)
mac.update(u32_be(len(approval_nonce))) mac.update(approval_nonce)
mac.update(envelope_sha256)
mac.update(u32_be(len(process_uid)))    mac.update(process_uid)
```

Lengths count UTF-8 bytes, encoded as big-endian `u32` with saturation at `u32::MAX`.
The 37-byte tag has no length prefix or NUL terminator; the digest is 32 bytes with no prefix.
The tag separates this HMAC from every other use of the key.
The profile name and CAIP-2 chain id make a blob unverifiable under another profile or chain.
A layout change bumps the tag; blobs under the previous tag do not verify.

All four variable-length fields carry a big-endian `u32` length prefix. The prefixes encode every field boundary, so inputs that split into different fields hash differently. A known-answer test pins the exact layout so an accidental change to the preimage is caught.

### Key custody

The key is the profile's `attestation_key_id` keyring entry, a 32-byte secret. The module takes the key as `&[u8; 32]` and implements only the HMAC. The caller loads it from the platform keyring into a `Zeroizing<[u8; 32]>`, passes `&*key`, and drops the guard immediately after the call. No key bytes are returned, transmitted, or written to disk.

### Constant-time verify

`verify_attestation(...)` recomputes the expected tag and compares with `subtle::ConstantTimeEq` to avoid timing side-channels. It returns a plain `bool`; the consumer never branches on partial-match progress.

### Process-uid binding and non-replay

`process_uid` identifies the OS user of the approving process: the numeric uid on Unix, and the process token user's SID string on Windows. Binding it into the HMAC gives cross-account-on-host non-replay: a blob minted by uid `1000` does not verify when presented by uid `2000`, because the recomputed tag differs. The attestation proves the keyring holder ran `approve`; it is not a proof that a human clicked "yes" in an agent UI.

### Key rotation invalidates pending approvals

The attestation tag is keyed by the live `attestation_key_id` entry. Rotating that key changes the HMAC key, so every already-minted attestation in the pending store fails verification on the next `_commit`. Rotation therefore invalidates all outstanding approvals; the operator must re-approve.

### Kind-specific digests

Four approval kinds bind extra fields by hashing them into the 32-byte slot that `compute_attestation` treats as `envelope_sha256`. Each uses a versioned domain-separation tag. A layout change bumps the tag, and digests under the previous tag do not verify.

- `ToolsetFirstInvokeGate`: `compute_toolset_gate_digest` hashes `TOOLSET_GATE_DOMAIN_TAG` (`stellar-agent-toolset-grant:v1`) followed by length-prefixed `toolset_name`, `capability`, `destination` (G-strkey), `asset`, then the fixed-width `amount_min_stroops` and `amount_max_stroops` as big-endian `i64`. `verify_toolset_gate_attestation` recomputes this digest and feeds it through `verify_attestation`.
- `TrustlineClawbackOptIn`: `compute_trustline_clawback_opt_in_digest` hashes `TRUSTLINE_CLAWBACK_OPT_IN_DOMAIN_TAG` (`stellar-agent-trustline-clawback-opt-in:v1`) followed by length-prefixed `network`, `code`, `issuer`.

- `RuleProposalSimulated`: the shared HMAC binds the versioned proposal digest over the resolved rule installation arguments.
- `MppChargeSimulated`: the shared HMAC binds the prepared artifact hash. The store verifier also compares the stored profile and chain with the binding.

A matching grant requires a version 3 HMAC that verifies under the profile's attestation key and profile/chain binding. It must be unexpired, with a lifetime of at most 30 days, and issued no later than the current time and at or after the second following the current installation. An invalid install time honors no grant. Consent issued in the install second re-prompts once. A forged or edited grant suppresses nothing.

The first-invoke grant suppresses only its re-prompt. Per-action `PaymentSimulated` approval fires on every toolset-routed payment and binds the executed envelope through `envelope_sha256`.

## Audit hash-chain

The audit log is a per-profile append-only JSONL file (`~/.local/share/stellar-agent/audit/<profile>.jsonl` on Linux; `~/Library/Application Support/Soneso.stellar-agent/audit/<profile>.jsonl` on macOS; `%LOCALAPPDATA%\Soneso\stellar-agent\data\audit\<profile>.jsonl` on Windows; see `stellar_agent_core::profile::schema::canonical_data_root` for the derivation). The entry schema and canonical-JSON rules live in `crates/stellar-agent-core/src/audit_log/entry.rs`; the chain primitives in `audit_log/chain.rs`; verification in `audit_log/verify.rs`.

### Per-entry hash

```text
current_entry_hash = SHA-256( canonical_json(entry without previous_entry_hash) || previous_entry_hash )
```

`canonical_json` is `serde_json` output with fields in struct-declaration order. The `previous_entry_hash` field is set to `""` (empty string, never JSON `null`) in the hashed body so the hash does not depend on itself; the real predecessor hash is concatenated separately. Hashes are stored as `sha256:<hex>` strings.

### Genesis and rotation handoff

The very first file's first entry chains off `ZERO_BLOCK_HASH`, which is `SHA-256([0u8; 32])`, `sha256:66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925`. The zero-block hash is used only for that one entry.

On rotation, the outgoing file's last entry is an `AuditRotationHandoff { next_file_name }`. The next file's first entry chains off that handoff entry's hash, not the zero-block hash, bridging the chain across files. The `next_file_name` records the rotated archive name of the file the handoff is written into, binding the rotation to a specific filename.

### Writer lock and reader concurrency

The writer's mutual exclusion lives on a sidecar lock file (`<log>.lock`), never on the log file itself. `AuditWriter::open` acquires an exclusive OS lock on the sidecar before touching the log. It holds it for the writer's whole life (including across rotation, whose archive rename and exclusive create rely on it). The OS releases it on drop or process death. The log file carries no OS lock on any platform, so readers (`audit verify`, the `find_*` scans) never contend with a live writer. This is load-bearing on Windows, where an exclusive file lock is enforced against reads through every other handle. The writer keeps a single handle for every read and write of the active log as a consistency invariant.

Readers can observe two transient states: a torn last line during an in-flight append (reported as a parse error on that entry, exactly as a genuine truncation would be). The other state is a briefly absent active file between rotation's rename and create. For the latter, readers and `verify_log` re-scan within a small bounded window, gated on the sidecar lock being observably held by a live writer. An unheld lock reports the gap immediately. The tolerance can only delay, never suppress, a `RotationGap`, chain-break, or HMAC failure. The lock-liveness probe momentarily acquires the sidecar lock, so `verify` may create the `.lock` file. In a microsecond window, it can surface spurious contention to a concurrently STARTING writer; this fails closed and is retryable. Verification of a copied-off audit directory is therefore not strictly side-effect-free on that anomalous path.

The reset ceremony also requires this lifetime writer lock. A second session
refuses before taking the window lock; stop the MCP server before reset.
See [Two sessions on one profile](#two-sessions-on-one-profile) for the contention
codes and the tests that pin each property.

### Per-file root HMAC sidecar

Each log file gets a `<file>.root_hmac` sidecar holding an HMAC-SHA256 tag (`sha256:<hex>`) over the chain root, keyed by the profile's `audit_log_hash_chain_key_id`. `sign_chain_root` mints it; `verify_chain_root` checks it with a constant-time comparison (`subtle::ConstantTimeEq`) against the supplied key. The sidecar is renamed alongside the log file on rotation.

### What `audit verify` checks

`verify_log(log_path, hmac_key)` collects the file chain (rotated siblings oldest-first by filename, then the active file) and walks it. Per file it enforces:

1. Each entry's `previous_entry_hash` equals the recomputed hash of the prior entry's canonical body; a mismatch is `ChainBroken`.
2. The first entry of each non-first file chains off the preceding file's last entry (the cross-file bridge).
3. Each rotated file's `AuditRotationHandoff.next_file_name` matches that file's actual basename, defeating file-substitution attacks; a mismatch, a missing handoff in a rotated file, or a handoff appearing in the active file is `RotationGap` / `ChainBroken`.
4. When `hmac_key` is supplied, each file's `.root_hmac` sidecar verifies on its first entry; a wrong tag is `HmacMismatch` and a missing sidecar is `HmacSidecarMissing` (with a key configured, a sidecar must exist for every file). The sidecar covers that first entry only, never a later one.
5. When an anchor is supplied, the anchored entry is intact at the anchored offset and the active file ends at or past it; anything else is `TipAnchorMismatch`. Growth past the anchor is accepted by the anchor rule; once entry tags are in force, the tag walk of item 6 decides whether those entries are authentic. The CLI supplies an anchor only when `--profile` is given AND the positional path is the log that profile configures, since the anchor names a path; every other case reports `anchor.status = "not_checked"` with the reason and verifies the chain alone.
6. When `hmac_key` is supplied, the walk checks every entry's `entry_tag` under the key derived from it, HMAC-SHA256(audit key, `stellar-agent-audit-entry-key:v1`). A tag is `sha256:` and the hex HMAC-SHA256, under that key, of `stellar-agent-audit-entry:v1` and the entry's 32 raw hash bytes; it sits outside the hashed body. Tags are in force from the first `audit_entry_tags_started` or `audit_entry_tags_rekeyed` row with a valid tag, and from any rotation handoff carrying `entry_tags: true`; when the walk's first file chains from such a handoff, from the start of the walk. A keyed start with a valid tag clears any earlier failure and becomes the reported boundary. Past it, a run of entries with a missing or mismatched tag is closed by the next valid entry and fails the walk with `EntryTagInvalid`, naming the run's first line and `missing` or `mismatch`; an `audit_entries_quarantined` row with a valid tag clears a run in its own file that starts within the count of rows directly before it. The result reports `entry_tags_verified` and `entry_tags_boundary`. Without a key no tag is checked.

Before the walk, the rule the prune applies too picks the first file's seed:
the zero seed without `<log>.pruned`, and otherwise the seed the marker records
for that file as its `oldest` or `previous` boundary. A marker that names
neither fails with `audit.chain_broken`, reason
`prune_marker_names_neither_boundary`, at line 1 of that file. With a key, a
null or wrong tag refuses with `audit.hmac_mismatch`. A malformed marker
refuses with `audit.parse_error`. Without a key the seed is unauthenticated. A
nonzero seed adds `pruned_prefix`, naming the first file and the count of
pruned archives. Later files chain from the walk's computed tip. A deletion
beyond the marker or an interior edit still breaks verification.

The writer prunes after the new active file exists, so a prune never fails the
rotation. It deletes only archives of one fully validated chain that ends at
the archive just rotated. Before any deletion it replays every archive from the
oldest to that one. The oldest archive's first entry must chain from the seed
the marker records for it, or from the zero seed when no marker exists, so the
start of the retained history is authenticated the same way verification
authenticates it. A log whose oldest archives or marker were removed outside
the prune stalls every prune until the operator recovers it
([audit-log recovery, section 11](audit-log-recovery.md#11-retained-history-without-an-authenticated-start)).
Each archive must open as a regular file without following a symlink or waiting
on a FIFO, and stay within a read budget: 1 MiB per line and the rotation
threshold plus 2 MiB per archive. Every entry must chain from the one before
it, each archive's first entry from its predecessor's handoff, and each archive
must end on a handoff naming it. A keyed writer also requires each archive's
first entry to carry a chain-root tag that verifies under its key. The links
bind the entries into one sequence, and the tags bind where that sequence
divides into files: an archive split at a handoff inside it still links, but
the part after the split carries no valid tag and stops the prune. The writer
writes no such archive, because a handoff is always the last entry of its file.
An unkeyed writer checks the links only. The just-rotated archive is checked
against the seed and handoff the writer holds in memory, never against what its
file states. The writer names each archive so it sorts after every existing
archive of the log: the current millisecond when that sorts after the newest
archive, and otherwise the newest archive's timestamp with the next six-digit
counter. The name order the prune, the open, and verification read is therefore
the creation order, also across a clock set back. A sibling placed under a name
that sorts after every archive precedes the next archive and stalls the prune
until it is removed. A copy of an archive already pruned, planted back with its
tag, carries that archive's own name, sorts oldest, and is deleted first or
stops the prune at the marker. The writer syncs the marker before removing each
archive and its sidecar. The prune trusts the proof it just made and does not
recheck a file between the proof and its deletion; a concurrent writer of the
audit directory is outside its guarantee. The `previous` seed lets verification
walk an archive whose removal fails or is interrupted. Key rotation re-signs
the marker as well as the root sidecars.

The read budget holds every archive the writer produces. An append whose
serialized row, newline included, exceeds 1 MiB refuses with
`audit.row_too_large` and never writes the row. A supplied entry is measured
before the append's checks, drain, or rotation, so the file, the chain, the
anchor, and the audit directory stay unchanged. A row the append builds itself
exists only after the rotation the file was due for, which can precede the
refusal. Each archive holds one rotation handoff, its last entry. A rotation
whose renames fail leaves its handoff pending. Every path that takes up a file
ending on a handoff naming a rotated sibling holds it as pending: the open, an
acquisition that replays bytes past the anchor, such as a handoff whose fsync
failed, and `audit reanchor`. A writer without an anchor whose handoff write,
flush, or fsync fails replays the file past its last entry before its next
append, the same way. An anchored writer adopts it in the anchor check of its
next acquisition; an append without that check refuses with
`audit.tip_anchor_mismatch` and latches. The next append of any row, including
the adoption row and the repair rows, first renames the file under that
handoff's archive name and appends no second handoff, so no row follows a
handoff and retries never grow an archive. A rename never replaces an existing
file: a rotation whose archive name, or its sidecar's name, is taken refuses
with `audit.rotation_bridge_unusable`, and so does an open whose active file
ends on a handoff naming an existing file. A rotation that finds no name after
the newest archive refuses with the same code and writes nothing. The check
runs right before the renames; a concurrent writer of the audit directory is
outside its guarantee.

A keyed writer writes a file's chain-root tag after its first entry is durable
and replaces the sidecar atomically through a temp file and a rename. A crash
between the two leaves a file with entries and no tag. A keyed open writes the
missing tag only after its anchor check proves the file is what the writer's
lineage wrote: a replay from byte 0 yields exactly the anchored entry count,
the last of those entries ends at the anchored offset, and its hash is the
anchored tip. An anchored file that fails the proof refuses at open with
`audit.tip_anchor_mismatch`. The tag binds where the file starts, so it is
written only when the first entry starts at byte 0; the writer writes no blank
lines or indentation. An open that adopts an unanchored file, or a keyed open
without an anchor store, writes no tag. `audit reanchor` writes it after its
anchor move, as the operator's acknowledgement of the file as it stands. Both
run before any append can rotate the file. A file that an unkeyed writer both
starts and rotates carries no tag and stalls a keyed prune until `profile
rotate-audit-key` re-signs it.

A planted, edited, split, unreadable, or oversized file in the counted range,
from the oldest archive to the one just rotated, stalls pruning until it is
removed, and so does an archive whose tag is missing or does not verify under
a keyed writer's key. The prune also stops on a marker that does not
parse, exceeds 16 KiB, does not authenticate under the writer's key, or names
neither boundary, a failed marker write, or a failed removal. Every stop logs a
warning naming the file and the cause, and keeps the excess archives. Past 21
rotated files, open and verify refuse with `audit.too_many_rotated_files`.

The `EventKind` match in the verifier is exhaustive with no wildcard arm, so adding an event variant forces a compile error until the verifier is updated.

A backward timestamp jump larger than `BACKWARD_TS_WARN_THRESHOLD_MS` (60000 ms) is reported as a warning, not a failure, because NTP corrections can move wall-clock time backward.

Settlement and receipt-clear lookups visit retained files newest first and
stop after the first file with a matching row. Each visited file's in-file
chain is verified, and in a log with no archives the first row must chain from
the zero hash. The eleventh rotation deletes the oldest archive. The lookup
runs outside the append's mutex. Two concurrent reconciliations of one hash can
both find an owed row, and any concurrent in-process append can rotate the log
between the file listing and the scan, renaming the matched file out of the
walk. Writer-managed history holds at most eleven files of about 10 MiB each
when pruning succeeds. A prune that stops leaves excess archives, for the
causes listed above.
Each lookup parses JSON and computes SHA-256 once per row visited, per settled
row and in each gate pass that reconciles. When the settlement lookup cannot
read the history, `tx status` and `stellar_transaction_status` log the error
and write no settled row. Where the profile has an audit writer,
`tx receipt clear` refuses with the verifier's code, such as
`audit.chain_broken` for a broken chain, and keeps the receipt.

### Keyring-held tip anchor

The chain walk and the per-file root signature both verify a PREFIX. An older copy of the active log, or a truncated one, satisfies them. The tip anchor closes that gap by holding the tip's coordinates outside the file.

The anchor, the re-anchor counter, and the audit binding live in the keyring, outside the log file. Anyone who can restore the keyring's own storage together with the log can restore an older state. With a headless keyring backend these entries are kept in a file on the same host. Anyone who can write that file can restore older entries or delete one, which needs no key material. A deleted binding is recorded again from the profile file at the next keyed use. A deleted anchor is refused while a fact outside it shows it was written; see **Missing anchor** below. A restored older copy of the whole headless store, together with a truncated log, agrees with that log, which is why mainnet readiness refuses a headless backend; see [Mainnet](#mainnet).

For each log PATH the keyring holds `<entry count>:<tip hash hex>:<end offset>`. These are the number of entries in the active file, the SHA-256 entry hash of its last entry, and the byte offset just past that entry. The writer advances all three inside `write_entry`, after the entry's `sync_data` and the in-memory tip update, under the sidecar lock the writer already holds. The advance retries once immediately under the sidecar lock. It remains best-effort: the row is already durable. A second failure latches the owed repair and retains its coordinates, including a rotation handoff's coordinates.

Plain appends retry a behind anchor before rotation and still write their rows during an outage. `require_anchor_current()` retries and refuses with `audit.tip_anchor_unavailable` while repair fails. Cached acquisition repairs after checking file identity and before reconciling the stored anchor.

A submission recorded through the pending row, the window-state reset, and
an x402 payment check the anchor before and after their pre-action row. They
refuse before send or wipe while the tip anchor cannot be written. MPP's
charge row keeps its best-effort anchor flow. On testnet, an x402 refusal keeps
the spend admitted before the gate. The audit gate checks the anchor before and
after the authorization row. On mainnet, this gate precedes intent consumption
and signed re-simulation.

A failed row settles every pending row with the same envelope hash. For an
anchor refusal, the recorder attempts to close the row after the reservation's
duplicate check under the window lock passes or, without window entries, after
the receipt gate records a new receipt. A resend that the duplicate check
refuses leaves its row open for the original submission's settlement. For a
`record_pending` error other than the duplicate refusal, the recorder also
attempts to close the row. That error can precede the duplicate decision, so it
does not prove exclusive ownership of the hash. A reservation persisted before
the error stands until reconciliation settles it. Without current window
entries, a reservation from an earlier stateful policy can also remain.
A closing row can settle that submission too.

A pending-row anchor refusal before the row writes no receipt and no row.
After the row, the check under the guard that appended it can refuse with
`submission.record_unavailable`, with `audit.tip_anchor_unavailable` in the
message. The recorder attempts the reservation release, a
`value_action_failed` row carrying that wire code, and receipt removal. Each
cleanup step is best-effort and logged; nothing is sent.

Check semantics, applied at writer open and again on every keyed acquisition by the writer registry (which caches one writer per profile for the process lifetime, so a check only at open would miss a file replaced underneath a live writer). The check sits in the registry rather than in each caller because the registry is the only way a keyed writer is reached, and a caller that omitted it would append to a log nothing had proved current:

| Observed | Verdict |
| --- | --- |
| The file at the path is not the file this writer's handle holds | `audit.tip_anchor_mismatch`; refuse, and drop the cached writer. See **File identity** below |
| File length equals the anchored offset and the entry ending there hashes to the anchored tip | Current; accept |
| File length exceeds the anchored offset, anchored entry intact, entry tags not yet in force | Accept, replay the appended tail, re-anchor on the new tip. A keyed writer then appends `audit_entry_tags_started`, counting the tail it absorbed once in `absorbed_count` |
| File length exceeds the anchored offset, anchored entry intact, entry tags in force | Accept only when every entry of the tail carries a valid tag under the writer's key; otherwise `audit.tip_anchor_mismatch` with reason `unauthenticated_tail` |
| File length exceeds the anchored offset, anchored entry absent | `audit.tip_anchor_mismatch`; refuse. A longer internally consistent chain that does not contain the anchored entry is a substitution. It passes the chain walk exactly as an honest log does |
| The anchored tip is the newest archive's rotation handoff | Accept: the anchor names the generation this file succeeded. Re-derive from the file, which must chain from that handoff |
| File length below the anchored offset, or the entry at the anchored offset is not the anchored one | `audit.tip_anchor_mismatch`; refuse |
| No anchor, and a recorded audit binding, a chain-root sidecar, or an `audit_tip_anchored` row in the file shows one was written | `audit.tip_anchor_missing`; refuse. See **Missing anchor** below |
| No anchor, file has entries, chain verifies, none of that evidence | Adopt the current tip, write the anchor, append `audit_tip_anchored { reason: adopted }` |
| No anchor, file empty, no chain-root sidecar | Store nothing and write no row; the first append writes the first anchor |
| No anchor, chain broken | Refuse |

The ahead-of-anchor case is the ordinary one, not an exception. Unkeyed writers receive no anchor handle; they append only to zero-config logs, which show no keying: no tags in force, no tagged row, no chain-root sidecar, and no anchoring row. An unkeyed open of a log that shows any of these refuses with `audit.chain_key_unavailable`, and an open with an anchor store but no key refuses one with tags in force or a tagged row. The CLI startup advisory reads such a log without a writer and writes no row. The crash window between an entry's `fsync` and the anchor write lands in the same place. Adoption with no operator action is the path for a log that nothing shows was anchored, such as one written only by unkeyed writers on the zero-config quickstart.

**Missing anchor.** An absent anchor is adopted only when nothing shows one was written. Three facts outlive a deleted anchor and show it: an audit binding recorded for the profile before this use, a chain-root sidecar beside the active file, and an `audit_tip_anchored` row of any reason in it. For an empty active file only the sidecar counts, since a rotation renames the sidecar with its archive and an empty file with one was truncated. With any of them the writer refuses with `audit.tip_anchor_missing`, naming the fact, and writes neither an anchor nor a row; the cached-writer check refuses the same way. Without the check, deleting the anchor and truncating the log would be adopted as a fresh log and the removed rows would leave no trace. A keyed use records an absent binding only after the audit key has loaded and passed the owner-key check, so a binding is never recorded for a profile with no key. `profile rotate-audit-key` minting a profile's first key treats a recorded binding as no evidence, since no keyed use of that log could have happened, and records an absent binding only after its writer opens. A log a keyed writer wrote with no anchor store carries a sidecar and is refused too. The way out is `audit reanchor --acknowledge-rollback`, whose `rollback_acknowledged` row is the permanent record. `audit verify --profile` applies the same rule to the profile's own log after the walk and fails with `audit.tip_anchor_missing`, its message saying `anchor: missing`. A keyed access on an empty log records the binding without writing an anchor; when only unkeyed writers append after it, the next keyed open reads the binding as evidence and refuses until the repair.

**Only a file with entries is ever anchored.** There is no anchor value meaning "this file is empty". Offset 0 is a prefix of every file. Such a value would classify every file at the path as ahead of it. A rollback (including a restore of the whole audit directory to an earlier snapshot) would be absorbed rather than refused. An absent anchor says the same thing honestly, and the adoption rule already covers it. A stored zero entry count is rejected on read rather than treated as "nothing anchored", so a corrupted value cannot disarm the guard.

**Rotation.** The anchor is advanced onto the outgoing file's handoff entry before the renames and is then left there. The file the rotation creates has no entry of its own to name, so it inherits nothing: until its first append the anchor still names the previous generation, and the rollback guard is armed on that value throughout.

That state is recognised rather than guessed. An anchor whose tip hash equals the newest archive's last entry, which `initial_chain_seed` already reads and already requires to be a rotation handoff naming that archive, describes the generation this file succeeded. Only the rotation itself writes that value. An attacker who appends a handoff to a copy of the log produces a new tip hash the anchor does not name. So the match cannot be manufactured from filesystem access. On the match the anchor is re-derived from the file at the path, which must chain from that handoff or the replay refuses. Restoring the pre-rotation directory state, or an older archive-and-active pair, therefore refuses: neither contains an archive whose handoff is the anchored one. The check runs before the length comparison, because such an anchor's count and offset describe the archive and comparing them against the file now at the path is meaningless in either direction.

**Anchored offset.** The offset is read from the file after the entry's `sync_data`, not computed as "previous offset plus bytes written". Every reader here tolerates blank lines between entries and at end of file, so a log that picked any up outside this writer has more bytes than the writer accounted for; an arithmetic offset would then name a position inside an entry and the next open would report a rollback on an untouched log. `O_APPEND` plus the exclusive lock make end of file the entry's end, which is where the reader's replay ends too.

**File identity.** Every read the anchor check makes except this one goes through the writer's single handle, which is the right source for the bytes it will append after. The file at the PATH is a different question. A `mv` over the log leaves the handle on the previous, now unnamed file, whose tail is exactly the anchored one. So every content comparison passes while the appends land where nothing can read them and the log an operator sees stays behind the anchor. The check therefore resolves the file at the path and compares its identity against the handle. Identity is device and inode on Unix, volume serial and file index on Windows, both through `same-file`. The check reads the length through the path rather than the handle. A mismatch, and a path holding no file at all, refuse under `audit.tip_anchor_mismatch`, and the refusal's detail names the log as replaced underneath the writer rather than as shorter than the anchor. The replacement is never adopted.

**The append is checked too.** A caller acquires the writer, signs, submits, and appends afterward, so acquisition alone leaves that span uncovered. Every anchored append checks four shapes of divergence: replacement, truncation, growth, and a same-length overwrite. It compares file identity, requires the length to equal the writer's last append or replay length, and hashes the entry at its cached tip offset. A replay includes tolerated trailing blank lines in that length; the anchor still names the last entry. Extra complete rows, torn prefixes, and bytes left after a failed sync all refuse before the next append. Each shape uses `audit.tip_anchor_mismatch` with its own reason. The cost is one identity comparison, one `stat`, and one entry read plus hash per row, with no keyring round trip. Open and keyed acquisition still accept an intact tail ahead of the anchor, because anchor writes are best-effort.

A refused append is durable, not merely in-process. The action the row was going to prove has already committed. A refusal that lived only in the writer's memory would be erased by a restart. The file at the path (an attacker's byte-identical copy included) would satisfy the anchor again. The writer therefore anchors the row it was owed: entry count plus one, the hash that row would have carried, and the offset it would have ended at. Every file at that path is then short of the anchor by exactly that row. So every later open refuses until an operator runs `audit reanchor --acknowledge-rollback`. Its report shows one more anchored entry than the file holds. Its row records the superseded anchor permanently. An anchor exactly one entry ahead of a log whose own chain verifies is that signature. The anchor write is best-effort like every other. If the keyring rejects it, the refusal still stands for this writer and for every caller still holding it. The next refused append retries it. That refusal does not survive the process.

The writer is also latched: every later acquisition and every later append through that instance refuses, whatever the path holds afterward. Its caller has already been told the append failed. A file that looks right again would only hide that. A writer's own rotation is not a divergence. The check precedes the rotation decision, and `finish_rotation` puts the handle on the file it created at the path before anything checks again. A rotation that failed after the rename reports `audit.partial_rotation`, which is a directory state an operator repairs by hand.

The registry evicts a writer that fails the check. The entry is kept as a tombstone rather than removed, because the evicted writer holds the sidecar lock until its last holder drops it and a fresh open in that window would report `audit.writer_locked` and name the wrong remedy; while a holder remains the tombstone answers the replacement, and once the writer is unreferenced the next acquisition opens what is at the path and checks it against the anchor on its own terms.

**Scope.** The anchor names one path inside one profile's keyring namespace. Its keyring service is the profile's own audit service. Its account is `<audit key account>-tip-<first 16 hex of SHA-256 of the lexically normalized path>`. A different `audit_log_path` or audit key therefore has an anchor coordinate of its own. The audit binding guards that change; see **Audit binding** below. Normalization is lexical, never `canonicalize`, because the coordinate must be derivable before the log file exists; paths differing only by `.` or `..` share an anchor, paths differing through a symlink do not. Two profiles pointed at ONE log path do not share an anchor. Each holds its own under its own service. Each advances only on its own appends. A rollback to the lagging one is absorbed there and refused by the other. That configuration is unsupported; `profile show` on each profile is what reveals it.

**Keyed opens always carry the anchor.** A keyed writer tags every row it appends, its rotation handoffs included; a handoff written while tags are in force carries `entry_tags: true`, which sits inside the hashed body. A keyed writer's rows are the ones `audit verify` covers and the ones worth removing, so a keyed open that did not advance the anchor would leave its rows unguarded. The registry's keyed entry point and the writer constructor both take a type that pairs the chain-root key with the anchor store and cannot be built without both, and one helper in the network crate produces the pair from the profile's audit keyring coordinate. The unkeyed entry point takes neither, and the anchored constructor the rotation verb uses takes the store as a required argument with the key optional, since a profile that has not minted a chain-root key yet still anchors. There is no way, at either level, to present a key without a handle.

**Residual: the replacement between the append's check and its write syscall.** The append checks the four shapes above and then issues the write; a replacement landing between the two still lands the row in the file that was displaced. The window is those adjacent syscalls rather than the whole sign-and-submit span, and closing it entirely would need the write and the proof to be one operation, which no filesystem offers. Detection is unaffected: the append advances the anchor to describe the displaced file. So the next acquisition refuses and every one after it refuses the file at the path as shorter than the anchor, until `audit reanchor`. Nothing is laundered: a file at the path that satisfied the advanced anchor would have to contain the very row being removed.

**Residual: the best-effort append window.** A row whose anchor write fails twice remains durable and unanchored until a successful retry or keyed acquisition. The latch lives only in memory. After process exit, rollback to the previous anchor silently loses that tail. A submission recorded through the pending row, the window-state reset, and an x402 payment never proceed while repair is owed. MPP's charge row and unkeyed writers remain outside this rule.

The residual has two shapes, and they are not equally weak. Stated precisely:

| State | What is accepted |
| --- | --- |
| The anchor names an entry of this file but is behind it, between an entry's fsync and its anchor write landing | Any state at or ahead of the anchored entry. The guard LAGS: everything before the anchored entry is still refused. One entry after two failed attempts; a keyring outage widens it to the appends made during the outage, bounded by the next successful write |
| No anchor has ever been written for this path: a new log, or the first keyed use of a log only unkeyed writers wrote | Anything at the path whose chain verifies. The guard is OFF: adoption takes the file as it finds it, so a rollback performed before that first acquisition becomes the baseline. A repointed `audit_log_path` does not reach this state on its own: the audit binding refuses it until the operator acknowledges it. Nor does a deleted anchor while a recorded binding, a chain-root sidecar, or an `audit_tip_anchored` row remains; see **Missing anchor**. There is no earlier anchored state to compare against, which is why this cannot be closed rather than why it is harmless |
| A file a rotation created, until its first append's anchor write lands: the anchor still names the archive's handoff | Any prefix of that file, down to empty, provided it chains from the handoff. The guard is OFF for that file: the rotation-completed rule re-derives from whatever is at the path. Normally one append wide, since the first append moves the anchor onto this file; a keyring outage spanning that append holds it open for the outage |

The two OFF states share a shape: the anchor names nothing in the file at the path, so there is no tip to compare a candidate against. Entries in an ARCHIVE stay guarded throughout. A rolled-back prefix of the pre-rotation file cannot chain from the archive's handoff, so it is refused, and `audit verify` walks every file regardless.

A keyring write outage that covers a rotation, failing both the handoff anchor and the first anchor of the new file, leaves the stored anchor on the pre-handoff tip. The live writer still holds the owed value. After a process exit, the next open and `audit verify` report a mismatch on an honest log, and recovery is `audit reanchor`.

Closing all three would need the anchor written BEFORE the entry it covers: an upper-bound reservation stored in the keyring ahead of each append. That is one keyring round trip per audit row and makes a keyring outage block or unaudit appends, which is a worse failure than the window it removes. The entry stays durable first.

**Appended forgeries.** The anchor detects rollback, truncation, and substitution; the entry tags detect appended forgeries past the boundary row. The entry-to-entry chain hash is unkeyed, so anyone who can write the file can append a well-formed entry chaining off the current tip. Past the boundary such an entry carries no valid tag, so keyed writers refuse the tail (`unauthenticated_tail`), `audit verify --profile` fails with `audit.entry_tag_invalid`, and the readers never reach it, because they stop at the writer's verified tip. What remains open:

- Code that can read the profile's audit key can compute valid tags.
- Rows before the boundary row are covered by the anchor only; the boundary absorbs an unanchored tail once and records its count.
- `audit verify` without `--profile` checks no tag.
- Zero-config logs carry no tags.
- Stripping tags inside the anchored prefix fails keyed verify until the next keyed open appends `audit_entry_tags_rekeyed { cause: open_repair }`.

`audit verify --profile` applies the same three-way rule in the same order as the writer: shorter than the anchor, then the anchored entry's intactness, then the tip at the anchored offset. It reads through the writer's own backward scan rather than a second implementation. So the two surfaces cannot disagree about a given file. With tags in force it also requires a valid tag on every entry past the boundary, the anchored prefix included, while the writer checks tags only on the tail past the anchor and on a file a rotation completed.

**Cross-file seed.** Opening the active file needs the hash its first entry chains from: the zero block for the first file of a chain, the outgoing file's handoff entry once the log has rotated. `initial_chain_seed` reads only the newest archive's last line and requires it to BE a rotation handoff naming that archive, refusing with `audit.rotation_bridge_unusable` otherwise, so a file dropped into the audit directory under a later timestamp cannot redirect the bridge. That check is structural, not cryptographic: it does not walk the archive's chain or verify its root signature. The bridge's integrity is established by `audit verify`, which walks every file, threads the tip from one into the next, and requires each file's chain-root signature under the profile's key. Every replay inside the writer seeds through this one function; none names the zero block directly. The seed also carries the handoff's `entry_tags` flag and tag, so tags stay in force across a rotation and a prune.

**Repair.** `stellar-agent audit reanchor --profile <name> --acknowledge-rollback` is the only way out of a mismatch or a missing anchor. It replays the whole log first, so a broken chain is refused rather than blessed. It writes the current tip as the anchor, increments a monotonic per-path re-anchor counter in the keyring, and appends an `audit_tip_anchored { reason: rollback_acknowledged, previous_anchor }` row. Without the flag it reports both anchors and exits 1 with `validation.acknowledgement_required`, changing nothing. When tags are in force and the active file ends in entries without a valid tag, the verb also requires `--acknowledge-unauthenticated-tail`; it keeps those entries and appends `audit_entries_quarantined { quarantined_count }` directly after them, in the same file and before its `audit_tip_anchored` rows. A tail that ends on a rotation handoff without a valid tag refuses with `audit.reanchor_failed` and names the line to remove. Readers skip quarantined rows. A changed audit binding needs `--acknowledge-binding-change` instead, and both flags when the current path's anchor also disagrees; see **Audit binding** below. See [Audit-log recovery](audit-log-recovery.md).

**Audit binding.** A persisted profile's audit log is bound in the keyring, at service `stellar-agent-auditbinding-<profile>` and account `default`, to the SHA-256 of its lexically normalized `audit_log_path` and to its audit-key coordinate. The record is JSON, `{"version":1,"log_path_sha256":"<64 hex>","audit_key":{"service":"...","account":"..."}}`, and parsing is strict. The coordinate derives from the selected profile name only. Before a keyed writer loads the chain-root key, it compares the profile with the record:

| Record | Persisted profile | Synthesized profile |
| --- | --- | --- |
| Absent | Record the profile's binding once the key has loaded, and continue; a failed write fails the acquisition with the keyring code | Continue; record nothing |
| Equal | Continue | Continue |
| Different or unparseable | Refuse with `audit.log_binding_changed` | Refuse with `audit.log_binding_changed` |

A read error other than an absent entry fails closed and writes nothing. The refusal names the profile and the remedy, never a path, a coordinate, or the record. `audit verify --profile` reads the binding without writing it and refuses a changed one the same way. `profile rotate-audit-key` checks it before it opens the writer, so a changed binding creates and anchors nothing at the repointed path, and records an absent one after the writer opens. The read-only smart-account verbs refuse rather than fall back to an unkeyed writer. Unkeyed writers, the startup advisory included, read and write no binding.

`audit reanchor --acknowledge-binding-change` accepts the change. The verb checks the binding before it opens the repair writer, because opening creates the directory, the lock sidecar, and the log file. It decides whether the current path's anchor disagrees with its log, by the rule `audit verify` applies or because the stored value cannot be parsed, and decides again under the writer's lock. A file ahead of its anchor agrees. An absent anchor disagrees when a chain-root sidecar or an `audit_tip_anchored` row shows prior anchoring; the decision under the lock reads the rows from the writer's replay of the active file, as the writer's own missing-anchor refusal does. With an agreeing anchor, or an absent one without that evidence, the binding flag alone is required and `--acknowledge-rollback` is ignored; with a disagreeing anchor both are required. The verb replays the current file and reads the anchor of the old path at the coordinate the recorded binding names. It anchors the current tip and bumps the current path's re-anchor counter once. It appends `rollback_acknowledged` when the anchor disagreed, then `binding_changed`, which names the old path's anchor as `previous_anchor`, both carrying the one bumped count. It stores the new binding last, so a run that stops earlier leaves the refusal in place. An unparseable record gives `previous_anchor` none.

The default `audit_log_path` derives from the OS data directory, which follows `$HOME` and `$XDG_DATA_HOME`. Two profile files of one name in two data roots that share one keyring bind different digests and refuse each other. Set an explicit `audit_log_path` in such a deployment.

### Closed wire-code set

Every `VerifyError` maps to one code from a fixed set; the line number and file basename go in the envelope `detail`, never the code, keeping cardinality bounded:

`audit.chain_broken`, `audit.rotation_gap`, `audit.hmac_mismatch`, `audit.hmac_sidecar_missing`, `audit.entry_tag_invalid`, `audit.too_many_rotated_files`, `audit.non_regular_file_log_path`, `audit.parse_error`, `audit.path_contract`, `audit.log_not_found`, `audit.io_error`, `audit.signer_set_canonical_body`, `audit.partial_rotation`, `audit.tip_anchor_mismatch`, `audit.tip_anchor_missing`.

The writer adds eight of its own outside that set, carried in the envelope detail rather than as `VerifyError` codes. `audit.writer_locked` means another process holds the writer lock. `audit.rotation_bridge_unusable` means the newest archive cannot supply the cross-file chain seed. `audit.outbox_busy` means the audit outbox lock stays held past its wait. `audit.outbox_unusable` means a committed outbox line does not parse or is not a consent row (`approval_attested` or `approval_attested_remote`). `audit.tip_anchor_unavailable` means keyring-held audit state could not be read or written. `audit.row_too_large` refuses a row over the byte cap. `audit.outbox_rows_missing` refuses a missing or changed committed queue prefix. `audit.outbox_loss_not_found` refuses an acknowledgement without a queued-row loss. Two writer refusals reuse codes from the set above with their own reasons: `audit.tip_anchor_mismatch` with reason `unauthenticated_tail` refuses a tail past the anchor without valid entry tags, and `audit.chain_key_unavailable` refuses an open without the audit key on a log that shows keying.

The value-verb pre-flight surfaces those and the rest of the writer's failure classes the same way. It stays fail closed for all of them, and each refusal names the remedy for its own condition. A tip-anchor mismatch carries `audit.tip_anchor_mismatch` and a missing anchor carries `audit.tip_anchor_missing`; both name the repair verb. A changed audit binding carries `audit.log_binding_changed` and names `audit reanchor --acknowledge-binding-change`. A condition about the LOG (held lock, unusable bridge, broken chain, an anchor that cannot be read or written, busy or unusable outbox, missing or changed committed outbox rows, I/O) carries `audit.chain_key_unavailable`. The specific `audit.*` sub-code heads the detail, with a pointer to the recovery runbook. Only a registry path or key registration conflict keeps the wording about a conflicting registration. `audit verify`'s tip-anchor refusal carries the verifier's own message under `audit.tip_anchor_mismatch`, with the anchored and observed counts and offsets, rather than the signing-path wording; its missing-anchor failure carries `audit.tip_anchor_missing` with the evidence and the observed count and offset.

A missing primary log surfaces `audit.log_not_found` and is classified validation-class (user-actionable: nothing has been written yet, or the path is wrong), distinct from an integrity violation.

The non-regular-file check rejects directories and symlinks before open, closing a symlink-redirect surface. A detected mid-rotation crash state (`PartialRotation`) is surfaced as an error and requires operator intervention; it is never auto-recovered, because silent recovery could mask a tamper attempt that manufactured the same directory state.

### Value-action emission sites

The commit and submit paths in the following table write `value_action_submitted` after the on-chain action confirms. It carries the SAME value legs the policy gate sized (single-derivation invariant: the legs are the `ValueEffects` the gate evaluated, never re-derived at the emission site). The redacted transaction hash (first-8-last-8) and confirmed ledger are recorded; the row never carries key material. Emission is non-fatal: a row-write failure after a confirmed submit logs a warning and never changes the result. A DeFi adapter that instead FAILS at submit records a `sa_raw_invocation` row (with the mapped `SaInvocationResult`) in its error arm.

x402 authorization signing is the exception to the row kind and to the timing. It writes `x402_payment_authorized` (its own `EventKind` carrying legs, network, and scheme) rather than `value_action_submitted`. The wallet signs the payment authorization without submitting it. The signed authorization still leaves the wallet: the payment flow re-simulates the signed entry against the configured RPC. That RPC therefore observes the signed x402 authorization and is part of the trust boundary.

The ordinary path, `exact::create_payment`, receives its clients from the host. Its `validate_requirements` refuses a mainnet passphrase or a mainnet-pattern endpoint before any request. The authorized path, `exact::create_payment_authorized`, takes bound mainnet proofs and returns the payment with its release authorization. It obtains its primary client from the bound context and its witness through the bound network helper. Both paths share the checks below.

Before signing, the payment flow requires the first simulation to return one unsigned legacy `Address` entry for the payer. Its root invocation must equal the built SAC `transfer` and carry no nested calls; any other answer returns `UnexpectedAuthEntries` before a signing primitive or the transmit gate runs. After the re-simulation, it requires a decodable first result whose authorization entries are empty or equal to the signed entries. A missing or undecodable result returns `RpcSimulateFailed`, other entries return `UnexpectedAuthEntries`, and no payload is returned.

Every request of the payment goes to the primary client, and `getNetwork` is its first request. On the ordinary path, the tool builds that client from the profile, and an endpoint identity refusal returns `EndpointIdentity` with its `network.*` code before any simulation. The authorized path checks that the endpoint serves mainnet before its first simulation. Both simulations must carry no restore preamble, a `minResourceFee` between 1 and 10,000,000 stroops, and transaction data that lists no archived entries and embeds a resource fee no larger than that minimum. The signed window is `ceil(min(maxTimeoutSeconds, 300) / 5)` ledgers after the first simulation's ledger, and an overflow refuses. A `getHealth` read on the same client must report `healthy` at a ledger before expiration. The first simulation lies at most one ledger ahead of it, and the re-simulation at most one ledger behind it and before expiration. These are consistency checks against one endpoint.

On the ordinary path, the tool prepares the cross-check witness before the signer load when the payment's amount reaches the asset's threshold. Its oracle client is the only other client of the payment; `create_payment` builds none. Between the first simulation and the health read, the oracle simulates the same unsigned envelope. Its answer must carry no error and no restore preamble and hold exactly one result. Its authorization entries match the primary's in count, `Address` credentials, address, and root invocation, with a `Void` signature. Its `minResourceFee` lies between 1 stroop and the ceiling. Its ledger trails the primary's by at most two and lies before the signature expiration. Nonce and expiration are not compared. A disagreement returns `CrossCheck` with `simulation.divergence` before a signing primitive runs. That comparison is the independent evidence that the transfer simulates and that the ledger the expiration derives from is current. The oracle's answer is never signed and never replaces the primary's: the nonce, the resource data, and the fee still come from the primary RPC. The health read keeps the identity deadline, so a witness that runs past it refuses at the health read, before signing.

On mainnet the oracle bounds the ledger of every payment, not only of a payment that requires the witness. Below the threshold, `obtain_soroban_witness_bound` has the oracle answer the mainnet identity and then `getLatestLedger`. The answer goes through the witness read's retry policy and refusals and the same two ledger checks: it trails the primary's simulation ledger by at most two and lies before the signature expiration. The outcome stays `not_required`. The independent ledger bound limits the expiration window despite an inflated primary answer. A mainnet profile without `oracle_provider_url` refuses every x402 payment with `network.witness_unavailable` (`OracleNotConfigured`) before signing. The expiration still derives from the primary's simulation ledger.

The transmit gate writes the row under the writer guard and requires a current anchor before and after it. Mainnet `x402_payment_authorized` rows record `RequireApproval`, the payment value leg, network, scheme, any required witness, and `signature_expiration_ledger`, the last ledger at which the signed authorization is valid. Every mainnet x402 error reply after the transmit gate passes appends a sentence that names that ledger. The signed authorization may have reached the configured RPC, and the host accepts it through that ledger whatever the wallet does next. A failure withholds the authorization with the mapped audit refusal. A failure after the row adds an `x402_authorization_withheld` row with the same `request_id` and a `failure_stage` label. The labels are `anchor_unavailable`, `resimulation`, `response_processing`, `encoding`, `payload_release`, and `terminal_approval`. On testnet, the anchor stage precedes transmission and keeps admitted spend. On mainnet, it precedes intent consumption, and the open intent releases its holds. A missing or undecodable re-simulation result is stage `resimulation`, and so are a re-simulation that asks for a restoration, breaks the fee bounds, or reports a ledger outside the bounds. Re-simulated entries other than the signed entries are stage `response_processing`. On mainnet, a refused intent consumption after the gate is also stage `response_processing`; the signed authorization has not reached the RPC then. `payload_release` marks a refused release consumption, and `terminal_approval` a pending approval that could not be consumed after it. That row is best-effort, and a failure to write it is logged at `error`.

The payment intent authorization binds the entry's nonce and signature expiration ledger beside the intent digest, in memory; the ledger record binds the intent digest. `check_preimage_against_authorization` refuses another nonce with `entry_nonce` and another expiration ledger with `entry_expiration`. `sign_soroban_auth_entry_authorized` takes the authorization by value and returns the signature with a `MainnetSignedSorobanIntent`, the only value `consume_soroban_intent` accepts, so one authorization signs one entry.

On mainnet, three consumption boundaries order the authorized path. The Message authorization of an authenticated payment is consumed before the SEP-10 signature. The payment intent is consumed before the signed simulation. The submit authorization is consumed before payload release. `consume_message_sign` consumes the Message authorization and returns `MessageUseReceipt`. The receipt carries the bound facts and owns the audit lease. `X402MainnetProofs::with_authenticated` moves the receipt into the owned payment proofs.

On mainnet, after release authorization is consumed, the tool consumes the pending approval. A failed or absent pending-record consume withholds the payload. The `payment withheld at terminal approval` prefix marks a refusal after the signed re-simulation. The x402 tombstone's `tx_hash` contains the lowercase final-envelope digest. The digest hashes the final envelope's base64 text, rather than a chain transaction.

| Surface | Verb / tool | Row |
| --- | --- | --- |
| MCP | `stellar_pay_commit`, `stellar_create_account_commit`, `stellar_claim_commit`, `stellar_trustline_commit` | `value_action_submitted` (sized legs) |
| MCP | `stellar_dex_trade`, `stellar_defindex_vault_deposit`, `stellar_defindex_vault_withdraw` | `value_action_submitted` on success; `sa_raw_invocation` on submit failure |
| MCP | `stellar_x402_create_payment`, `stellar_x402_authenticated_payment` | `x402_payment_authorized` (its own `EventKind` carrying legs, network, and scheme, plus a passed witness when the payment required one), fatal, before the signed re-simulation. `x402_authorization_withheld` follows a later failure, at a stage the paragraphs above list. Mainnet `x402_payment_authorized` rows record `RequireApproval` before signed re-simulation. Later withholding rows identify the failed stage with the same request identifier. |
| MCP | `stellar_sep43_sign_and_submit_transaction` | `value_action_submitted` (opaque: empty legs + `opaque_reason`) |
| CLI | `pay`, `claim`, `accounts create` (sponsored mode only), `trustline`, `trade` | `value_action_submitted` (sized legs) |

The value descriptor reaches the emission site through the policy engine's `evaluate_full` / `evaluate_with_value_full`, which surface the sized `ValueEffects` on the allow path; the decision-only `evaluate` / `evaluate_with_value` views discard it and must never gate a value-moving dispatch (see the rustdoc on those methods). Rows are written under the profile's `audit_log_hash_chain_key_id`, loaded through the single `stellar_agent_network::keyring::load_hmac_key_32` source, so `audit verify` covers them.

The emission layer differs by surface. The CLI `pay`, `claim`, `accounts create`, and `trustline` verbs and the CLI `trade` verb emit at the CLI layer. The DEX and DeFindex submits emit inside the shared DeFi adapters, so both the MCP and CLI DeFi paths route through the same emission site rather than each surface emitting its own row.

### Key-write emission sites

Each profile command that writes long-lived key material to the keyring records a `keyring_key_written` row after the write succeeds, naming the key slot (`key_purpose`) and the keyring coordinates. The signer and owner-key enroll commands additionally record a redacted (first-5-last-5) public address; the RPC credential enrollment and the HMAC-key rotations record none. The row NEVER carries a key value, seed, base64 material, or any derived secret.

| Command | `key_purpose` | Public address |
| --- | --- | --- |
| `profile enroll-signer` | `mcp_signer_seed` | redacted derived address |
| `profile enroll-owner-key` | `owner_public_key` | redacted owner address |
| `profile enroll-rpc-credential` | `rpc_credential` | none |
| `profile rotate-nonce-key` | `nonce_hmac` | none |
| `profile rotate-attestation-key` | `attestation_hmac` | none |
| `profile rotate-counterparty-key` | `counterparty_cache_hmac` | none |
| `profile rotate-audit-key` | `audit_hash_chain_hmac` | none |
| `profile rotate-policy-state-key` | `policy_window_state_hmac` | none |

`rotate-audit-key` takes the audit writer's exclusive sidecar lock first and holds it throughout. No other process can append or rotate while the per-file sidecars are being rewritten. The MCP server acquires its audit writer when an operation needs it, such as a commit preflight before signing. MCP balance reads do not acquire it. Under V1, payment simulations can reconcile overdue reservations, acquire the writer, and write settlement audit rows. The registry normally caches the writer and holds its lock until process exit. A replaced-file refusal during acquisition marks the cached writer for eviction. After callers release it, the next acquisition drops it and checks the file at the path against the anchor. While the server holds the writer, rotation refuses with `audit.writer_locked`, even if the operation that acquired it later fails. The envelope carries that code in its detail, as the `approval.*` and `counterparty.*` lock codes do. Acquiring the writer also runs the tip-anchor check before the key is touched, so a rolled-back log is refused with the profile's key left alone. With an old key it then checks the log's entry tags under that key, under the held lock, and refuses with that check's code (`audit.entry_tag_invalid` among them) before any key write. It then (1) persists the new key, (2) loads it and switches the held writer to it, which appends `audit_entry_tags_rekeyed { cause: rotation }` tagged under the new key once tags are in force, (3) appends the `keyring_key_written` row, (4) reconciles the tip anchor and drains the audit outbox, and (5) re-signs every per-file chain-root sidecar with the new key. No file is rewritten. A crash between (1) and (2) leaves entries tagged under the old key past the newest keyed start; the next keyed open appends `audit_entry_tags_rekeyed { cause: open_repair }`, and a rerun converges the same way. A first mint appends no rekey row. Re-signing last is what covers a row that happened to open a new file: its chain root is brought onto the new key by the same pass. A drained consent row that opens a new file is covered by the same pass. The re-sign pass reads the replacement key from the keyring after persistence.

## Wallet unlock lifecycle

The unlock window bounds when the CLI environment signing path can access or transfer a 32-byte seed. The MCP server uses keyring signer handles. `Wallet` manages access; `LockedSeed` owns the stable home.

### Zeroizing seed and eager pin

`Wallet::unlock(profile_name, &seed, ttl_seconds, mlock_required)` is synchronous. It allocates a zeroed 64 KiB-aligned home, attempts its configured lock, then copies the borrowed seed into it. `region::lock` eagerly pins with `mlock(2)` on POSIX or `VirtualLock` on Windows. Each home occupies a separate allocation so another seed's drop cannot unlock its page. A page size above 64 KiB is a lock failure under `True` and `Warn`.

`signer_from_wallet` consumes the wallet and transfers its `LockedSeed` into the signing key. Signing reads that same address. Drop zeroizes in place before unlocking and freeing the home, including on panic unwind.

### MlockRequired postures

`MlockRequired` has three postures controlling behaviour when `mlock` fails:

| Value | Behaviour on `mlock` failure |
|-------|------------------------------|
| `true` (default Linux/macOS) | Fail closed: `WalletLifecycleError::MlockUnavailable`; unlock refused before the seed enters the home. |
| `"warn"` (default Windows) | Proceed with unprotected memory; emit `tracing::warn!`. |
| `false` | No lock attempted; no warning (operator accepts swap-disclosure risk). |

The posture is set in the profile file and is not overlayable.

A tolerated lock failure emits a structured warning with `profile`, `reason`, and `errno`, and returns those details to the caller. The mainnet environment path appends `wallet_mlock_failed` after submission or attach refusal. This ordering keeps an audit rotation from invalidating the authorization before submission.

### TTL cap and RAII dispose

The default TTL is `DEFAULT_TTL_SECONDS` (30); the hard cap is `MAX_TTL_SECONDS` (600). `unlock` rejects `ttl_seconds == 0` or `ttl_seconds > 600` with `WalletLifecycleError::TtlInvalid`. The profile field `wallet.unlock_ttl_seconds` is validated against that range when the window is constructed: a value of 0 or above 600 is refused, never clamped.

`Wallet::seed` and `Wallet::into_locked_seed` check the clock and refuse access after expiry. The seed stays in a zeroize-on-drop page, locked when the lock succeeds, until its wallet or receiving signer drops it. Mainnet environment signers unlock once per signature and drop the seed afterward. Testnet environment signers keep it for their command, which can outlast the TTL. `Wallet` and `SoftwareSigningKey` are `Send + Sync`; shared mutation requires caller synchronization.

## Headless keyring store

Windows Credential Manager requires an interactive logon session; a Windows service, an SSH/WinRM session, or a scheduled task fails every keyring read/write with `auth.keyring_interactive_session_required`. The `stellar-agent-headless-keyring` crate provides an opt-in, file-backed alternative for exactly this deployment shape. It implements `keyring_core::api::CredentialStoreApi` / `CredentialApi` and slots in behind the SAME `KeyringEntryRef` (service, account) coordinates every existing enroll/rotate/sign call site already uses. `keyring_core::Entry::new(service, account)` is unchanged everywhere; only which concrete store answers it differs.

### Activation surface

`stellar_agent_network::keyring::init_platform_keyring_store` checks the `STELLAR_AGENT_KEYRING_BACKEND` environment variable FIRST. It is called unchanged at every existing keyring-consuming call site across the CLI and MCP server (~25 sites). Unset: the platform keyring (unchanged default). Set to `"headless-env"` or `"headless-dpapi"`: the headless store is registered as the process default instead. Initialisation NEVER falls back to the platform keyring on any failure (missing/invalid key, unsupported platform, or state-directory resolution failure all refuse). There is no profile-file `[keyring] backend = ...` surface. Threading a `Profile` reference through every `init_platform_keyring_store()` call site was judged not worth it against an env var that already fully serves the deployment shape this feature targets. Most call sites have no loaded profile in scope at that point.

### Protection modes and trust model

| Mode | Env var | Primitive | Trust boundary |
|------|---------|-----------|-----------------|
| `headless-env` | `STELLAR_AGENT_HEADLESS_KEYRING_KEY` (32-byte URL-safe base64, no padding) | XChaCha20-Poly1305 (`chacha20poly1305` crate) | The env var is the root of trust: any reader of it can decrypt every entry. Targets Linux services and CI where a secret manager already injects env vars under trusted access control. |
| `headless-dpapi` (Windows only) | none | `CryptProtectData` / `CryptUnprotectData`, CurrentUser scope, with the entry's coordinate as optional entropy, via `stellar-agent-windows-identity`'s `dpapi_protect_with_entropy` / `dpapi_unprotect_with_entropy` (`CRYPTPROTECT_UI_FORBIDDEN`, never blocks on a UI prompt) | Processes running as the same Windows user can decrypt when that session can access the user's DPAPI master key. |

DPAPI depends on access to the current user's master key. Key-authenticated SSH
sessions can lack that access; an interactive desktop logon may help.
`headless-env` has no DPAPI dependency and requires its configured encryption key.
Under `headless-env` the profile's audit key, and with it the entry-tag key, stays
sealed from code that lacks the configured encryption key. Under `headless-dpapi`
any process of the same Windows user can read the audit key and compute valid
entry tags.
Protect failures report `auth.keyring_platform_error` with the operation, backend,
and fixed `CryptProtectData` diagnostic, including the numeric Windows code when
available. Unprotect failures keep a detail-free cryptographic error and map to
`BadDataFormat`; their wallet diagnostic reveals no decryption reason or code.

Both modes are tamper-evident and fail closed: XChaCha20-Poly1305 carries its own Poly1305 authentication tag (a tampered ciphertext fails to decrypt); DPAPI blobs are self-authenticating (`CryptUnprotectData` fails on a modified blob). Both modes bind `service`||`\0`||`account` to the value: `env-key` as AEAD associated data, `headless-dpapi` as DPAPI optional entropy. A ciphertext relocated to a different entry coordinate fails to open. A DPAPI entry sealed with no entropy opens through the call without entropy once; the read rewrites it bound to its coordinate under the store lock, only while the file still holds the value it opened, and a failed rewrite fails the read. Until that first read such an entry opens at any coordinate. An entry that opens neither way fails as a corrupt value. Owner public keys are stored as G-strkeys, a form no 32-byte symmetric-key loader accepts, and every symmetric-key loader refuses a key equal to the profile's owner public key.

### Mainnet

The headless store carries no generation or freshness witness. Restoring an older copy of its file together with a truncated audit log makes the tip anchor and the log agree again, so the anchor cannot prove the log was not rolled back. Mainnet readiness (`audit_readiness`) and `profile enable-mainnet` therefore refuse a process whose active backend is not the platform keyring with `network.mainnet_keyring_backend_unsupported`, before any keyring entry is read. `stellar_agent_network::keyring::active_keyring_backend` reports the backend: a registered headless store answers first, then `STELLAR_AGENT_KEYRING_BACKEND`, the input backend selection reads, so a check before registration and one after agree. An unrecognized value of that variable counts as not the platform keyring. Testnet paths do not check the backend.

### Storage

One JSON file for the whole host/user (not one per profile: the `(service, account)` coordinate space inside the file is checked against sibling profiles, mirroring the platform keyring's own single-shared-store shape) at `<canonical_data_root>/headless-keyring/store.keyring`. Written atomically: temp-file + `sync_data` + rename + parent-directory fsync (`0600` on Unix), the same discipline `PersistedWindowStore` (policy window-state) and the audit-log sidecar writer use. A corrupted or unparseable file fails every subsequent read closed (`keyring_core::Error::BadStoreFormat`) rather than silently behaving as an empty store. Every write takes a cross-process sidecar lock, `<store>.lock`, then re-reads the file, applies its one change, and rewrites it atomically, so concurrent writers in different processes are serialized. Reads take no lock.

### Audit and logging

Enrollments/rotations through this store emit the SAME `KeyringKeyWritten` audit row every existing profile command already emits. That emission is keyed off `keyring_core::Entry::set_password` succeeding, which is backend-agnostic. The store additionally emits a `headless_keyring.write` tracing log line naming the active protection mode (`backend = "headless-env" | "headless-dpapi"`), so the backend kind is visible in logs without a hash-chained audit-schema change. A DPAPI entry rewritten bound to its coordinate emits `headless_keyring.entry_rebound`.

## Nonce scheme

The nonce primitive lives in the `stellar-agent-nonce` crate (`crates/stellar-agent-nonce/src/lib.rs`). The MCP server mints a nonce at simulation time and verifies it at commit time through a replay window.

### Wire format and salt

A `Nonce` is 48 bytes, transmitted as URL-safe base64 with no padding:

```text
bytes[0..16]  = random salt (OsRng)
bytes[16..48] = HMAC-SHA256 tag (32 bytes)
```

The salt does not feed either side of the HMAC. Its role is uniqueness (two calls with the same envelope in the same millisecond still produce different nonces) and, as part of the full 48-byte nonce (salt plus tag), keying the replay window's HashMap.

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

`ReplayWindow` is a `HashMap`-backed single-use tracker with TTL eviction, held per `WalletServer` instance. It is not persisted across process restarts. The fail-closed-on-restart property comes from `boot_nonce`: a 16-byte `OsRng` value initialised once per process and never persisted. A nonce minted before a restart carries the old `boot_nonce` baked into its HMAC tag, so after restart the recomputed tag differs and the nonce is rejected (`HmacMismatch`). An in-memory-map-only design was rejected because an empty post-restart map would accept a pre-restart nonce on first presentation; a persistent counter was rejected because it would let an operator opt out of fail-closed-on-restart.

### Key residency and rotation

The HMAC key is the profile's `mcp_nonce_key_alias` keyring entry, stored as URL-safe-no-pad base64 (platform keyrings accept UTF-8 passwords; raw bytes can fail on some backends). `NonceMint` holds no key bytes: every `mint` / `verify` lazy-loads the key into a `Zeroizing` guard for a single stack frame, copies the first 32 bytes into a `Zeroizing<[u8; 32]>`, and drops the intermediates immediately. `rotate_nonce_key` generates 32 fresh `OsRng` bytes, base64-encodes them, and atomically swaps the keyring entry; the CLI exposes this as `profile rotate-nonce-key`.

## Submit-layer network binding

A Stellar signature commits to a network: the SEP-23 `TransactionSignaturePayload` the signer hashes carries `network_id = SHA-256(network_passphrase)`, so the same transaction signed for two networks produces two different signatures. Nothing in the wire format records which network a signature was made for; it can only be recovered by re-deriving the payload under a candidate network id and checking the signature against it. The check lives in `crates/stellar-agent-network/src/signing/verify_binding.rs`; the endpoint check it rests on is `StellarRpcClient::endpoint_identity`.

### Ordinary submission order

1. A caller-declared mainnet network passphrase is refused with `network.mainnet_write_forbidden`. Zero RPC calls.
2. An RPC URL matching a known mainnet host is refused the same way. Zero RPC calls.
3. The envelope is decoded locally. A malformed envelope, or a legacy `TxV0` envelope, is refused with no round trip: V0 is not part of the SEP-23 tagged-transaction set, so neither the signing path nor this one can construct a payload for it.
4. The endpoint is asked which network it serves and which protocol it runs (`getNetwork`), on the same client instance that will send.
5. The ed25519 signer sets of the accounts whose authority the transaction invokes are fetched in one `getLedgerEntries` call.
6. Every decorated signature is verified under the network id the endpoint reported.
7. `sendTransaction`, then poll `getTransaction`.

Steps 4 and 5 are two reads ahead of the send, so inside the submit layer every submission makes two round trips before the send.

### Authorized signing and submission

The four full-mode classic CLI verbs and four classic MCP commits resolve
sealed authority before signing. Endpoint identity binds the originating client,
network, and protocol. Transaction authority binds the envelope and signer.
Signing checks authority before key access and verifies the returned signature.
A verification refusal can therefore follow a signer call.

The submit entry independently checks its grant, endpoint/client identity,
transaction binding, and signatures. `SubmissionRecorder::pre_send_authorized`
durably consumes authorization before `sendTransaction`. Refusal after signing
withholds submission; it does not establish that no signature exists.

Pending-approval attestations on testnet use version 4: the version 3 fields
(approval kind, creation time, and expiry) plus the approver, either the local
operator or the remote operator credential the listener verified. Every
testnet pending-approval consumer requires `attestation_version = 4` with a
well-formed approver; a record under version 2 or 3, or without an approver,
verifies nothing. Toolset grants keep their own versions.
`approval.attestation_invalid` covers missing coverage or a mismatched
subject. MCP reports failed approval proofs as `policy.approval_required`.

#### Mainnet presence consent

A mainnet consent is a version 5 attestation with a mainnet passkey approver
and a WebAuthn presence receipt. The attester takes a sealed
`ConsentAuthorization`: `Standard` (local or remote approver) refuses on a
mainnet binding with `approval.presence_required` before any row or store
write, and `Mainnet` carries a `VerifiedMainnetPresence`, which only
`verify_mainnet_presence` produces, with the current verified policy.

A same-user process holding the audit HMAC key can wrap a version 5 record
around a user-verified assertion that its own localhost page obtains. A
misleading local page remains a risk. The owner seed admits approval
credentials, so signing the policy on a host where same-user code runs
exposes that seed.

The ceremony issues one challenge per pending entry from
`issue_mainnet_presence`, under the policy that `MainnetApprovalAuthority`
loads from the persisted profile's owner key, signed policy, pin, and
enablement, never from a request:

```text
challenge = SHA-256(
  b"stellar-agent-mainnet-presence:v1" ||
  random32 || lp(consent_request_id) || lp(approval_nonce) ||
  lp(profile_name) || lp(chain_caip2) || lp(kind_name) ||
  subject32 || lp(process_uid) ||
  u64be(entry_created_at_ms) || u64be(entry_expires_at_ms) ||
  i64be(policy_sequence) || policy_digest32 || policy_owner32 ||
  lp(b"localhost") || lp(expected_origin) ||
  u64be(challenge_issued_at_ms) || u64be(challenge_expires_at_ms)
)
```

`lp(x)` is `u32be(len(x)) || x`. The subject is the classic envelope subject,
the x402 subject with its home domain, or the trustline clawback opt-in digest;
other kinds have no mainnet consent path. The challenge lives for the shorter
of 120 seconds and the entry's remaining life, on the monotonic and the wall
clock, and verifies at most once. The relying-party ID is `localhost`; the
expected origin is exactly `http://localhost:<port>` from the bound listener,
`crossOrigin` must be absent or false, and `topOrigin` absent.

Verification runs the shared assertion primitive in
`stellar-agent-core::approval::webauthn`, beside the DER-to-compact low-S
normalization; the smart-account verification functions forward to both. The
primitive checks the type, challenge, relying-party hash, user
presence, user verification, the backup flag pair, and the ES256 signature over
`authenticator_data || SHA-256(client_data_json)` under the public key the
signed policy lists for the asserted credential ID.

The receipt keeps the consent request ID, the random input, the policy
sequence, digest, and owner, the expected origin, the issue, expiry, and
verification times, and the raw assertion. Its digest is SHA-256 of
`b"stellar-agent-mainnet-presence-receipt:v1"`, `u32(version)`,
`lp(request_id)`, the random bytes, `i64(policy_sequence)`, the policy digest
and owner bytes, `lp(expected_origin)`, the three times as `u64`, then `lp` of
the credential ID, authenticator data, `clientDataJSON`, and compact signature.
The version 5 HMAC is the version 4 preimage under the tag
`stellar-agent-approval-attestation:v5`, with the approver tag `0x02` and the
length-prefixed credential ID, followed by the 32-byte receipt digest. The
store records version, approver, receipt, and blob together; the version 4
record methods refuse a mainnet passkey approver.

Before the row, the attester rechecks the locked entry's nonce, kind, uid, and
both lifetime fields against the challenged snapshot, recomputes subject and
challenge, requires the current policy to equal the challenge's policy by
sequence, digest, and owner, and checks both deadlines again after the keyring
and audit waits. The commit witness repeats the receipt checks without the
browser session or the monotonic clock: version 5, the mainnet passkey
approver, the HMAC, the raw assertion under the current signed key, the
challenge recomputed from the stored record, `issued <= verified < expires`,
`expires <= entry_expires`, at most 120 seconds of challenge life, and
`verified <= now`. The witness binds the receipt digest and the policy digest,
and authorization requires the policy digest to match the policy it resolves
under (`approval_policy_mismatch`).

The authority loads the policy with `PinMode::Advance` at challenge issue, so
an observed credential removal cannot be rolled back through wallet commands,
and with `PinMode::CompareOnly` at the witness. Lock order: the pending store,
then the window state; no presence code runs while the window-state lock is
held.

The `approval_attested` row of a mainnet consent carries `mainnet_presence`:
the credential fingerprint, the challenge and receipt digests, the policy
digest and sequence, the relying-party ID and origin, the UP and UV flags, the
signature counter, and the verification time. The counter is recorded only; no
durable counter is kept and no clone is detected.

Mainnet approve, the local inbox, and direct CLI confirmation open a localhost
passkey page. The operator reviews the authoritative transaction and approves
with an owner-pinned credential. Headless consent, `--yes`, `--no-open` on the
mainnet inbox, and remote mainnet approval refuse. Ledger signing also requires
this passkey ceremony.
The page binds its rendered view digest to the current entry and signed policy
before issuing a challenge. Challenge and assertion requests require the
session cookie, per-nonce CSRF header, and origin-scoped session proof.
A challenge is consumed before assertion decoding, including on failure.
The one-shot listener returns a sealed proof to the command; the inbox consumes
it through the shared decision path. Both paths reload authority after waits.
The command waits until pending expiry; each challenge lasts at most 120 seconds.
The listener uses the exact bound localhost port as its assertion origin.


### Endpoint identity before the first signed read

The submit layer's check covers the bytes it sends, but the values in those bytes are read earlier. The fee, the source sequence, and the claim entry are signed. The account views and the reservation reconcile shape the policy decision. The classic paths therefore read and send through one client and check its endpoint first:

- CLI `pay` and `claim` in every stage that reads, sponsored `accounts create`, `trustline`, and `pool init` build one `StellarRpcClient` per run. Its endpoint check runs immediately before the first request whose answer feeds a signature or a policy decision, and the send goes through it.
- The MCP prepare tools `stellar_pay`, `stellar_create_account`, `stellar_trustline`, and `stellar_claim` check their client before its first read. The commit tools check the client they submit with before the sequence read, so the check is the first request on it.
- `--sign-only` checks only when it decodes the envelope and reads the accounts its gate needs. An envelope it cannot decode is signed with no request.
- A `pool init` resume makes no request when the profile already holds the pool or the checkpoint records its completion. Every other resume checks before its first read, whether or not it sends.

Checks that need no request keep their place ahead of the endpoint check: argument, keyring, and profile validation, envelope decoding, the structural mainnet refusal, and the relayer refusal. The `pool init` audit pre-flight and the forced approval of a toolset-gated MCP pay commit without approval fields need no request either and come first. On the full CLI `pay` pipeline, `--source` and `--fee` are checked after the reconcile.

Every refusal that follows a read comes after the endpoint check. Those are account and claim-entry errors, policy denial, approval refusal, rebuild divergence, the audit pre-flight, a malformed nonce, and the chain, fee, asset, and amount checks. The reservation reconcile and its settlement come after it too. A CLI `claim` or `trustline` refused at the early check carries no preview.

The cross-check witness uses `oracle_provider_url` and checks its endpoint identity
before reading. The oracle must serve the primary's chain. Identity and reads
share a 15-second attempt deadline. Transport read failures retry up to three
attempts, seven seconds apart. Disagreements, identity or credential refusals,
invalid answers, and elapsed deadlines never retry.
The MCP dispatch gate reconciles reservations on a client of its own.
On the CLI, reconciliation uses the primary client.

An MCP commit's early check refuses without consuming the nonce. The commit reads the clock for the nonce's expiry after the check, so the check's time counts toward that expiry. A refusal by the submit layer's own check comes after the nonce is consumed.

### Cross-check witness

Each witnessed stage compares the entries its decision read on the primary.
The witness follows the policy decision and fee-cap check.
CLI pay, claim, and sponsored create, and all four MCP classic commits witness
before the audit pre-flight. CLI trustline and pool init witness after their
pre-flight and before the signer load that sends.
Pool init permits its fresh funder identity load and checkpoint recovery before
the witness. Recovery includes seed and receipt settlement writes.

| Stage | Compared entries | Value |
|---|---|---|
| MCP `stellar_pay_commit` | Payment observations below | Source debit leg |
| MCP `stellar_create_account_commit` | Source account | Starting balance in XLM |
| CLI `pay`, full pipeline | Payment observations below | Source debit leg |
| CLI `pay --sign-only` and `--submit-only` | Payment observations below | Source debit leg |
| CLI `claim`, full pipeline | Source account, record, trustline (below) | Unvalued |
| CLI `claim --sign-only` and `--submit-only` | Source account | Unvalued |
| CLI sponsored `accounts create` | Sponsor account | Starting balance |
| CLI `trustline` | Source, issuer presence and flags | Unvalued |
| CLI `pool init`, every send | Funder, absent channels | Unvalued |
| MCP `stellar_trustline_commit` | Source, fresh issuer flags | Unvalued |
| MCP `stellar_claim_commit` | Source, fresh claimable record | Unvalued |

Payment observations cover the source account and destination presence, home
domain, and flags. They also cover the SEP-29 flag when read and the source
trustline for an issued send asset. Staged payments use the decoded envelope.
They read the SEP-29 flag only for a memo-less envelope paying a plain G account.

A full claim compares the source account and the complete claimable-balance
record. For an issued asset, it also compares the source trustline.

The source debit leg is the send amount of a payment or strict-send path
payment, and the send maximum of a strict-receive path payment. A muxed staged
source or destination is witnessed on its G account. `--build-only` signs and
sends nothing, so it has no witness. An envelope the staged decoder cannot
classify has none either.

The classic witness covers CLI `pay`, `claim`, sponsored `accounts create`,
`trustline`, and every sending `pool init` path. It also covers MCP
`stellar_pay_commit`, `stellar_create_account_commit`, `stellar_trustline_commit`,
and `stellar_claim_commit`. The x402 payment tools `stellar_x402_create_payment`
and `stellar_x402_authenticated_payment` are covered by a second simulation on
the oracle: before the payer signs, the oracle simulates the same unsigned
transfer, and the answers are compared. The mainnet x402 witness binds the
expected transfer and payer. It uses thresholds from the profile and signed
policy. Opaque staged envelopes and the SEP-43 signing tools remain uncovered.

The source comparison covers existence, sequence, native balance, subentry count,
and four authorization flags. Sequence and native balance require exact equality;
a change between reads refuses and requires retrying the action. A trustline
comparison covers existence, balance, limit, and raw flags. Only an absent
destination account counts as absent at the pay sites. Trustline issuer reads
also distinguish absence from errors; any other failed read
refuses with its own code, so a transient primary failure is never compared as
an absence.

One oracle request reads every distinct key. The comparator associates answers
by returned key XDR and validates each entry's embedded identity.
Duplicate, unrequested, malformed, or inconsistent entries refuse as
`network.witness_unavailable`. The witness records the oracle authority, ledger,
SHA-256 digest of compared inputs, and entry kinds. Pending and submitted audit
rows preserve this evidence, including when reconciliation writes the outcome.

The chain enforces sequence, source balance, trustline existence, authorization,
and limits; credit-payment destination existence; account-creation destination
absence; the fee bid; and time bounds. An included transaction that fails an
apply-time check can still cost its fee.
The witness also protects policy reserve and balance views, destination identity,
and SEP-29 decisions before signing.

A skipped or not-required outcome makes no oracle comparison of any kind.
With an oracle configured, a memo-less payment requires a comparison even below
threshold. Mainnet missing asset thresholds refuse before this memo rule.
Reservation reconciliation reads the primary alone.

### Classic fee cap

The covered stages check the per-operation fee against
`classic_max_fee_per_op_stroops` before obtaining a witness.
CLI `pay` and `claim` check the cap in the full pipeline, `--build-only`,
`--sign-only`, and `--submit-only`. MCP pay, create-account, trustline, and
claim check it in both prepare and commit. CLI sponsored `accounts create`,
`trustline`, and every sending `pool init` path also check the cap.
Opaque, fee-bump, and multi-operation staged envelopes and the SEP-43 signing
tools remain outside this coverage.

The checked fee is the resolved auto-selected, explicit, profile, or command
fee, or the fee decoded from a presented or staged envelope. A fee equal to the cap
passes. A fee above it refuses with `fees.percentile_exceeds_cap`, whose text
names the fee's source. On a mainnet profile the cap is required at action
time, refusing with `validation.mainnet_fee_cap_required` when unset;
`profile init --network mainnet` writes `10000`. The fee is not witnessed: the
chain charges at most the bid.

`pool init` passes the per-operation fee to the builder, which multiplies it by
the operation count, three per channel. A fee whose total does not fit the
transaction's fee field refuses with `validation.fee_total_overflow` before the
fresh checkpoint or signer load. The pool crate checks the same total before
building the sandwich. A sending resume checks its fee before retiring an attempt.

The classic callers and resolver check the effective signed/profile cap.
MCP preparation uses the same precedence. The smaller value applies, or the
one available value; a higher profile value warns. The enabled-policy minimum
requires its signed field. The resolver independently evaluates the bound action.
Its fee-check failure becomes `network.mainnet_authorization_refused`.
All four full-mode CLI verbs pass numeric `total_fee_stroops`, equal to unsigned
`tx.fee`, to policy evaluation on both networks. `pay --build-only` and
`claim --build-only` pass it too, so `minimum_reserve` gates the fee of the
envelope they return.

### Endpoint identity is authoritative

The declaration states which network the caller intends; the probe states which network the endpoint is, and the second decides. Transport failures are retried with bounded exponential backoff under the caller's own submission deadline, using the retryability classification of `sendTransaction` with one exception. An answer whose body does not deserialize, such as one without `protocolVersion` or with a value of the wrong type, is not retried. The endpoint answered, and a retry would only spend the deadline on the same answer. A passphrase mismatch is a verdict rather than a transport fault and is not retried. An HTTP 401 or 403 answer is not retried either: the endpoint refused the request's credential, and the same request gets the same answer. `get_health_within` shares this classification. The probe is fail closed: it never falls back to the declaration.

The outcomes, in the order the check reaches them:

- endpoint answers HTTP 401 or 403: `network.rpc_credential_refused`, not retried, with the status and the endpoint's authority
- identity not established within the submission timeout, or an answer that does not deserialize: `network.endpoint_identity_unavailable`
- ordinary submission sees the mainnet passphrase: `network.mainnet_write_forbidden`
- endpoint reports a different network than the caller declared: `network.endpoint_network_mismatch`
- protocol version outside the supported range on mainnet: `network.unsupported_protocol_version`

The same answer carries the endpoint's protocol version, which the protocol rule checks against `SUPPORTED_PROTOCOL_VERSIONS`, protocol 29 in this release. A release adds a version to the range only after its testnet acceptance tests ran against that version. On testnet, and on any other network whose passphrase matches the declaration, a version outside the range passes with one logged warning that carries the version and the range. On mainnet the same version is refused. Ordinary submission refuses mainnet before the protocol check. Authorized submission enforces the mainnet protocol range.

The probe runs on the client instance that will carry `sendTransaction`, not on a fresh one, so the identity that was established is the identity of the connection the transaction goes out on.

### Provider credentials on the RPC client

A provider record can name a keyring entry and a placement for its role's endpoint ([Provider credentials](../profiles.md#provider-credentials)). The loader opens no keyring entry. `Profile::role_url` maps a role to its URL and `Providers::record_for` to its record; `RpcCredentialBinding::for_role` pairs the two, and `rpc_endpoint::rpc_client` reads the credential when a client is built:

- The credential is read only when the URL the caller sends to equals the profile's URL for the role byte for byte. Any other URL, such as a CLI flag or an agent's tool input, gets a client without a credential, and no keyring entry is opened. An agent therefore cannot move a provider key to a host of its choice.
- `NetworkContext::from_profile` binds the primary credential. `NetworkContext::primary_client`
  builds the clients of the CLI classic verbs, their MCP prepare and commit tools, the x402
  tools, and the classic read sites, CLI `fees stats` only with `--profile`. MCP
  `stellar_fee_stats` builds its client with `profile_rpc_client` instead, so a differing
  `rpc_url` input gets none. The cross-check witness builds the oracle client with
  `profile_rpc_client` through `OracleEndpoint::from_profile`; for ordinary `create_payment`
  the MCP handler prepares it, and the x402 crate receives it and builds no client. The
  authorized x402 path obtains its primary client from the bound context. It obtains the
  oracle witness through the bound network helper. The Friendbot path of `accounts create`, the MCP `stellar_friendbot`
  tool, `stellar_sep43_sign_and_submit_transaction`, and the smart-account, DeFi, and MPP
  clients carry no credential.
- The value goes from the keyring into a `Zeroizing<String>` and from there to the transport. A header value is marked sensitive, so its `Debug` form hides it. A query or path placement interpolates the value into the transport target; the client's `url()` returns the configured URL without it.
- `StellarRpcClient` implements neither `Debug` nor `Clone`, because the inner transport prints its target URL.
- Every error the client builds from transport or server text replaces the stored value and the form it sends with `[redacted]` before the URL scrub. For a header value with a scheme prefix, the token after the first space is replaced too when it holds at least 8 bytes. The `error` field of a simulation answer gets the same scrub. A value the server splits, truncates, or re-encodes is not caught.
- The transport's own copies of the value, in the header map and the interpolated target, are not zeroized and live until the client drops.

The reserved-entry rule keeps a credential reference off the entries of the wallet's own keys, so an edited profile cannot make the wallet send a seed or HMAC key to an endpoint. It compares the reference with the wallet key references of the profile being loaded, taken from the merged profile and from the file alone, because a testnet overlay can replace `mcp_signer_default`:

- The ASCII-lowercased `account.service` must differ from that form of every wallet key reference. The Windows store names an entry by joining account and service with a `.`, and both may contain one.
- The service must differ, ASCII case-insensitively, from every wallet key reference's service, which covers accounts derived from that service.
- No `.`-separated part of the lowercased `account.service`, trimmed of spaces, may start with `stellar-agent-` unless it starts with `stellar-agent-rpc-`.
- `service` and `account` hold only printable ASCII without leading or trailing spaces, so no store can fold a non-ASCII letter onto an ASCII name.

The `stellar-agent-` namespace is always covered. A wallet entry with a custom name is covered only as long as the file still names it, and only for the references of the profile being loaded.

`release_max_level_info` keeps `tracing` events above INFO out of release builds. Records from the `log` facade, such as keyring-core's, pass through the `tracing` bridge and are filtered at runtime. A test drives a credentialed identity request with every `tracing` level enabled, the `log` bridge installed, and no redacting formatter, for each placement, and asserts that no log line holds the value. It covers debug builds over HTTP/1.1.

### Retries, deadlines, and failover

The identity check, the signer-set fetch, and `sendTransaction` share one retry policy:

- Up to 5 attempts.
- After failed attempt n, counted from 0, a random sleep in `0..=min(8 s, 500 ms × 2^n)` precedes the next attempt. The four sleep caps are 0.5, 1, 2, and 4 s.
- Each attempt and each sleep ends at the deadline of the invocation that started it. A sleep that reaches the deadline ends the retries with the last error.

Two retry scopes are distinct, and only the first exists. Inside one submission, the retry combinator wraps `sendTransaction`, but under the pinned `stellar-rpc-client` a submission sends once. The client turns every transport failure on send into `TransactionSubmissionFailed` with the `No status yet:` marker, and an `ERROR` answer with a result into the same variant, and one without a result into `MissingError`; the send classifier retries none of them. An HTTP 500 on send therefore ends as one send and an unknown outcome, which `a_transport_failure_after_the_record_returns_the_timeout_shape` pins with an exact send count. The combinator covers the variants the client does not produce on send, `TransactionSubmissionTimeout` and `JsonRpc`, and its own tests drive those. Across submissions there is no retry: no recovery path sends. `tx status`, `stellar_transaction_status`, the reconciliation pass before each value verb's gate, and `tx receipt clear` read the chain and write the wallet's records, and their tests count zero sends. The idempotent helpers `submit_transaction_idempotent`, `reconcile_receipt` and `submit_fee_bump_idempotent` have no caller in the shipped verbs and are not part of the recovery protocol.

The confirmation poll asks `getTransaction` every 2 s under the same deadline. No poll request and no sleep between polls runs past it. An answer that arrives after it is not accepted. The caller gets the timeout outcome and reconciles the hash with `tx status`. The retention-aware poll of the idempotent path makes one exception. At the deadline it runs one final `getHealth` retention check, bounded to 2 s, so it returns within the deadline plus 2 s.

With a submission recorder present, four exits return `submission.tx_timeout`: the deadline, an unexpected `getTransaction` status, a poll error that is not transient, and a send failure that is not a definitive refusal. Each may follow a send that reached the network, so each leaves the receipt, the pending row and the reservation standing, and the message says to settle the transaction by its hash and not to resubmit. Without a recorder, the three failure exits report their own errors. On testnet, a definitive refusal, `ERROR` with a transaction result, settles the submission at the send: the endpoint reported a validation error for the envelope, the wallet never sends those bytes again, and the receipt records the failure. What a testnet node's queue does with those bytes afterwards is not something the wallet observes; a copy relayed elsewhere that later becomes valid applies without being counted. The mainnet submit path takes the primary's negative answers as claims: a refusal at the send returns `submission.tx_timeout` with the receipt, the pending row and the reservation standing, so a relayed copy that applies later is still counted, and a `FAILED` confirmation releases only when the oracle reports the mainnet passphrase and then the same transaction `FAILED`, under the oracle's code; otherwise it returns `submission.tx_timeout` the same way.

A standalone identity check, the one a command or tool runs before its first read, runs under its own deadline. On CLI `pay`, `claim`, sponsored `accounts create`, and `pool init`, that deadline is `--timeout-seconds` from the check's start. On `trustline` and the MCP tools, it is the profile's `submit_timeout_seconds`. The submission that follows starts a fresh deadline. Inside a submission, the identity check shares the submission's deadline.

The wallet has no automatic failover: the secondary and oracle endpoints verify reads and never send a transaction. It has no circuit breaker either, because the CLI runs one command per process.

### Which accounts answer for which signatures

For a `Tx` envelope: the transaction's own source account and every distinct operation-level source account, because an operation-level source contributes its own authority and is signed for separately. For a `TxFeeBump` envelope: the fee source answers for the outer signatures and the inner transaction's sources for the inner ones. Muxed accounts resolve to the underlying G-account, which is where the signer set lives. The distinct set is fetched in a single `getLedgerEntries` call; an account absent from the ledger is `network.account_not_found`, refused before anything is sent.

One class of operation source is absent from the ledger by construction: an account that an earlier operation of the same transaction creates. It exists when the operation applies but not when the envelope is submitted, and its signer set at that point is exactly its own master key, which is the account id. Such an account is therefore not requested from the ledger and its candidate key is derived locally. The CAP-33 sponsored-creation sandwich is built this way, with the new account signing the `EndSponsoringFutureReserves` operation that names it as source. The derived key's signature must verify under the endpoint's network id.

### Per-signature verdict

Each `DecoratedSignature` carries a four-byte hint, the trailing four bytes of the signer's public key. The hint narrows the gathered signers to those whose key bytes `28..32` match it; the signature must then verify against one of those candidates under the payload rebuilt for the endpoint's network id.

- verifies under the endpoint's network id: accepted
- fails under the endpoint network but verifies under mainnet: `network.envelope_signed_for_mainnet`
- verifies under neither: `network.envelope_signature_unverifiable`
- a signature set carries no decorated signatures at all: `network.envelope_unsigned`, refused before the round trip. The sets are checked separately, so a fee-bump with a signed outer and an unsigned inner is refused here rather than on chain

Every signature must pass, and each signature set must have at least one. Hash-x and pre-auth-tx signers contribute no ed25519 key, so a signature only such a signer could account for has no candidate to match against and is refused rather than waved through. The posture is closed by construction: an envelope carrying a signature this layer cannot account for is not submitted.

## Policy V1 evaluator

`PolicyEngineV1` (`crates/stellar-agent-core/src/policy/v1/mod.rs`) is the signature-verified typed-criteria engine, active when `profile.policy.engine = V1` (the default for newly-minted profiles). The alternative, `NoopPolicyEngine` (`policy/mod.rs`), is selected by `engine = "noop"`. It supplies one policy boundary alongside entry, signing, and submit checks. Testnet allows all tools. Mainnet read-only (`destructive_hint = false`) allows. Mainnet destructive returns `Err(PolicyError::NotImplemented)`, surfaced as `policy.engine_required`.

### First-match default-deny

`PolicyEngineV1` wraps one `PolicyDocument` whose owner ed25519 signature is verified at load. `evaluate` resolves the rules whose `ScopeId` matches `(profile_name, project_id)`, then walks them in declaration order. The first rule whose `RuleMatch` (tool name + chain-id filter) matches is selected; its criteria run in order; the first criterion returning `Ok(Some(reason))` produces `Decision::Deny`. If every criterion passes, the rule's `decision` is returned. If no rule matches, the engine returns `Decision::Deny(DenyReason::NoMatchingRule)`, default-deny.

### Criteria catalog

Each criterion is a `Box<dyn Criterion>` (`Send + Sync`) with a snake_case kind tag. The catalog (`policy/v1/criteria/mod.rs`):

| Kind tag | Purpose |
|----------|---------|
| `asset_allowlist` | Pinned `native`, classic `CODE:G...`, or contract `C...` identities; other valued legs refuse with `policy.deny.asset_not_allowlisted` |
| `per_tx_cap` | Per-transaction value cap |
| `per_period_cap` | Sliding-window per-period value cap |
| `rate_limit` | Sliding-window call-rate limit |
| `counterparty_allowlist` | Destination allowlist (`G_ACCOUNT` / `C_ACCOUNT` / `KNOWN_ISSUER` / `HOME_DOMAIN`; `SEP10_IDENTITY` and `ONE_TIME_ADDRESS` are reserved, not evaluated); `KNOWN_ISSUER` checks debit legs only unless the criterion's `gate_inflows = true` opt-in extends it to inflow legs too |
| `minimum_reserve` | Minimum-reserve guard (classic-account tools only, see below) |
| `inner_invocation_count_cap` | Multicall inner-count cap |
| `bundle_aggregate_cap` | Multicall aggregate-value cap (implicitly enforces the Generic-rejection check below, on any rule that carries it) |
| `restrict_bundle_to_recognised_kinds` | Reject generic / unrecognised inner kinds |
| `bundle_per_period_cap` | Per-period cap across a bundle (implicitly enforces the Generic-rejection check above, on any rule that carries it) |
| `bundle_per_tx_cap` | Per-tx cap applied to each inner (implicitly enforces the Generic-rejection check above, on any rule that carries it) |
| `bundle_rate_limit` | Rate limit across a bundle |
| `quorum_satisfied` | Smart-account signer-group quorum |
| `home_domain_resolved` | Counterparty `stellar.toml` resolved/cached (contract counterparties only, see below) |
| `sep10_session_active` | Active SEP-10 session for the account |
| `sep45_session_active` | Active SEP-45 session for the contract |

The bundle gate decomposes the encoded declared calls. Only a typed transfer from the wallet has a sized value effect. Every other call is opaque to matched per-call value criteria.

Multicall bundles also carry a hard floor independent of policy: `evaluate_bundle` denies any bundle with more than 50 inners (`DEFAULT_INNER_INVOCATION_COUNT_CAP`) before rule resolution. Policy authors may configure a lower cap but cannot raise it above the floor.

The allowlist, single-call caps, bundle caps, and period accounting share
network-aware asset identity. A classic asset and its SAC count together;
a SAC derived on another network does not match the classic identity.
Claim legs have no asset and are not covered by the allowlist.

Every build requires `mainnet.approval_credentials` with 1 to 16 credentials
in any policy with a `[mainnet]` table; the loader, the minimum evaluator, the
profile-body validator, and the canonicalizer share one parser, and the
canonical form sorts the entries by raw credential ID.
A `mainnet-write` build enforces the minimum policy when a mainnet profile
loads or signs a v2 body with `[mainnet]`. It requires a positive sequence,
a profile-specific scope, at least one rule, exact mainnet chain and tool
matches, and no opaque signing or home-domain criteria.
Approval rules require an explicit TTL of at most 3600 seconds.

Non-deny value-out rules require one asset allowlist, a destination allowlist
with `G_ACCOUNT` or `C_ACCOUNT`, per-transaction and per-period caps covering
every allowed asset, and a rate limit. Trustline rules require one asset
allowlist; claim rules must not carry one. Read-only rules need no value caps.
Allow `stellar_balances` and `stellar_transaction_status` so MCP can reconcile
a timed-out submission. Message-signing tools are outside the read-only set.

The signed mainnet table requires a classic per-operation fee cap. Optional
cross-check thresholds are positive i128 values with pinned keys; the native
threshold respects `MINIMUM_FLOOR`. Native SAC aliases and duplicate classic/SAC
keys refuse. The optional authorization TTL is 1 to 120 seconds.
`ThresholdSet::from_profile_and_signed` and `check_classic_fee_cap_signed`
combine a signed value with the profile's: the effective threshold and fee cap
are the per-asset minimum, and a profile value above the signed one emits a
warning. Admitted classic callers use effective signed/profile values, and
the resolver independently reevaluates them. See the normative
[policy schema](../profiles.md#mainnet-policy-body),
[minimum](../profiles.md#enabled-policy-minimum), and
[fee and threshold rules](../profiles.md#thresholds-and-fees).

The policy criteria have no memo requirement. `stellar_pay` and `pay` refuse a
payment without a memo to an account whose `config.memo_required` data entry
is `1` (SEP-29). For a destination that needs a memo without that entry, such
as an exchange deposit account, the operator supplies the memo with every
payment; the policy cannot refuse its absence.

### Persisted window-state store

`per_period_cap`, `rate_limit`, `bundle_per_period_cap`, and `bundle_rate_limit` are stateful: their evaluation reads accumulated history from `PolicyStateStore` (`policy/v1/criteria/state_store.rs`), an in-memory `Mutex<HashMap<StateKey, VecDeque<StateEntry>>>` of timestamp, amount, and pending flag. A pending entry counts whatever its age; a confirmed entry is dated from the close time of the ledger that applied it and leaves the window from there. In-memory state alone would reset to empty on every process start (and every CLI invocation is its own process), so a durable backing store is required for these criteria to actually accumulate across calls.

`PersistedWindowStore` is one file per profile at `<canonical_data_root>/policy/<profile>.window`. It lives in `stellar-agent-network::policy_state`, not `stellar-agent-core`; see the crate-placement rationale in that module's rustdoc. The store needs the keyring primitives that live in `stellar-agent-network`, and `stellar-agent-core` must not depend on `stellar-agent-network`.

- **Format**: `[32-byte HMAC-SHA256 tag] || [canonical JSON body]`, an embedded-tag layout mirroring the counterparty `stellar.toml` cache's v2 format. `i128` amounts serialise as decimal strings, never a bare JSON number.
- **Versions**: each snapshot's version follows from its content. Version 3 is the compact form. Version 4 adds the mainnet authorization ledger, the authorization records and the holds of the open ones, and is written while that history is non-empty, settled records included, until pruning empties it. The reader accepts versions 1 to 4 for the current snapshot and versions 3 and 4 for a prepared successor, on both sides of the commit point. A legacy current snapshot keeps its version while a successor is prepared. Compatibility is kept for compact version 3 files with no authorization history; a prepared file from another build is not part of that promise.
- **Authorization ledger**: a hold counts against the window from the mint until its authorization is consumed, invalidated, or expires, and lives outside the bucket records, so hydration, reconciliation, confirmation, and release never see it. Expiry is measured on the store's own clock, and a transaction sweeps expired authorizations under the lock before it counts. A consumed transaction authorization's holds become the submission's ordinary pending records; a consumed Soroban intent's become confirmed authorized spend. Settled history is pruned after the retention window; an open record never is.
- **Key**: the profile's `policy_window_state_key_id` keyring coordinate (`stellar-agent-policy-window-<profile>` by convention), lazily minted on first write.
- **Lock**: `WindowStoreLock`, an OFD-advisory exclusive flock at `<store-file>.lock`, structurally identical to the counterparty cache's `CacheLock`, serialises every read-modify-write (record, reset, resign, authorization transitions) across concurrent MCP-server and CLI processes. It lives in `stellar-agent-core::policy::state_lock`, and the policy pin at `(<window service>, <window account>-policy-pin)` is read, written, and compared only under it.
- **Admission**: `record_pending` (the write that reserves a submission's spend, immediately before the send) re-applies the governing criterion's comparison under the lock it already holds, against the file it has just read and verified. Each entry carries the limit that governs its bucket (`WindowLimit::Amount { asset, window, max_stroops }` or `WindowLimit::Count { window, max_calls }`), derived from the same fields the criterion's `evaluate` compares against and never persisted. A batch any bucket can no longer admit is refused as `WindowStoreError::PolicyDenied`, carrying the `DenyReason` the criterion produces for that condition, and nothing is written; entries of one batch on one key accumulate against each other. A same-key pending record dated more than 30 seconds past the entry's own clock fails the gate's query closed, and admission refuses it as `policy.deny.evaluation_error`; the diagnostic names the host-clock offset. Confirmed ledger close times count toward the cap even when they are ahead of the host clock. The recorder maps that refusal to `WalletError::PolicyDenied`, which reports the gate's own `policy.deny.*` code at every surface, and unwinds the receipt, the pending audit row and the held sequence exactly as any other pre-send refusal does. The gate reads the window before the transaction is built and signed, so without this recheck two callers on one profile could each pass the gate against the same state and both spend against it.
- **Atomic write**: temp file + `sync_data` + rename + parent-directory fsync, the same discipline as the audit log's rotation `write_sidecar_atomic`.
- **Retention**: confirmed entries older than the largest supported window (`1w` = 604,800s) are pruned on every write. A pending entry is kept until it settles, whatever its age.
- **Failure posture**: an unreadable, tampered (HMAC mismatch), or unparseable store file is fail closed. `PolicyEngineV1`'s construction site hydrates the store BEFORE the engine is usable. A hydration failure refuses engine construction (`policy.engine_unavailable` / `BuildRegistryError::PolicyEngineError`) rather than silently starting with an empty store. Recovery: `stellar-agent profile reset-window-state <name> --reason <reason>`, which re-initialises the file to empty and audits the reset (`PolicyWindowStateReset`). On every chain, an authenticated file of a newer format version refuses reads with `UnsupportedVersion` and the reset with `profile.reset_window_state_newer_version`; use the build that wrote it.
- **Mainnet rule**: in a build with mainnet writes, a mainnet profile's store that cannot be verified refuses every read and write with `policy.window_state_unverifiable`, naming the defect: a missing file with a committed generation, a missing or unusable key beside an existing file, a malformed file, an HMAC mismatch, or a generation mismatch. No write mints a key or a file over such a state. A missing file with no committed generation is a genuine first run. The reset above is the remedy, and its audit row's reason names the defect it recovers from. A verifiable store that still holds an effective open mainnet authorization refuses the reset with `profile.reset_window_state_open_authorizations` and changes nothing; expired authorizations are released in memory, and nothing is written before the audit row. Testnet profiles and builds without mainnet writes keep the recovery above.
- **Rotation**: `stellar-agent profile rotate-policy-state-key <name>` first verifies an existing store file's tag under the old key. It refuses the rotation, changing nothing, when the tag does not verify or the file exists without a minted old key. It then mints a fresh key and re-signs the store file's existing body under it. The re-sign itself needs no old key. This is the same "recompute the tag over the unchanged body" shape as `rotate-audit-key`'s chain-root sidecar re-sign, so accumulated history survives rotation.

Stateful criteria derive window entries from the same `ValueEffects` used by evaluation and audit. Network submissions reserve those entries before sending and settle them from the ledger result. A reservation's id is the envelope hash, so the window refuses a second reservation for bytes it already holds, pending or confirmed: the recorder asks before it writes the pending row, which keeps a resend after a lost receipt from writing any row, and the reservation write refuses again under the file lock. Both map to `submission.tx_already_submitted`. The refusal exists only where the submission takes a reservation, so only under a policy with a stateful criterion. A release drops the pending records of a reservation and keeps its confirmed ones. A release on chain evidence (a consumed sequence, or an observed close time past a nonzero time bound, each confirmed by a fresh `NOT_FOUND`) records `release_code` on the receipt, restores a missing receipt first, and reports the submission as settled, so the caller writes a `value_action_failed` row under the evidence's code; a later status run writes it from the receipt when that append failed. The receipt file is unauthenticated, so its `release_code` is the label of that row and never evidence: a reservation whose receipt claims a release is settled on the chain like any other. On a mainnet profile the primary's `FAILED` and `NOT_FOUND` release nothing: the oracle's answer settles them, and its `NOT_FOUND` runs the evidence rule on the oracle's retention floor, chain time and account sequence. A pass checks once that the oracle reports the mainnet passphrase before any of its answers count; an oracle that reports another network or whose identity cannot be read settles nothing in that pass. A reservation recorded against submission ledger 0 never releases on `NOT_FOUND`. Confirmed spend is dated from the later of the applying ledger's close time and the reservation's own time. MPP and testnet x402 authorizers use `record_authorized_window_state`, which applies the reservation comparison under the file lock before signing or signed RPC re-simulation. Refusal records no entries, withholds the credential, and carries the governing policy denial to the caller. Admitted authorization spend consumes window headroom even if subsequent signing or delivery fails. The x402 tools validate the payment requirements in full before the dispatch gate, so invalid requirements consume no headroom. On testnet, admission precedes the endpoint identity check inside `create_payment`, so an identity refusal keeps the admitted spend. Mainnet x402 payments use authorization records instead. Mainnet payment minting follows endpoint, simulation, witness, and health checks. The payment intent is consumed immediately before signed re-simulation. `record_confirmed_window_state` remains an unconditional post-confirmation recorder: spend already applied on-chain must be counted, and a persistence failure is logged.

### Authorization records and recovery

Minting allocates an authorization identity and reservation under the state lock.
The proof binding includes that identity and reservation. A hold reduces
available window headroom until consumption, invalidation, or expiry.
Transaction consumption turns its holds into submission pending records.
Authorization records and submission holds are distinct.

Consumption rereads the policy pin under the lock and checks profile and chain.
A second consume refuses without rewriting the store. Invalidation releases
holds without reopening authority. An invalidation returning false can still
commit an expiry sweep. Settled history remains for the retention window;
open records are not pruned. An approval nonce remains single-use within retention.

`resolve_message_sign` checks the consumer, verified policy and enablement,
intent network, approval binding and lifetime, and audit readiness before
minting. The Message record binds the home domain, web-auth domain, server key,
challenge digest, ephemeral key, policy, enablement, and approval. It reserves
no value. The Message authorization is consumed before the SEP-10 signature.
`consume_message_sign` consumes the authorization and returns
`MessageUseReceipt`. The receipt carries the bound facts and owns the audit
lease.

The authenticated payment continues its used Message record with one Soroban
intent. The intent permits one payload-release child under the same approval.
The payment intent is consumed before the signed simulation. The submit
authorization is consumed before payload release.

A minted Message record is open. Successful consumption makes it used. Refused
consumption attempts invalidation. An already settled record stays settled. If
cleanup fails, the record remains open until expiry. The cleanup warning retains
the primary refusal.

The authorized SEP-10 completion refuses an unreadable clock and verifies its own
signature before submission. Its precondition labels for these refusals are
`clock_unavailable` and `signature_invalid`. The `Debug` output of
`MessageUseReceipt` shows only its domain, identifier, and home domain.
`MainnetIdentityInputs` shows only the profile, and `PreparedEphemeralAuth`
shows only its account and home domain. The verified session redacts its JWT to
the first and last eight characters.

A live consumed or receipt-held approval reports `policy.approval_consumed`.
Consumption followed by pre-send recording failure can leave no approval
tombstone. Reuse can then report `network.mainnet_authorization_refused`.
`submission.record_unavailable` retains its own meaning. Existing ownership of
signed bytes refuses with `submission.tx_already_submitted`.
Authorization operations share a mainnet clock. Clock failure reports
`wallet.clock_error`. A witness bound to another envelope or intent reports
`network.witness_unavailable` with `WitnessUnavailableReason::EnvelopeMismatch { part }`.
The message contains "cross-check refused: the transaction's {part} does not
match the observations the witness compares".
In `stellar_x402_create_payment` it follows a "payment withheld" prefix that
names the withholding stage.
The `{part}` is `source`, `sequence`, `operation`, `memo`, `value`, `envelope`,
or `authorization`. The wallet refuses signing and sending.
The message tells the operator to build the action again.

Reset refuses effective open authorizations with
`profile.reset_window_state_open_authorizations`. Enabled-mainnet state that
cannot be verified uses `policy.window_state_unverifiable`. Stop the MCP server,
inspect the defect, and use `profile reset-window-state <NAME> --reason <REASON>`
with `--owner-secret-env VAR` holding the pinned owner's seed on an enabled
installation, in every build. The check reads the nonce and pin under the scoped
store lock. A newer authenticated format refuses reset with
`profile.reset_window_state_newer_version`; use a build that understands it.
Reset audits the defect before replacement; expiry release remains in memory
until that audit step succeeds.

### Operator authorization logs

Each reported authorization refusal emits one warn-level entry with `path`,
`precondition`, and message `mainnet authorization refused`. `precondition`
uses stable snake-case labels from `MainnetPrecondition`. The labels identify
failed checks, not separate public wire codes. The public code remains
`network.mainnet_authorization_refused`. Context entry refusal instead logs
`mainnet write context refused`. The MCP identity mapper of the authenticated
x402 tool does not log that refusal again. A failed cleanup after a refused
Message consumption emits `mainnet authorization cleanup failed`. It is separate
from the primary refusal. Every other identity failure of the authenticated tool
logs one warn-level `x402_authenticated_payment: mainnet identity gate aborted before payment`
entry with `error_code` and `home_domain`. A failed SEP-10 exchange also logs
`x402-identity: SEP-10 auth failed` with the web-auth authority and home domain.
Message authorization refusals log the `path` `resolve_message_sign`,
`consume_message_sign`, `prepare_ephemeral_auth`, or
`complete_ephemeral_auth_authorized`. Their message-specific preconditions are
`message_use_mismatch` and `message_client_account`, and a reused approval
nonce logs `approval_nonce_reused`. A failed invalidation after a payment or
release refusal logs `authorization cleanup refused; primary failure retained`
with the invalidation stage, a `settled` flag, and the error code. The tool
still returns its primary refusal.

`STELLAR_AGENT_LOG` takes precedence over `RUST_LOG`. The default level is
`info`, and output goes to stderr. Report refusal to the operator without
switching networks. A retry needs fresh preparation and approval. Unknown
submission outcomes require reconciliation instead.

### Injected views fail closed when absent

Several criteria need state the core crate cannot fetch itself (account reserves, identity, counterparty cache, SEP-10/SEP-45 sessions, quorum). To avoid a circular dependency on the network and smart-account crates, these arrive as optional trait objects on `EvalContext` (`AccountReservesView`, `AccountIdentityView`, `CounterpartyCacheView`, `Sep10SessionView`, `Sep45SessionView`, `QuorumView`), populated by adapters in `stellar-agent-mcp` at the dispatch site. When a configured criterion's required view is `None`, the criterion returns `Err(PolicyError::CriterionEvaluationFailed)` rather than silently passing: `minimum_reserve` with no `account_view`, `sep10_session_active` with no session view, and `home_domain_resolved` with no counterparty cache all fail closed. `AccountIdentityView` is deliberately a separate trait with no default methods so a missing `home_domain` cannot become a silent allow.

### HOME_DOMAIN allowlist verification

`HOME_DOMAIN` matching in `counterparty_allowlist` requires the domain to be verified through the counterparty cache, not merely asserted. The destination's self-asserted on-chain `home_domain` must be resolved in the cache, AND the cached `stellar.toml`'s `ACCOUNTS` list must contain the account (`CounterpartyCacheView::is_account_listed`, default `false`, fail-closed). An absent or expired domain binding, or one that does not list the account, denies. Operators populate the cache with `stellar-agent counterparty warm-up` / `counterparty refresh <domain>`. The deny detail distinguishes an unverified domain (no live entry in the cache) from an unlisted account (resolved, but the account is absent from `ACCOUNTS`).

A `HOME_DOMAIN` binding is evidence for one hour from its fetch. An entry
whose fetch time lies more than five minutes in the future counts as expired.
Expired entries satisfy neither the `HOME_DOMAIN` kind of
`counterparty_allowlist` nor `home_domain_resolved`. A policy that relies on
the `HOME_DOMAIN` kind needs `counterparty warm-up` on a schedule shorter than
one hour. Warm-up refreshes only the domains named in `counterparty_allowlist`
criteria that contain `HOME_DOMAIN`. A policy that uses `home_domain_resolved`
keeps each domain it relies on live with a scheduled
`stellar-agent counterparty refresh <domain>` per domain.

### `minimum_reserve` is inapplicable to smart-account verbs

`account_view` is populated only for classic-account tools (`stellar_pay`, `stellar_create_account`, `stellar_claim`) whose acting account is a plain Stellar account with a classic `AccountEntry`. The smart-account verbs (MCP `stellar_dex_trade` / `stellar_defindex_vault_deposit` / `stellar_defindex_vault_withdraw`, and the corresponding CLI `trade` / `vault` commands) act through a deployed smart-account contract (C-strkey). A contract has no classic `AccountEntry`, so there is no reserve state to fetch and `account_view` stays `None` on these tools by design. A rule that configures `minimum_reserve` on one of them fails closed on every call via the criterion's own `CriterionEvaluationFailed` path. The same applies to `identity_view` on these tools: the DeFi counterparty (pool / router / vault) is a contract, so a configured identity-class criterion (`home_domain_resolved`) is equally unanswerable and fails closed. Operators should not configure `minimum_reserve` or identity-class criteria on rules matching the smart-account verbs.

### Fail-closed registry construction

The policy loader (`policy/v1/loader.rs`) is fail closed at parse time. An unknown criterion kind, a malformed criterion definition, an empty `match.tool` or `match.chain`, or any item the dispatcher cannot fully type returns `PolicyError::PolicyFileParseFailed`. The document does not load and the engine does not start with a partially-understood ruleset. Tool-registry construction is likewise fatal on duplicate registrations or an unknown engine variant, preventing a `destructive_hint = false` shadow of a destructive tool.

`profile reset-window-state` writes its `policy_window_state_reset` audit row,
with the wiped accrual, before it mints a key, advances the generation or
replaces the store. A reset whose row cannot be written does not happen.
With an owner seed, the row records the pinned owner's signature over the
profile, chain, store SHA-256, generation pair, bounded reason and request id.
Owner-required, owner-mismatch and pin refusals write no row and change no state.
The [CLI reference](../cli-reference/profile-and-governance.md#reset-window-state-name---reason-reason)
describes the row, the refusals, the failure windows and the recovery.

## MPP sponsored authorization

The testnet MPP path adds a one-shot authorization lifecycle on top of the
existing value policy, approval, signer, and audit substrates. The complete
module map and state graph live in [MPP internals](mpp.md).

The versioned authorization fingerprint length-prefixes profile, network
passphrase digest, payer, normalized request-context digest, exact challenge
digest, method, intent, sponsored mode, amount, token, recipient, and expiry.
Replay identity separately hashes the payer, request-context digest, and exact
challenge digest with the `stellar-agent-mpp-challenge:v1\0` domain. Effective
expiry does not affect identity. The store reuses a live unclaimed match and
retains consumed matches as replay markers.
The MPP approval additionally binds the prepared-artifact hash and every
operator-visible term. Attestation expiry is capped by both five minutes and the
challenge lifetime.

The per-profile state file is authenticated by a dedicated keyring HMAC key and
serialized under a sibling-file cross-process lock. Reads reject symlinks,
non-regular/oversized files, invalid HMAC, invalid records, reconstructed-XDR
mismatch, and duplicate authorization IDs, fingerprints, or approval nonces.
Writes use a bounded temporary regular file,
flush, atomic rename, and parent sync. Credentials, raw receipts, and exact
transaction hashes are never persisted.

The MPP committed and intent counters sit beside the HMAC key in the keyring.
The state lock covers preparation through commit. Its pathname is checked
against the held regular file at acquisition, before atomic replacement, and
immediately before each counter write. Unix compares device and inode.
Windows denies delete sharing for the held handle and checks pathname metadata
and creation time through an opened path. Missing or changed identity refuses.

Counter writes compare trusted values under that verified lock. Reservation
requires both counters to hold the prepared values and strictly exceeds each
valid one. Commit re-reads both counters, requires its exact expected committed
value and reserved intent, and verifies the authenticated publication. One
guarded setter performs every counter write and checks lock identity again
after the keyring write; a changed path refuses the update as not confirmed and
is logged at warn level. Equal competing targets refuse. Outside the limit
below, a losing writer preserves the winning snapshot and counters.
Failures before publication in ordinary mutations preserve acknowledged records
and reserve their generation permanently. Reads reject snapshots below the
committed high-water mark before record lookup. Reads complete higher snapshots only with an exact
matching intent through the same guarded commit checks. A missing file is
empty only at committed generation zero.

On Unix, the current limit is three windows after the final lock identity
check. Each requires an actor with write access to the state directory who
replaces the lock path with timing inside the window. Windows denies deletion
and renaming while the lock handle lives, so none of the windows exists there.

- Between the check before a counter write and the keyring write, a stale
  writer can lower a counter or overwrite a newer one. A restored older snapshot
  then passes reads, and the replay records written after it are lost.
- Between the check before the atomic replacement and the rename, a stale
  writer's snapshot can overwrite a newer committed one. Reads refuse it as
  rolled back, a reset carries it without a stale flag, and the newer writer's
  replay records are lost.
- Between the check before a state-key rotation, in a discarding reset or in
  the key mint on first open, and the rotation, a stale writer can replace the
  key. The newer writer's snapshot survives as bytes but no longer
  authenticates. Every open refuses, only a discarding reset recovers, and the
  newer writer's replay records are lost.

When both anchors are proven absent (`NoEntry`), a verified version 1 file is
adopted once under the lock, with a mandatory `mpp_state_adopted` row. It becomes
version 2 at generation one with its records intact. An adoption interrupted
at intent one before publication resumes at generation two. If that attempt
stops before publication, opening refuses because intent two cannot be told
apart from anchor removal. Move the state file out of the MPP state directory
and run the reset to discard. A version 2 file whose generation equals the
intent under an absent committed counter completes its publication on open. Any other absent counter on that format, or any other
intent beside a version 1 file, refuses. Keyring access errors cannot authorize
adoption.

`profile reset-mpp-state <NAME> --acknowledge --reason <REASON>` recovers
refused state. Under the lock, it reads the state first: a keyring access
error, an I/O error, or a state path that is not a regular file refuses with
nothing changed. It then audits the profile, discarded generation, carried
generation, stale flag, and reason. When the state key passes the owner check
and authenticates the file, reset keeps every record and the prune watermark.
Unclaimed records close as `expired_unresolved`; other statuses survive. It
publishes above the maximum trusted committed counter, intent, and snapshot
generation, keeping the key. Older snapshots refuse, and existing handles read
the carried history. A carry needs a valid committed counter and an absent or
valid intent; an authenticated file beside an absent or malformed committed
counter, or a malformed intent, refuses before the audit row. Only a discarding
reset, after the operator moves the state file out of the MPP state directory,
recovers that state.

The carried snapshot is the one on disk, so a same-user rollback of the state
file before a reset loses the records written after that snapshot. No write
leaves the file more than one generation below the committed counter; a larger
gap marks the carry as stale in the result and the audit row.

When no snapshot authenticates, reset rotates the key, retains every valid
counter, and uses guarded atomic replacement to publish an empty snapshot
strictly above their maximum, then syncs the directory. An absent or malformed
counter does not block that path:
the guarded writes replace it while it holds what the reset observed, and the
fresh key leaves no earlier snapshot that authenticates. Every replay marker is
discarded on that path; a settled charge loses its settled status. The result
reports `carried_records`, `carried_generation`, and `stale_carry`, with a null
discarded generation for an absent or malformed committed counter. An
inaccessible counter refuses before audit or mutation, and no counter-repair
operation exists. Audit failures refuse before mutation; the request row
survives a later storage failure. A partial reset has these recovery cases:

- After key rotation and before publication, the reset leaves no snapshot that
  authenticates under the new key. Opening refuses; rerun the reset to discard.
- After publication under a malformed committed counter, opening refuses with
  the anchor error and reset refuses the carry. Move the state file out of the
  MPP state directory and rerun the reset to discard.
- After publication under an absent or valid committed counter, opening
  completes the commit when the intent names the authenticated snapshot.

Profile handles check their cached key against the keyring on reads and
mutations.

Prune retains the largest expiry removed as `pruned_through`. Without an
identity match, a challenge expiring at or below that watermark refuses with
`mpp.challenge_expired`. This protects clock regression after pruning. A
discarding reset and a stale carry raise the watermark to the reset time plus
the challenge lifetime cap, which covers every challenge whose record the reset
lost. A repeated prepare of a challenge whose unclaimed record expired returns
`mpp.challenge_expired`.

Keyring compromise is outside the rollback boundary; a filesystem-backed
keyring needs protection independent of the MPP state-file snapshots.

Commit claims durable state before policy accounting or key access. Policy usage
is recorded before signing and is never refunded from an absent receipt. The
signer handle loads the secret only at the actual sign call. Mandatory signed
re-simulation precedes the authorization audit delivery gate. Any ambiguous
post-claim path becomes `indeterminate` or `authorized_withheld` and cannot sign
again. The configured RPC therefore observes signed authorization and is part of
the trust boundary. A failure in the sponsored commit writes a withheld row whose
`failure_stage` names the side of the send. `pre_signing` is before the sign
call (`key_access_began = false`). `signing` runs from the sign call to just
before the send, and `resimulation` is at or after it. `resimulation` means the
signed entry reached, or may have reached, the configured RPC.

Mainnet refusal occurs at every public MPP adapter and again in the sponsored
library boundary before RPC, state creation, keyring access, or signing. MPP is
also absent from the toolset capability router.

## Smart-account auth digest

The auth digest binds a Soroban signing payload to the context-rule ids that govern it. The primitive is `compute_auth_digest` in `crates/stellar-agent-core/src/smart_account/auth_digest.rs`.

### Computation

```text
auth_digest = SHA-256( signature_payload || context_rule_ids_xdr )
```

`signature_payload` is the 32-byte hash produced by the Soroban host (`HashIdPreimageSorobanAuthorization`). `context_rule_ids_xdr` is the XDR serialisation of `AuthPayload::context_rule_ids`: an `ScVal::Vec(Some(ScVec([ScVal::U32(...)])))`. It contains a 4-byte `SCV_VEC` discriminant (`0x00000010`), a 4-byte `Some` marker (`0x00000001`), a 4-byte big-endian element count, then per element a 4-byte `SCV_U32` discriminant (`0x00000003`) and the 4-byte big-endian `u32` value. The result is the 32-byte `AuthDigest`, rendered as 64 lowercase hex chars by `Display`.

### Canonical rule-id encoding

Callers MUST produce `context_rule_ids_xdr` via `encode_context_rule_ids`, which emits exactly the bytes the on-chain contract hashes. Hand-assembling a length-prefixed `u32::to_be_bytes` sequence (or any other layout) computes a digest that passes `compute_auth_digest` off-chain but is rejected on-chain. The layout matches the OpenZeppelin `stellar-accounts` v0.7.2 `__check_auth` computation.

### Downgrade-attack closure and on-chain failure

Signing the digest rather than the raw `signature_payload` closes the rule-id downgrade attack by a malicious transaction sponsor. Because the rule ids are inside the hashed preimage, swapping them changes the digest and invalidates the signature. A signer that signs the raw payload, or that builds a non-canonical `context_rule_ids_xdr`, produces a signature the contract rejects during `__check_auth`. The failure is on-chain at submission, not at off-chain digest computation. The silent off-chain success that breaks on submit is exactly what this primitive exists to prevent. The function logs only input byte-lengths and the one-way output digest at debug level; the raw payload and rule-id XDR are never logged.

### Signed invocation tree

The digest covers the invocation tree inside `signature_payload`. Address credentials are not bound to a transaction, so whoever holds a signed entry can submit it in a transaction of its own until the signature expiration ledger. The rule ids do not narrow the tree either: under an OpenZeppelin `Default` rule, such as the bootstrap rule 0 the DeFi adapters sign under, `__check_auth` accepts any context. The tree the wallet signs therefore comes from the wallet, not from the RPC.

`submit_signed_invoke` (`crates/stellar-agent-smart-account/src/submit.rs`) requires the simulated root invocation of the wallet's entry to equal the caller's host function in contract, function name, and every argument. The sub-invocations under it must match the caller's `DeclaredSubInvocations`:

- `None`, the default: no sub-invocations. A wallet entrypoint authorizes its own frame, and the contracts it calls are authorized through invoker-contract auth without adding a node to the wallet's tree.
- `TokenTransfers`: each sub-invocation is a `transfer(from, to, amount)` on a declared token, `from` is the wallet, the recipient matches when the declaration sets one, and the amounts counted against each declared entry sum to at most its bound. The Soroswap adapter declares the input token with an open recipient (the router picks the pair) and the trade's input amount. A DeFindex deposit declares each vault asset with the vault as recipient and its desired amount.
- `Calls`: the sub-invocations equal declared calls in declared order, each used at most once. The multicall submit declares its encoded bundle calls and decomposes those same calls for valuation. The signed leaves form an ordered subset of the declaration.

Every accepted sub-invocation is a leaf. The wallet then signs its own root with the accepted subtree. Any other tree refuses with `simulation.divergence.auth_contexts` before a signing primitive runs; the message names the differing part or the index of the refused sub-invocation and the reason, never a value. The divergence check of the auth-entry builder then compares one fingerprint per node of the simulated tree (`node:` plus the SHA-256 of the node's function XDR and its child count) with one per node of the signed tree, as a second check behind those two.

Public smart-account signing entry points consume `CheckedSigningRules`, obtained through `SignersManager::check_signing_rules`. The proof binds the account, network and rule set after the verifier pin and status checks. Quorum collection passes that checked set to every group completion. `rules verify-pins` compares hashes without enforcing status. A pin is a `WasmHashPin`, the full 32-byte code hash, serialized as 64 lowercase hex characters; every pin comparison, including the resolved hash of an external reference, the migration repoint, the refresh and signer-add deduplication and the policy-removal match, compares all 32 bytes. The guarantee covers code identity within the rule and policy-set scope of the pin check; it inherits the integrity of the audit log the pins are read from. The `SaContextRuleCreatedV2` and `SaContextRulePinsUpdatedV2` rows carry full pins. An older `SaContextRuleCreated` or `SaContextRulePinsUpdated` row with hashes holds eight-byte prefixes: the reader returns it as an incomplete record, its canonical bytes and chain hash unchanged, and the newest row across both formats is the record. An incomplete record refuses with `sa.wasm_pin_incomplete` before any signing primitive runs; no override flag applies and no byte is inferred from the chain or the allowlist.

The timelock path signs `schedule`, `execute`, and `cancel` with the operator's classic key. That Address authorization has no context rule at all, so the path signs only the timelock call it built, with no sub-invocations. `submit_timelock_invoke_with_g_key_auth` (`crates/stellar-agent-smart-account/src/timelock_submit.rs`) checks every Address entry of the simulation before it signs any: each must name the operator's key and have the call as its root with no sub-invocations. A root that differs or carries sub-invocations returns the same `simulation.divergence.auth_contexts` refusal, and no entry is signed. The public `schedule_upgrade`, `execute`, and `cancel` operations map that refusal, like every other submission failure except the mainnet refusal (and, for `execute`, an unresolved submission), to `sa.timelock_schedule_failed`, `sa.timelock_execute_failed`, and `sa.timelock_cancel_failed`; the refusal text is kept in the reason.

## Redaction discipline

Audit and policy wire output never carry secrets or raw argument maps:

- The audit log records raw argument key names only (`arg_keys`); raw argument values are never logged at any level. Typed value events retain each leg's amount, asset, and redacted destination.
- Strkeys (`G` / `C` / `T` / `M` / `P`) in `decision_reason` are redacted to first-5-last-5 (for example `GABC...WXYZ`).
- Transaction hashes are redacted to first-8-last-8.
- The `envelope_hash` is recorded unredacted because it is a SHA-256 digest with no user data.

On the classic and x402 paths, server-derived text that the wallet does not validate to a fixed shape passes through `quote_server_text` or `escape_server_text`. Values validated to a fixed shape (an LDH endpoint host, strkeys, the network, amounts) are printed as validated. The scrub applies before the text reaches an error, a tool result, or a log line, and covers RPC errors, the simulation `error`, SEP-10 and stellar.toml answers, and x402 header fields. Each URL keeps its host and port, and each whitespace run becomes one space. Other control characters and non-ASCII characters become `\u{...}` escapes, and the text is cut at 200 characters. An error quotes the text. A SEP-10 answer with a non-2xx status reports the method and the status; its body is not read. A stellar.toml syntax error reports its line and column, not the line itself.

Smart-account audit constructors require their strkey and hash fields to be pre-redacted at the call site (first-5-last-5 for addresses, first-8-last-8 for hashes) before the entry is built; the constructors do not redact internally. Policy `DenyReason` strkey/contract-id fields are redacted to first-5-last-5 at the MCP boundary, and the `_commit` verifier collapses `Expired` / `NotFound` / `AlreadyAttested` into the single wire code `policy.approval_required` so the caller cannot distinguish those internal states.
