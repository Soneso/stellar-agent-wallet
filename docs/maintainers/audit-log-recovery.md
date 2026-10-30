# Audit-log recovery

Operator guidance for the states the audit log can be found in that block a writer from opening, or a value-moving verb from signing. Every one of them is deliberate: the audit log is tamper-evidence, and a writer that recovers silently from a suspicious state destroys the evidence it exists to keep.

For the cryptographic detail behind these states see [Security internals](security-internals.md#audit-hash-chain).

## 1. Tip-anchor mismatch

**Wire code:** `audit.tip_anchor_mismatch`

**What it means.** The keyring holds a tip anchor for the log file: the number of entries in it, the SHA-256 hash of its last entry, and the byte offset just past that entry. The log at that path diverges from that tip. It is shorter than the anchor, or the entry ending at the anchored offset is not the anchored entry. A live writer also refuses growth beyond its own last append offset, including complete foreign rows or a torn prefix.

**Why it is checked at all.** The hash chain links each entry to its predecessor, and each file's `.root_hmac` sidecar signs that file's first entry. Both verify a PREFIX. Restoring yesterday's copy of the active log, or truncating the last few entries off it, leaves a log that passes the chain walk and the root signature and looks clean. The anchor is the only thing that knows how far the log had got. The anchor, the re-anchor counter, and the audit binding live in the keyring, outside the log file. Anyone who can restore the keyring's own storage together with the log can restore an older state. With a headless keyring backend these entries are kept in a file on the same host. Anyone who can write that file can restore older entries or delete one, which needs no key material. A deleted binding is recorded again from the profile file at the next keyed use. A deleted anchor is refused while anything shows it was written (section 1.1). Mainnet readiness refuses a headless backend, because a restored copy of its file can make a truncated log and its anchor agree.

**Where it surfaces.**

- Every value-moving CLI verb and MCP tool, before any signing key is touched or any transaction is submitted.
- `stellar-agent audit verify --profile <name> <log-path>`, when the path is the one that profile configures.
- `stellar-agent profile rotate-audit-key <name>`, before the key is rotated.

**Causes, in the order worth checking.**

1. **A restore.** The audit directory, the profile's data root, or the whole home directory was restored from a backup or a filesystem snapshot. Check the log's modification time against the times of the runs you expect to see in it.
2. **A truncation.** The file was clipped by a log-management tool, a failed copy, or a disk-full condition. `stellar-agent audit verify <log-path>` without `--profile` tells you whether the remaining prefix is intact.
3. **A second machine.** Two hosts sharing a profile directory over a network filesystem, or a profile directory synced by a file-sync client, each anchor independently in their own keyring. The anchor is per host.
4. **Tampering.** Someone with write access to the audit directory removed rows. Nothing about a rollback distinguishes this from case 1 on its own; the modification times, the contents, and your own change record do.

**Recovery.**

Establish which of the four it was BEFORE running the repair. Once the anchor moves, the evidence that it had moved is gone from the anchor. Only the row the repair writes remains.

```
stellar-agent audit verify <log-path>                       # is the remaining prefix intact
stellar-agent audit reanchor --profile <name>               # report only, changes nothing, exits 1
stellar-agent audit reanchor --profile <name> --acknowledge-rollback
```

When the profile's audit binding has also changed, the verb needs `--acknowledge-binding-change` as well; see §4.

The reporting form prints the anchor in force and the anchor it would write, both as `<entry count>:<byte offset>`, and exits 1. A stored anchor that cannot be parsed at all is reported as `unusable (<field count> colon-separated fields, <n> bytes)` rather than echoed. This includes a corrupted value, or one written by a build that predates the current format. The acknowledging form replaces it. Every other verb refuses on such a value: reading it as "nothing is anchored" would turn a corrupted anchor into a silently disarmed guard. Nothing is written. The acknowledging form replays the whole log first (a log whose own chain is broken is refused here, not blessed). It writes the current tip as the anchor, increments a monotonic per-path re-anchor counter in the keyring, and appends an `audit_tip_anchored` row naming the superseded anchor. That row is permanent: the log carries its own record that a rollback was accepted, including how far back it went.

**Growth underneath a live writer** refuses with the reason "the log is longer than the writer's last append". The writer stays latched after that refusal. Stop the process, preserve a copy of the log, and inspect the added bytes. Restore the last known intact prefix only after establishing which bytes are foreign or torn. Verify the repaired chain, then use the reporting and acknowledging `audit reanchor` forms above if the owed-row anchor requires repair. A chain that does not verify needs its bytes repaired first; re-anchoring cannot fix a splice. An intact tail ahead of the anchor at open remains acceptable, including a tail left by an anchor-write outage.

**A log replaced underneath a live writer** can also cause this refusal.
The MCP server normally caches an acquired writer until process exit.
Replacing the log by `mv` leaves its handle on the previous file until that
handle closes. Each acquisition and append compares the file at the path
against the open handle. A mismatch refuses with `audit.tip_anchor_mismatch`
and a message naming the replacement.

A replaced-file refusal during acquisition marks the cached writer for eviction. While callers
retain it, acquisitions continue to refuse. After callers release it, the
next acquisition drops the cached writer and opens the file at the path.
That file must satisfy the tip anchor. Overwriting the log in place (`cp`,
`>`, or a restore that writes through) preserves its identity; the tip
comparison detects divergence.

The process then stops using that writer: the caller holding it is refused on its next row, and every later request is refused with the same message until nothing references it, at which point the next value verb opens whatever is now at the path and checks THAT file against the anchor.

**A row refused on a replaced log leaves the anchor one entry ahead.** An append that is refused records, in the keyring, the row it was obliged to write: its count, its hash, and where it would have ended. That record retries once immediately and remains best-effort. When the keyring itself rejects it, the refusal still stands for the writer that made it and for every caller still holding that writer, but it does not survive the process. The signature described below is then absent, and the log looks like one that simply stopped. The action that row was going to prove has already committed, so the obligation outlives the process that failed to meet it. No file at the path satisfies the anchor afterward, including a byte-identical copy of the log as it stood a moment earlier. An anchor exactly one entry ahead of a log whose own chain verifies cleanly is that signature. `audit verify <log-path>` will report the chain intact while the anchored count exceeds the entry count by one. Treat it as a row that was owed and not written, establish what happened to the file, and recover with the acknowledging repair below. The `audit_tip_anchored` row it writes names the superseded anchor, which is the permanent record that a row went missing.

The same durability applies to a log truncated, extended, or overwritten in place inside that span: the append refuses on the file's length or on the entry at its own last append, and anchors the owed row identically. One row can still be lost, in the adjacent syscalls between an append's check and its write; the anchor then describes the displaced file, which is what turns the loss into a refusal rather than into silence.

The MCP server acquires its audit writer when an operation needs it, such as a commit preflight before signing. MCP balance reads do not acquire it. Under V1, payment simulations can reconcile overdue reservations, acquire the writer, and write settlement audit rows.

The registry normally caches the writer and holds its lock until process exit. A replaced-file refusal during acquisition marks the cached writer for eviction. After callers release it, the next acquisition drops it and checks the file at the path against the anchor.

A repair against a held writer refuses with `audit.writer_locked` in the
envelope's error detail. Stop a server holding that profile's writer, repair,
and start it again. The same applies to `profile rotate-audit-key`.

**Queued consent rows.** After its `audit_tip_anchored` rows, the acknowledging repair drains the audit outbox (section 8), so rows `stellar-agent approve` queued while the log was refused follow the repair rows. If the drain refuses, the repair still stands: the verb exits 0, omits `outbox_drained`, and lists the refusal under `warnings` (`audit.outbox_unusable`, `audit.outbox_busy`, `audit.outbox_rows_missing`, or the condition an append refused on, such as `audit.io_error`). Every queued row stays queued for the next drain, which appends again any row the refused drain had appended. The reporting form leaves the log, the anchor, and the outbox unchanged.

## 1.1 Missing tip anchor

**Wire code:** `audit.tip_anchor_missing`

**What it means.** No tip anchor is stored for the log path, yet something shows that one was written. Three facts outlive a deleted anchor:

- an audit binding recorded for the profile before this use (§4);
- a `.root_hmac` chain-root sidecar beside the active file, which a keyed writer writes with the file's first entry;
- an `audit_tip_anchored` row of any reason in the active file.

For an empty active file only the sidecar counts: a rotation renames the sidecar with its archive, so an empty file that still has one was truncated. The refusal names the fact it found. Adopting such a log would take a truncated file as the baseline and the removed rows would leave no trace, so the writer refuses and writes neither an anchor nor a row.

**Where it surfaces.** The same places as a mismatch (section 1). `stellar-agent audit verify --profile <name> <log-path>`, for the path that profile configures, reports it after the chain walk with a message that says `anchor: missing`. Without `--profile` the verb reads no keyring and checks no anchor.

**Causes.** The keyring entry holding the anchor was deleted: by a keyring tool, by a reset of the keyring, or by someone covering a truncation. A crash or a keyring failure between a file's first keyed entry and its first anchor write leaves the same state. A log written by a build without the anchor that a keyed writer signed also shows its sidecar; it refuses once. So does a log whose keyed use recorded the binding on an empty file and only unkeyed writers appended to it afterward.

**Recovery.** Check the log's prefix and establish why the anchor is gone, as for a mismatch. Then run:

```
stellar-agent audit verify <log-path>
stellar-agent audit reanchor --profile <name>               # report only, changes nothing, exits 1
stellar-agent audit reanchor --profile <name> --acknowledge-rollback
```

The reporting form prints the anchor in force as `none`. The acknowledging form anchors the current tip, bumps the re-anchor counter, and appends a `rollback_acknowledged` row with no `previous_anchor`. That row is the permanent record that a missing anchor was accepted.

## 2. Partial rotation

**Wire code:** `audit.partial_rotation`

Rotation renames the active log to an archive, renames its `.root_hmac` sidecar alongside, and creates a fresh active file. A crash part-way through leaves a directory state the writer refuses to open, rather than guessing. Three shapes are detected.

### 2.1 Orphan sidecar

A `<stem>.<timestamp>.root_hmac` sidecar exists with no matching `<stem>.<timestamp>` log file: the sidecar rename completed, the log rename did not.

Recovery: confirm the archive log really is absent rather than moved elsewhere. If it is absent, the rotation never happened and the sidecar belongs to the still-active file. Move the orphan sidecar out of the audit directory to a location outside it, then reopen. The active file's sidecar is rewritten on its next first-entry write, and `profile rotate-audit-key` re-signs every sidecar in the chain deterministically.

### 2.2 Mid-rename temporary file

A `.tmp` file is present in the audit directory. Every atomic write in this subsystem writes to a sibling temp file and renames; a leftover means an interruption.

Recovery: inspect the `.tmp` file. It is a partial sidecar or a partial state file, never a partial log. Move it out of the audit directory and reopen.

### 2.3 Truncated last entry

The active log's last line is not parseable JSON: the process died mid-append, before `fsync` completed.

Recovery: the entries before it are intact. Truncate the file to the end of the last complete line, then reopen. `stellar-agent audit verify <log-path>` confirms the result. Expect a tip-anchor mismatch on the next acquisition if the truncation removed a row the anchor had already counted; §1 applies.

## 2.4 Unusable rotation bridge

**Wire code:** `audit.rotation_bridge_unusable`

A file created by a rotation chains its first entry off the outgoing file's rotation-handoff entry, so opening the active file means reading that handoff out of the newest archive. This state means the archive's last entry is not a handoff naming that archive.

Causes: the archive was truncated mid-entry, or something that is not a rotated sibling of this log was placed in the audit directory under a name matching the rotated-sibling pattern (`<stem>.<compact timestamp>`).

The same code, with the reason "a file already exists under the rotation's archive name", refuses a rename onto an existing file. A rotation renames the active file and its sidecar only to names that are free. The writer names each archive so it sorts after every existing archive of the log. A fresh rotation therefore finds its name taken only by a stray `<name>.root_hmac` sidecar without its archive. An open, or an append after a failed handoff write, whose active file ends on a rotation handoff naming an existing file refuses before anything is written. Recovery: identify the file under that name. Move a stray sidecar without its archive out of the directory. If it is a genuine archive of this log, the handoff at the end of the active file was not written by the writer; investigate it as tampering (section 1).

The same code, with the reason "the archive names after the newest archive are exhausted", means the rotation found no name that sorts after the newest archive, which the message names. The writer takes the current millisecond when that sorts after the archive. Otherwise it continues from the archive's name with a six-digit counter, so a clock set back or standing still keeps the names in creation order. The names run out only after 999,999 rotations while the clock stays behind the newest archive. A file placed in the directory under a name ending in a counter of six nines exhausts them at once. The rotation writes nothing. Recovery: check the system clock and the newest archive, and move a file that is not a genuine archive of this log out of the directory.

The writer refuses rather than seeding the replay from an unverified hash. Recovery: list the audit directory, identify the file the message names, and confirm it is a genuine archive of this log. If it is not, move it out of the directory and reopen. If it is, it was truncated; `stellar-agent audit verify <log-path>` reports where.

The check is structural: it confirms the shape, not the archive's chain or its signature. `audit verify` is what establishes the bridge's integrity, walking every file and requiring each one's chain-root signature under the profile's key.

## 2.5 Rotation and the anchor

Rotation advances the anchor onto the outgoing file's handoff entry and leaves it there. The file the rotation creates has no entry of its own to name, so it inherits nothing until its first append; the guard stays armed on the previous generation's tip throughout.

An anchor naming the newest archive's handoff is recognised automatically on the next open, with no operator action and no row. That match is the fingerprint of a rotation, and nothing an attacker can write to the filesystem produces it: appending a handoff to a copy of the log yields a different tip hash. Restoring the directory to its pre-rotation state, or to an older archive-and-active pair, therefore refuses: neither holds an archive whose handoff is the anchored one, even though both restored states pass the chain walk.

There is no anchor value meaning "this file is empty". Offset 0 is a prefix of every file, so such a value would make every file read as ahead of the anchor and a restore would be absorbed rather than refused.

A keyring write outage can leave the stored anchor on the pre-handoff tip when
both the handoff and first new-file anchor fail. The live writer retains the
repair coordinates. After process exit, open and `audit verify` report
`audit.tip_anchor_mismatch` on this honest log. Verify the chain and investigate
the outage, then use `audit reanchor --profile <name> --acknowledge-rollback`.

## 3. What the anchor does not protect

The anchor detects rollback and truncation. It does not detect forgery.

The entry-to-entry chain hash is unkeyed. Someone who can write the log file can append a well-formed entry that chains correctly off the current tip, and both the chain walk and the anchor will accept it. The tip moved forward, which is what an honest append also looks like. Only the FIRST entry of each file carries a keyed signature, the `.root_hmac` sidecar, and only its own file's root.

Detecting appended forgeries would need a keyed tag per entry. This substrate does not have one. What it gives you is: entries cannot be edited or removed without detection, the log cannot be rewound without detection, and a file cannot be substituted for another without detection.

The anchor is also not a cross-host guarantee. It is held in the local keyring and describes one path on one host. The anchor, the re-anchor counter, and the audit binding live in the keyring, outside the log file. Anyone who can restore the keyring's own storage together with the log can restore an older state. With a headless keyring backend these entries are kept in a file on the same host. Anyone who can write that file can restore older entries or delete one, which needs no key material. A deleted binding is recorded again from the profile file at the next keyed use. A deleted anchor is refused while anything shows it was written (section 1.1). Mainnet readiness refuses a headless backend, because a restored copy of its file can make a truncated log and its anchor agree.

It is also not continuous in time. The anchor is written after the entry it covers is fsynced, because failing an append over a keyring error would misreport a row that was written. That leaves three states, and they differ in kind:

- **Lagging.** Between an entry's fsync and its anchor write landing, the anchor names the previous entry of this file. A rollback to that entry or later is absorbed; anything earlier is still refused. The write retries once immediately, then on the next append or keyed acquisition. After process exit, rollback to the previous anchor silently loses the unanchored tail. An outage widens the lag to the appends made during the outage.
- **Off, no anchor yet.** Until the first keyed append on a log path, nothing is anchored: a new profile, or a log written only by unkeyed writers. A changed `audit_log_path` is refused by the audit binding until it is acknowledged (§4). Adoption takes the file as it finds it. A rollback performed before that first acquisition becomes the baseline, silently, because there is no earlier anchored state to compare it against. Once a keyed writer has run, a deleted anchor no longer returns the log to this state (section 1.1).
- **Off, freshly rotated file.** From a rotation until the first append into the new file has its anchor write land, the anchor still names the archive's handoff. Any prefix of the new file, down to empty, is accepted if it chains from that handoff. Normally one append wide; a keyring outage spanning that append holds it open.

Entries already in an ARCHIVE are guarded throughout all three: a rolled-back prefix of the pre-rotation file cannot chain from the archive's handoff and is refused. When an anchor is expected and absent, treat the log as unverified rather than clean, and prefer `audit verify --profile` on a log you have reason to doubt: the chain walk covers every file regardless of the anchor's state.

## 4. Scope of the anchor

The anchor names one PATH inside one profile's keyring namespace. Its keyring service is the profile's audit-key service (`stellar-agent-audit-<profile>` by default) and its account is that key's account plus a digest of the lexically normalized log path, so:

- A changed `audit_log_path` or audit key has an anchor coordinate of its own, with nothing stored at it. The audit binding refuses that change until the operator acknowledges it; see **Audit binding** below.
- Paths that differ only by `.` or `..` components resolve to the same anchor. Paths that differ through a symlink do not: normalization is lexical, never `canonicalize`, because the coordinate has to be derivable before the log file exists.

**Two profiles must not share a log path.** Each holds its own anchor for that file, under its own audit service, and each advances only on its own appends. The profile that appended last is ahead; the other lags by everything the first wrote. A rollback to the lagging anchor is then refused by one profile and absorbed by the other, and whichever runs first decides which answer the operator sees. The configuration is unsupported; give each profile its own log file.

To check for it, run `stellar-agent profile show <name>` on every profile on the host and compare the `audit_log_path` values. Two profiles reporting the same path are in this state, whether or not either has refused anything yet.

### Audit binding

**Wire code:** `audit.log_binding_changed`

**What it means.** The keyring records, for each persisted profile, the SHA-256 of its lexically normalized `audit_log_path` and its audit-key coordinate. The record sits at service `stellar-agent-auditbinding-<profile>`, account `default`. The profile names a different log path or audit key than the record, or the record cannot be parsed. Every keyed audit writer refuses before it loads the audit key. The value-moving verbs and tools, on the zero-config profile too, exit with the code before signing. The read-only smart-account verbs, `approve --id <nonce>`, `approve serve`, `audit verify --profile`, `credentials add-passkey` (before its ceremony), and `profile rotate-audit-key` and `profile reset-window-state` exit with it too. A command whose audit row is best effort skips the row and continues: the other `profile` enroll and rotate verbs. A refusal creates nothing at the path the profile names.

**When the record is written.** The first keyed use of a persisted profile records it from the profile file, once the audit key has loaded; a profile with no audit key records nothing. A synthesized zero-config profile only compares, and records nothing. Unkeyed writers neither read nor write it.

**Causes.** An operator edited `audit_log_path` or `audit_log_hash_chain_key_id` in the profile file, or the file was edited or replaced by someone else. A value set through a `STELLAR_AGENT_*` environment variable is refused at load and never reaches this check.

**Recovery.** Establish who changed the profile and why. A binding change needs no MCP server stop: a server running the edited profile refuses before it opens the new path, so it holds no lock there. A server still running the old profile refuses after the acknowledgement until it restarts. The zero-config profile has no profile file, and `audit reanchor` loads only a profile file. On that profile, first restore the `default.toml` that recorded the binding, or write one that names the log. Then run:

```
stellar-agent audit reanchor --profile <name> --acknowledge-binding-change
```

| Recorded binding | Current path's anchor | Flags required | Rows appended |
| --- | --- | --- | --- |
| Equal or absent | Any | `--acknowledge-rollback` | `rollback_acknowledged` |
| Changed or unreadable | Agrees, or absent without prior anchoring evidence | `--acknowledge-binding-change` | `binding_changed` |
| Changed or unreadable | Disagrees, cannot be parsed, or absent with prior anchoring evidence | Both | `rollback_acknowledged`, then `binding_changed` |

An anchor agrees when `audit verify` would accept it; a file ahead of its anchor agrees. An absent anchor is covered by the first row: with an equal or absent binding the verb needs `--acknowledge-rollback` for it as for a mismatch (section 1.1). In the changed-binding rows an absent anchor disagrees when a chain-root sidecar or an `audit_tip_anchored` row shows prior anchoring, and agrees otherwise: a changed binding names a log path and audit key no anchor was written for yet, so only the log can show that one was. The verb decides this before it opens the writer and again under the writer's lock, where it reads the rows from its replay of the active file. A missing flag refuses with `validation.acknowledgement_required`, names the flag, and writes nothing. On success the verb anchors the current tip, bumps the current path's re-anchor counter once, and appends the rows, each carrying that count. `binding_changed` names the old path's anchor as `previous_anchor`, or none when the record was unreadable. The new binding is stored last, so a run that stops earlier leaves the refusal in place and a rerun appends its rows again. The envelope lists the conditions acknowledged and how the record compared. Queued consent rows follow the repair rows, as in section 1.

**Two data roots, one keyring.** The default `audit_log_path` derives from the OS data directory, which follows `$HOME` and `$XDG_DATA_HOME`. Two profile files of one name in two data roots that share one keyring bind different digests and refuse each other. Set an explicit `audit_log_path` in the profile file in such a deployment.

## 5. Adoption

A log with no anchor is adopted on first keyed use, with no operator action, when nothing shows an anchor was written: no recorded audit binding, no `.root_hmac` sidecar, and no `audit_tip_anchored` row in the file. A log written entirely by unkeyed writers is the ordinary zero-config state, and minting an audit key later must not be a one-way door. A log with any of the three is refused with `audit.tip_anchor_missing` (section 1.1).

Adoption replays the whole log first. A broken chain is refused rather than adopted.

On success the current tip becomes the anchor and an `audit_tip_anchored` row with reason `adopted` is appended. An adoption writes its row only for a non-empty file: an empty file stores no anchor and gets no row, and its first append writes the first anchor. A non-empty file gets exactly one such row per adoption.

## 6. Appends made without the anchor

Not every writer carries the anchor. The CLI startup advisory, the zero-config best-effort path, and the read-only smart-account verbs open the log unkeyed and do not move it. Their appends leave the log AHEAD of the anchor, which is not an error: the next acquisition that does carry the anchor replays the appended tail, confirms it chains off the anchored tip, and re-anchors on the new tip. No row is written for that; the appended rows are their own record.

The same path absorbs the crash window between an entry's `fsync` and the anchor write. The entry is durable, the anchor is one behind, and the next reconciliation closes the gap.

## 7. Reading the tip-anchor rows

```
grep '"kind":"audit_tip_anchored"' <log-path>
```

| Field | Meaning |
| --- | --- |
| `reason` | `adopted`, the log was taken under anchor protection at its current tip. `rollback_acknowledged`, an operator accepted a rolled-back log. `binding_changed`, an operator accepted a profile whose log path or audit key differs from its recorded binding. |
| `entry_count` | Entries in the active file when the anchor was adopted or repaired, before the first row of that adoption or repair. Every row of one repair carries the same count. |
| `previous_anchor` | The superseded anchor as `<entry count>:<byte offset>`. For `binding_changed`, the anchor of the log path the previous binding named. Absent for an adoption, and for a binding change whose record was unreadable or whose old path had no anchor. |
| `reanchor_count` | The current path's re-anchor counter after this repair. One repair bumps it once, so a `rollback_acknowledged` row and the `binding_changed` row after it carry the same count. Absent for an adoption. |

A `rollback_acknowledged` or `binding_changed` row is the thing to look for when reading a log's history: it marks a point where the log's own continuity was accepted rather than proven. A `rollback_acknowledged` row names how many entries and bytes were given up. A `binding_changed` row names where the previous log ended.

## 8. The audit outbox

`stellar-agent approve --id` writes its `approval_attested` row before it persists the approval. When a running MCP server or `approve serve` inbox holds the audit writer, the command cannot append to the log itself. It queues the row in the audit outbox, and the running process appends it.

**Files beside the log.**

| File | Purpose |
| --- | --- |
| `<log>.outbox` | Queued rows: JSON lines, one audit entry per line, mode `0600`. Each entry carries the timestamp of the consent it records. |
| `<log>.outbox.lock` | Held by every append and every drain while it touches the outbox. Waited on for up to 2 s, then `audit.outbox_busy`. |
| `<log>.drain.lock` | Held for its whole life by every writer that drains: the MCP server, `approve serve`, and every keyed CLI verb. `approve --id` reads it once to tell a draining holder from one that does not drain. |

**Keyring commitment.** The audit key's service stores the queue's count and SHA-256 chain head at `<audit-account>-tip-<path-digest>-outbox`.
Every append checks the committed prefix, syncs its new line, then stores the updated commitment.
A failed state write truncates the append back and refuses consent.

**Drain points.** A draining writer checks the commitment, appends every queued row, stores zero state, then truncates the outbox:

- when it opens, right after the tip-anchor check;
- on every keyed acquisition in a running process, under the same lock as that check;
- before each row of its own.

A command that consumes an approval acquires the writer after it reads the approval and before it loads a signing key. A queued consent row is therefore in the log before the key is touched. `audit reanchor` drains after its repair rows. The repair writer never drains when it opens, and its reporting form never drains.

**Delivery is at least once.** A crash between a drain's appends and its truncation appends the same rows again on the next drain. A repeated row keeps its `request_id`, which identifies it. An append that never returned `Ok` can leave a final segment with no newline; the next append or drain discards it with a warning.

**A row can record a consent that did not take effect.** The consent row is written, or queued, before the approval is persisted. A persist failure after the row, or a crash between the row and the persist, leaves an `approval_attested` row for an approval that never took effect. To tell, find the entry whose nonce starts with the row's `nonce_prefix` in `stellar-agent approve list --profile <name> --include-expired`. The approval took effect when the entry shows `attested: true` or kind `Consumed`. It did not when the entry still shows its original kind with `attested: false`, or is a `Rejected` tombstone. A listed toolset gate entry is inconclusive, because its removal after a persisted grant is best-effort. An entry already removed by `approve gc` cannot be judged from the store.

**Timestamps.** A drained row keeps its consent timestamp. Every draining writer drains before its own rows, so the log stays in time order. Three cases can still put an older timestamp after a newer one. The first is a row from a writer that does not drain: the CLI startup advisory, the zero-config path, or the `audit reanchor` repair rows. The second is a repeated row after a crash. The third is the adoption row an acquisition appends when its drain refuses. `audit verify` can then report `backward_timestamp_jump`; with the `request_id` of a repeated row, or the row's kind, that warning is explained.

**Committed queue.** A missing, shortened, changed, or reordered committed prefix refuses with `audit.outbox_rows_missing` before any queued row is appended.
This blocks keyed acquisition and approval consumption until the operator acknowledges the loss.
Rows beyond the commitment drain too, preserving delivery after an interrupted append or drain.
An absent keyring state reads as zero for an outbox without a commitment.
Raw deletion or restore of keyring entries outside the wallet rests on the platform keyring, as described in SECURITY.md.
The commitment does not authenticate who queued a row.

`audit verify --profile` checks the commitment under the outbox lock when the path is the profile's log.
It reports `outbox_pending` separately and warns about torn, unparseable, or unreadable queued lines.

### 8.1 Unusable outbox

**Detail sub-code:** `audit.outbox_unusable` (under `audit.chain_key_unavailable`)

**What it means.** A complete line of `<log>.outbox` does not parse as an audit entry. Every drain refuses, so every keyed acquisition refuses too, and the outbox is left unchanged. `audit verify` lists the line numbers under an `outbox_unparseable` warning.

**Recovery.**

1. Stop the processes that use the profile: the MCP server, `approve serve`, and any CLI verb.
2. Inspect the file: `cat -n <log>.outbox`. Each intact line is one consent row, with its `kind`, `ts`, `request_id`, and `nonce_prefix`.
3. Move the file out of the audit directory: `mv <log>.outbox <somewhere-else>/outbox.saved`.
4. Re-queue the intact lines byte-identically, in their original order and with each newline, into a new `<log>.outbox` with mode `0600`. Leave out only the unparseable lines.
5. Start one keyed verb, or the MCP server. Its first acquisition checks and drains the re-queued rows. A missing or changed committed line reports `audit.outbox_rows_missing`; follow section 8.3.

Deleting a line drops a consent row whose approval may already have taken effect. Keep the saved file with the incident record, and leave out only what does not parse.

### 8.2 Busy outbox

**Detail sub-code:** `audit.outbox_busy` (under `audit.chain_key_unavailable`)

**What it means.** The outbox lock stayed held for the whole 2 s wait. Another process is appending to or draining the outbox, or a process holding it has stopped responding.

**Recovery.** Retry. If it persists, find the process holding `<log>.outbox.lock` (`lsof <log>.outbox.lock` on Unix) and stop it; the lock is released when its holder exits. `approve --id` refuses with this code and persists nothing, so retrying it is safe.

### 8.3 Lost or changed committed rows

**Detail sub-code:** `audit.outbox_rows_missing`

The keyring records a committed prefix that the outbox does not hold unchanged and in order.
Every keyed writer acquisition and every draining write refuses.
An append also refuses, so concurrent approvals cannot persist consent into a divergent queue.

Stop processes using the profile and preserve the outbox for inspection.
After investigating, the operator runs:

```bash
stellar-agent audit acknowledge-outbox-loss --profile default --reason "Queue inspected; missing consent requires fresh approval"
```

The command checks the log's tip anchor and takes its writer and drain locks.
It checks that the loss holds and that every remaining complete line parses.
It then revokes every decided, unexpired, unconsumed approval, including mainnet confirmations and recorded passkey assertions, and every toolset grant.
Undecided requests remain.
It appends `audit_outbox_loss_acknowledged`, drains the remaining complete rows, stores zero state, and truncates the outbox.
The operator approves affected actions again, creating new consent rows.

The result reports `profile`, `expected_rows`, `found_rows`, `drained`, `revoked_approvals`, and `revoked_grants`.
A held writer refuses with `audit.writer_locked`.
A log rolled back behind its tip anchor refuses with `audit.tip_anchor_mismatch`; follow section 1 first.
No divergence refuses with `audit.outbox_loss_not_found` and writes no acknowledgement.
A remaining line that does not parse refuses with `audit.outbox_unusable` before anything is revoked or written.
Follow section 8.1 for that line, then rerun the acknowledgement.
An append refusal after the acknowledgement row leaves the queue and commitment in place; a rerun records the loss again.
A crash after revocation leaves the loss in place; rerunning revokes any remaining permissions.
`audit verify` reports each acknowledgement as an `outbox_loss_acknowledged` warning without changing the chain verdict.

## 9. Tip anchor unavailable

**Detail sub-code:** `audit.tip_anchor_unavailable`

**What it means.** The keyring-held tip anchor could not be read or written.
A keyed append retries its anchor once immediately. Two failed writes leave
the row durable and the anchor behind. Plain appends continue best-effort, and
`require_anchor_current()` repairs or refuses without writing a row.
A submission recorded through the pending row, the window-state reset, and an
x402 payment require repair before and after their pre-action row.
The pending row maps the refusal to `submission.record_unavailable`; the reset
and x402 use `audit.chain_key_unavailable`. The detail names the sub-code.
A pending-row refusal before the row writes no receipt and no row. After the
row, the recorder attempts the release of the reservation, a
`value_action_failed` row under `submission.record_unavailable` that closes
the pending row, and the removal of the receipt, each best-effort and logged.
A resend that the reservation's duplicate check refuses after its row leaves
that row open for the original submission's settlement. Nothing is sent.
On testnet, an x402 refusal keeps the admitted spend. On mainnet, an anchor
refusal precedes intent consumption, and the open intent releases its holds. A
refusal after the authorized row also records `x402_authorization_withheld` with stage `anchor_unavailable`.
MPP's charge row keeps its existing flow.

**Recovery.** Restore keyring access and retry. A live writer retries the
anchor value it still owes; a keyed reopen absorbs an honest tail in the same
generation. Reopening still refuses while the keyring is unavailable. Use
`audit reanchor` only for an established mismatch, including the rotation
outage in section 2.5.

**Unusable outbox commitment.** A detail that contains `outbox state is
unusable` names a different cause: the keyring holds a value at the outbox
commitment's account, `<audit-account>-tip-<path-digest>-outbox` in the audit
key's service, that does not parse. The wallet never writes such a value, so
it was changed outside the wallet. Restoring keyring access does not clear
it. Every drain, every keyed acquisition, every queued consent, and
`audit acknowledge-outbox-loss` refuse with this sub-code, and nothing is
read as "nothing queued".

1. Stop the processes that use the profile: the MCP server, `approve serve`,
   and any CLI verb.
2. Copy `<log>.outbox` out of the audit directory with the incident record.
3. Remove the keyring entry at that account with the platform keyring tool, as
   in section 10. An absent commitment reads as zero.
4. Start one keyed verb, or the MCP server. Its first acquisition drains every
   complete queued line.

Removing the entry gives up the check of the rows queued before it, as a
deletion of the entry outside the wallet does (section 8, "Committed queue").
Compare the saved outbox with the `approval_attested` rows the drain appended
before approving anything new.

## 10. Unreadable or undecodable audit key

**Wire codes:** `audit.chain_key_unavailable` from the value-moving verbs and tools; from `stellar-agent profile rotate-audit-key`, the keyring read failure's own code, or `internal.unexpected_state` with the detail sub-code `audit.key_decode_failed` or `audit.key_length_error`.

**What it means.** The profile's audit chain-root key entry exists, but it cannot be read, or its value is not base64 of exactly 32 bytes. `rotate-audit-key` mints a key only where no entry exists. It refuses an entry it cannot read or decode, before it records a binding, writes a key, or touches the log. The entry may hold the key the log's chain-root sidecars are signed under, and a read failure may be the keyring itself failing, which a new write would hide.

**Recovery.** Investigate first: a locked or failing keyring is fixed in the keyring, and the key comes back unchanged. If the stored audit key is corrupt:

1. Remove that keyring entry with the platform keyring tool, such as Keychain Access on macOS, Seahorse on Linux, or Credential Manager on Windows. The entry's service and account are the profile's `audit_log_hash_chain_key_id`.
2. Run `stellar-agent profile rotate-audit-key <name>` to mint a new key. It re-signs the log's chain-root sidecars under that key.
3. If the log's anchor is gone, the rotation refuses with `audit.tip_anchor_missing` (section 1.1). Run `stellar-agent audit reanchor --profile <name> --acknowledge-rollback` after the checks that section names.

## 11. Retained history without an authenticated start

The retained history starts where `<log>.pruned` says its oldest archive
starts, or at the zero seed when no prune has run. A log whose oldest archives
were deleted outside the writer, for example by a build that pruned without the
marker, by a log-management tool, or by hand, or whose marker was deleted, has
an oldest archive that chains from neither. `audit verify` fails at line 1 of
that archive. Every prune stops with a warning that names this section and
keeps every archive, so the archives accumulate until open and verify refuse
past 21 rotated files with `audit.too_many_rotated_files`. The writer never
adopts such a start on its own: a missing archive or marker looks exactly like
removed evidence.

**Recovery.** Establish why the history is short, as for a mismatch (section
1). Then keep the old log as the record and start a new one at the path:

1. Stop every process that holds the profile's audit writer, such as a running
   `stellar-agent-mcp` server.
2. Copy the whole audit directory to a location outside it and keep the copy.
3. Move the active log, every archive `<log>.<timestamp>`, each one's
   `.root_hmac` sidecar, and `<log>.pruned` when present out of the audit
   directory. Leave the lock file and the audit outbox in place.
4. Run the repair against the now empty path:

```
stellar-agent audit reanchor --profile <name>               # creates the empty log, writes no row, exits 1
stellar-agent audit reanchor --profile <name> --acknowledge-rollback
```

The reporting form creates the empty log at the path, writes no row and no
anchor, and prints the anchor in force and `none` as the anchor it would
write. The acknowledging form appends the log's first row, a
`rollback_acknowledged` row naming the superseded anchor, anchors it, bumps the
re-anchor counter, and drains the audit outbox; it creates the log as well when
the reporting form did not run. `audit verify <log-path>` then verifies the new
log from the zero seed. The moved files keep the earlier history.

The prune and `audit verify` pick the start of the retained history by one
rule: the zero seed without a marker, and otherwise the seed the marker records
for the oldest archive as either of its boundaries. A marker that names neither
boundary for the oldest archive stops every prune and fails `audit verify` with
`audit.chain_broken`, reason `prune_marker_names_neither_boundary`, at line 1
of that archive. When the full history from the zero seed sits beside such a
marker, for example after the whole directory was restored from a copy taken
before the first prune, move the marker out of the audit directory and keep it
with the copy: verification and the next prune then start from the zero seed,
and no reanchor is needed.

A prune that stops logs a warning naming the file it stopped at and the cause,
and the rotation still completes. A planted, edited, split, unreadable, or
oversized file from the oldest archive to the one just rotated, a malformed
handoff, an archive whose chain-root tag is missing or does not verify under
the writer's key, a marker that does not parse or authenticate, or a failed
marker write or removal keeps the excess archives and needs investigation. A
sibling placed under a name that sorts after every archive precedes the next
archive, which the writer names after it, and stops the prune the same way.
Pruning resumes once the offending file is removed or
restored; rotating cannot repair an interior edit. A keyed open writes a
missing tag only for a file its anchor proves from byte 0; for a file it
cannot prove, such as one adopted without an anchor, `audit reanchor` writes
the tag after the operator acknowledges the file as it stands. Neither writes a
tag for a file whose first entry does not start at byte 0. An archive that
an unkeyed writer both started and rotated has no tag. After checking that it
is genuine, `profile rotate-audit-key` re-signs every file. Past 21 rotated
files, open and verify refuse with `audit.too_many_rotated_files`.
