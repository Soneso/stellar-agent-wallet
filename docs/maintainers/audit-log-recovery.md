# Audit-log recovery

Operator guidance for the states the audit log can be found in that block a writer from opening, or a value-moving verb from signing. Every one of them is deliberate: the audit log is tamper-evidence, and a writer that recovers silently from a suspicious state destroys the evidence it exists to keep.

For the cryptographic detail behind these states see [Security internals](security-internals.md#audit-hash-chain).

## 1. Tip-anchor mismatch

**Wire code:** `audit.tip_anchor_mismatch`

**What it means.** The keyring holds a tip anchor for the log file: the number of entries in it, the SHA-256 hash of its last entry, and the byte offset just past that entry. The log at that path no longer contains that tip. It is shorter than the anchor, or the entry ending at the anchored offset is not the anchored entry.

**Why it is checked at all.** The hash chain links each entry to its predecessor, and each file's `.root_hmac` sidecar signs that file's first entry. Both verify a PREFIX. Restoring yesterday's copy of the active log, or truncating the last few entries off it, leaves a log that passes the chain walk and the root signature and looks clean. The anchor is the only thing that knows how far the log had got, and it lives in the platform keyring, where filesystem access alone cannot rewind it.

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

Establish which of the four it was BEFORE running the repair. Once the anchor moves, the evidence that it had moved is gone from the anchor — only the row the repair writes remains.

```
stellar-agent audit verify <log-path>                       # is the remaining prefix intact
stellar-agent audit reanchor --profile <name>               # report only, changes nothing, exits 1
stellar-agent audit reanchor --profile <name> --acknowledge-rollback
```

The reporting form prints the anchor in force and the anchor it would write, both as `<entry count>:<byte offset>`, and exits 1. A stored anchor that cannot be parsed at all — a corrupted value, or one written by a build that predates the current format — is reported as `unusable (<field count> colon-separated fields, <n> bytes)` rather than echoed, and the acknowledging form replaces it. Every other verb refuses on such a value: reading it as "nothing is anchored" would turn a corrupted anchor into a silently disarmed guard. Nothing is written. The acknowledging form replays the whole log first (a log whose own chain is broken is refused here, not blessed), writes the current tip as the anchor, increments a monotonic per-path re-anchor counter in the keyring, and appends an `audit_tip_anchored` row naming the superseded anchor. That row is permanent: the log carries its own record that a rollback was accepted, including how far back it went.

**A log replaced underneath a live writer** is the fourth cause in a different shape. A long-lived process — the MCP server — holds one file handle for its lifetime, so replacing the log by `mv` leaves that handle on the previous file: it still exists, unnamed, until the process exits. The identity of the file at the path is compared against that handle on every acquisition and again on every row appended, so this refuses with the same code and the refusal's message names the log as replaced underneath the writer rather than as shorter than the anchor. Overwriting the log in place (`cp`, `>`, a restore that writes through) never changes the file's identity and is caught by the ordinary tip comparison instead.

The process then stops using that writer: the caller holding it is refused on its next row, and every later request is refused with the same message until nothing references it, at which point the next value verb opens whatever is now at the path and checks THAT file against the anchor.

**A row refused on a replaced log leaves the anchor one entry ahead.** An append that is refused still records, in the keyring, the row it was obliged to write — its count, its hash, and where it would have ended. The action that row was going to prove has already committed, so the obligation outlives the process that failed to meet it: no file at the path satisfies the anchor afterwards, including a byte-identical copy of the log as it stood a moment earlier. An anchor exactly one entry ahead of a log whose own chain verifies cleanly is that signature, and `audit verify <log-path>` will report the chain intact while the anchored count exceeds the entry count by one. Treat it as a row that was owed and not written, establish what happened to the file, and recover with the acknowledging repair below; the `audit_tip_anchored` row it writes names the superseded anchor, which is the permanent record that a row went missing.

The same durability applies to a log truncated or overwritten in place inside that span: the append refuses on the file's length or on the entry at its own last append, and anchors the owed row identically. One row can still be lost, in the adjacent syscalls between an append's check and its write; the anchor then describes the displaced file, which is what turns the loss into a refusal rather than into silence.

**While the MCP server is running**, it holds the audit writer's exclusive lock for its lifetime, so the repair refuses with `audit.writer_locked` in the envelope's error detail. Stop the server, repair, start it again. The same applies to `profile rotate-audit-key`.

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

The writer refuses rather than seeding the replay from an unverified hash. Recovery: list the audit directory, identify the file the message names, and confirm it is a genuine archive of this log. If it is not, move it out of the directory and reopen. If it is, it was truncated; `stellar-agent audit verify <log-path>` reports where.

The check is structural: it confirms the shape, not the archive's chain or its signature. `audit verify` is what establishes the bridge's integrity, walking every file and requiring each one's chain-root signature under the profile's key.

## 2.5 Rotation and the anchor

Rotation advances the anchor onto the outgoing file's handoff entry and leaves it there. The file the rotation creates has no entry of its own to name, so it inherits nothing until its first append; the guard stays armed on the previous generation's tip throughout.

An anchor naming the newest archive's handoff is recognised automatically on the next open, with no operator action and no row. That match is the fingerprint of a rotation, and nothing an attacker can write to the filesystem produces it: appending a handoff to a copy of the log yields a different tip hash. Restoring the directory to its pre-rotation state, or to an older archive-and-active pair, therefore refuses — neither holds an archive whose handoff is the anchored one — even though both restored states pass the chain walk.

There is no anchor value meaning "this file is empty". Offset 0 is a prefix of every file, so such a value would make every file read as ahead of the anchor and a restore would be absorbed rather than refused.

## 3. What the anchor does not protect

The anchor detects rollback and truncation. It does not detect forgery.

The entry-to-entry chain hash is unkeyed. Someone who can write the log file can append a well-formed entry that chains correctly off the current tip, and both the chain walk and the anchor will accept it — the tip moved forward, which is what an honest append also looks like. Only the FIRST entry of each file carries a keyed signature, the `.root_hmac` sidecar, and only its own file's root.

Detecting appended forgeries would need a keyed tag per entry. This substrate does not have one. What it gives you is: entries cannot be edited or removed without detection, the log cannot be rewound without detection, and a file cannot be substituted for another without detection.

The anchor is also not a cross-host guarantee. It is held in the local platform keyring and describes one path on one host.

It is also not continuous in time. The anchor is written after the entry it covers is fsynced, because failing an append over a keyring error would misreport a row that was written. That leaves three states, and they differ in kind:

- **Lagging.** Between an entry's fsync and its anchor write landing, the anchor names the previous entry of this file. A rollback to that entry or later is absorbed; anything earlier is still refused. A failed write is retried at the start of the next append, so a transient keyring error costs one entry; an outage widens it to the appends made during the outage.
- **Off, no anchor yet.** Until the first keyed append on a log path, nothing is anchored: a new profile, a changed `audit_log_path`, or the first use of a log written before the anchor existed. Adoption takes the file as it finds it. A rollback performed before that first acquisition becomes the baseline, silently, because there is no earlier anchored state to compare it against.
- **Off, freshly rotated file.** From a rotation until the first append into the new file has its anchor write land, the anchor still names the archive's handoff. Any prefix of the new file, down to empty, is accepted if it chains from that handoff. Normally one append wide; a keyring outage spanning that append holds it open.

Entries already in an ARCHIVE are guarded throughout all three: a rolled-back prefix of the pre-rotation file cannot chain from the archive's handoff and is refused. When an anchor is expected and absent, treat the log as unverified rather than clean, and prefer `audit verify --profile` on a log you have reason to doubt: the chain walk covers every file regardless of the anchor's state.

## 4. Scope of the anchor

The anchor names one PATH inside one profile's keyring namespace. Its keyring service is the profile's audit-key service (`stellar-agent-audit-<profile>` by default) and its account is that key's account plus a digest of the lexically normalized log path, so:

- Changing a profile's `audit_log_path` starts a fresh anchor at the new path. The first value-moving verb after the change adopts the new file's tip and records an `audit_tip_anchored` row with reason `adopted`. This is deliberate: the old anchor describes the old file, which still has it.
- Paths that differ only by `.` or `..` components resolve to the same anchor. Paths that differ through a symlink do not: normalization is lexical, never `canonicalize`, because the coordinate has to be derivable before the log file exists.

**Two profiles must not share a log path.** Each holds its own anchor for that file, under its own audit service, and each advances only on its own appends. The profile that appended last is ahead; the other lags by everything the first wrote. A rollback to the lagging anchor is then refused by one profile and absorbed by the other, and whichever runs first decides which answer the operator sees. The configuration is unsupported; give each profile its own log file.

To check for it, run `stellar-agent profile show <name>` on every profile on the host and compare the `audit_log_path` values. Two profiles reporting the same path are in this state, whether or not either has refused anything yet.

## 5. Adoption

A log with no anchor is adopted on first keyed use, with no operator action. This is what happens on the first run after upgrading a wallet whose audit log predates the anchor.

Adoption replays the whole log first. A broken chain is refused rather than adopted. When the writer has a chain-root key and the file has a `.root_hmac` sidecar, that sidecar must verify; a log with no sidecar at all still adopts, because a log written entirely by unkeyed writers is the ordinary zero-config state and minting an audit key later must not be a one-way door.

On success the current tip becomes the anchor and an `audit_tip_anchored` row with reason `adopted` is appended. Exactly one such row appears per adoption.

## 6. Appends made without the anchor

Not every writer carries the anchor. The CLI startup advisory, the zero-config best-effort path, and the read-only smart-account verbs open the log unkeyed and do not move it. Their appends leave the log AHEAD of the anchor, which is not an error: the next acquisition that does carry the anchor replays the appended tail, confirms it chains off the anchored tip, and re-anchors on the new tip. No row is written for that; the appended rows are their own record.

The same path absorbs the crash window between an entry's `fsync` and the anchor write. The entry is durable, the anchor is one behind, and the next reconciliation closes the gap.

## 7. Reading the tip-anchor rows

```
grep '"kind":"audit_tip_anchored"' <log-path>
```

| Field | Meaning |
| --- | --- |
| `reason` | `adopted` — the log was taken under anchor protection at its current tip. `rollback_acknowledged` — an operator accepted a rolled-back log. |
| `entry_count` | Entries in the active file when the anchor was written, before this row was appended. |
| `previous_anchor` | The superseded anchor as `<entry count>:<byte offset>`. Absent for an adoption. |
| `reanchor_count` | The path's monotonic count of acknowledged rollbacks, after this one. Absent for an adoption. |

A `rollback_acknowledged` row is the thing to look for when reviewing a log's history: it marks a point where the log's own continuity was accepted rather than proven, and names how many entries and bytes were given up.
