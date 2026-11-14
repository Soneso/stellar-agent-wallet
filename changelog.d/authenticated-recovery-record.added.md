- Authenticated recovery run records provide bounded reading, exposure validation, contextual classification, and pure scheduling views.
  Run objects select a dedicated wire version, which remains after compaction. Builds supporting only version 12 refuse these files.
  The maximum operation size changes from 184,365 to 192,685 bytes. Admission headroom changes the file threshold from 1,179,648 to 1,048,576 bytes.
  The threshold also applies to existing version-12 files. Eligible pruning frees capacity; protected authorizations retain their records.
  This release writes no run records; the recovery driver does not create them.
  The driver retains its request, selection, timeout, and settlement behavior and preserves run bytes on every commit.
  Views grant no proof, debit release, successor permission, or retry command.
  `stellar-agent tx receipt clear <ENVELOPE_HASH> --acknowledge` records an accounting acknowledgement.
  Untimed holds also require `--acknowledge-unbounded`; neither acknowledgement proves a chain outcome or permits a successor.
