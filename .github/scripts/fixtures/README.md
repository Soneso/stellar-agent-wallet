# Provenance fixtures

`SHA256SUMS` and the predicate in
`stellar-agent-0.1.0-alpha.12.intoto.jsonl` come from the public alpha.12 release.
The fixture is the Sigstore bundle reduced to its DSSE envelope. The envelope
keeps the payload type, and the statement keeps the subjects. The predicate keeps
the builder, the build type, the source repository, tag, commit, and entry point,
the metadata, and the materials. The invocation environment is
empty to exclude personal data. Signatures and verification material are
omitted because this fixture tests predicate content, not signature
verification.
