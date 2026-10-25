# Provenance fixtures

`SHA256SUMS` and the predicate in
`stellar-agent-0.1.0-alpha.12.intoto.jsonl` come from the public alpha.12 release.
The fixture is the Sigstore bundle reduced to its DSSE envelope. The predicate
keeps the builder, the source repository, tag, commit and entry point, the
materials, the subjects and the payload type. The invocation environment is
empty to exclude personal data. Signatures and verification material are
omitted because this fixture tests predicate content, not signature
verification.
