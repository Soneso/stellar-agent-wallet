# Provenance fixtures

`SHA256SUMS` and the subjects in
`stellar-agent-0.1.0-alpha.12.intoto.jsonl` come from the public alpha.12 release.
The fixture is the Sigstore bundle reduced to its DSSE envelope. The envelope
keeps the payload type, and the statement keeps the subjects. The predicate keeps
the builder, the build type, the entry point, and the metadata flags.
The source repository, tag, commit, material identity, and build invocation ID
are synthetic. The invocation environment has exactly the generator's 15 keys
with synthetic values and no personal data. Its commit, ref and repository owner
match the source, and its ref type and event name are `tag` and `push`.
The checker does not compare the other environment values.
Signatures and verification material are omitted because this fixture tests
predicate content, not signature verification.
