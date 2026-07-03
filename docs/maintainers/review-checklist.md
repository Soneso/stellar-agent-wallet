# Review checklist

Every change is reviewed for production readiness before it is committed.
Reviewers check the change against the dimensions below, and review repeats until
every reviewer approves with no blocking findings.

## Reviewers

- **Security reviewer** — security and key hygiene, dependency licensing, and the
  project invariants.
- **Code reviewer** — documentation, public API and dead code, reuse and
  duplication, and test quality and coverage.
- **Architecture reviewer** — reuse-versus-build and dependency choices, module
  architecture, and overall production readiness.

## Dimensions

### 1. Correctness

- Logic is correct; edge cases and negative paths are handled.
- Where a specification (SEP, CAP, SLIP, BIP) publishes test vectors, the code is
  verified against them.

### 2. Security and key hygiene

- No secret material appears in logs, `Debug` output, or error messages. Account
  identifiers and transaction hashes are redacted at info level.
- Secret values zeroize on drop; no un-zeroized copies linger.
- No `unsafe`. No `unwrap`, `expect`, or `panic` in library code unless provably
  infallible with an inline justification.
- Every error path fails closed; nothing fails open.
- No secrets or mainnet keys are committed.

### 3. Tests and coverage

- Line coverage is at least 90% per crate. Any shortfall is justified in the
  review (for example, live-network paths exercised by acceptance tests rather
  than unit tests).
- **Tests assert correct behavior.** A test must fail if the behavior it covers
  regresses. A test that only raises the coverage number by exercising or
  asserting wrong or buggy behavior, or that would still pass if the code were
  broken, is a blocking finding and must be reported. The fix is to correct the
  code or the expected value — never to keep the test for the coverage number.

### 4. Documentation

- Every public item has rustdoc, with `# Errors`, `# Panics`, and `# Examples`
  sections where applicable. Examples compile and run as doc-tests.
- Comments and docs are accurate, terse, and describe current behavior and
  rationale only. No development-history narration. No references to internal or
  non-public documents. No placeholder or scaffolding language.
- User-facing behavior (CLI commands, MCP tools) is documented under `docs/`.
- Architecture, design decisions, and subsystem internals are documented under
  `docs/maintainers/`.

### 5. Reuse and dependencies

- No code duplicates functionality that already exists in the repository or that a
  dependency already provides.
- XDR, strkey, RPC, and transaction-building primitives use the maintained Stellar
  crates (`stellar-xdr`, `stellar-strkey`, `stellar-rpc-client`,
  `stellar-baselib`) rather than hand-rolled equivalents. A decision not to reuse
  is documented.
- Dependencies are pinned to the latest stable version available at authoring
  time. No unused dependencies.

### 6. Public API and dead code

- The public API is minimal and coherent; unused public items are removed.
- No dead code. No `TODO` or `FIXME` unless it cites a tracked issue.

### 7. Licensing and invariants

- Every dependency license is permissive-compatible.
- Derived or vendored code carries the attribution its source license requires.
- The change preserves the project invariants: self-custodial keys that never
  leave the host without explicit per-action consent, no required
  project-operated backend, no central store of user secrets, a permissive
  license, deterministic machine-readable output, and testnet/mainnet parity.

### 8. Build gates

All of the following pass:

- `cargo fmt --all --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-features` (unit, integration, and doc-tests)
- `cargo llvm-cov` meets the coverage bar
- `cargo machete`
- `cargo deny check`
