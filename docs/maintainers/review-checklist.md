# Review checklist

Every change is reviewed for production readiness before it is committed.
Reviewers check the change against the dimensions below, and review repeats until
the review approves with no blocking findings.

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
- Fail closed. A check that runs before signing or submission refuses on error
  rather than proceeds. The behaviors that deliberately differ are documented:
  the audit chain-key pre-flight on the synthesized zero-config profile in
  [SECURITY.md](../../SECURITY.md#security-model-summary) and the audit rows
  written after the chain action in
  [concepts](../concepts.md#the-hash-chained-audit-log). A change adds
  no new one without a security review.
- No secrets or mainnet keys are committed.
- A credential or authorization returned without local submission is treated as
  a one-shot value action: policy accounting happens before signing, durable
  replay state is claimed first, and an ambiguous post-key-access result cannot
  sign or deliver again.

### 3. Tests and coverage

- A pull request that changes Rust code carries the `coverage` label, and the
  `coverage` check on its head is green.
- Line coverage clears the per-crate floors enforced by
  `.github/scripts/check-coverage.py` (a regression ratchet set a few points
  below current offline coverage); 90% per crate is the aspirational target,
  and any shortfall below it is justified in the review (for example,
  live-network paths exercised by acceptance tests rather than unit tests).
- **Tests assert correct behavior.** A test must fail if the behavior it covers
  regresses. A test that only raises the coverage number by exercising or
  asserting wrong or buggy behavior, or that would still pass if the code were
  broken, is a blocking finding and must be reported. The fix is to correct the
  code or the expected value, never to keep the test for the coverage number.

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

### Dependency bumps

- When updating `stellar-rpc-client`, inspect its `send_transaction` error
  construction and re-check `is_definitive_send_refusal` in
  `crates/stellar-agent-network/src/submit.rs`. The classifier depends on the
  client's `No status yet:` wording to distinguish an unknown transport outcome
  from a definitive endpoint refusal; that distinction controls the code the
  caller receives.
- Run both real-client tests in
  `crates/stellar-agent-network/tests/network/submission_record_integration.rs`:
  `a_transport_failure_after_the_record_returns_the_timeout_shape` and
  `a_refused_send_retains_the_reservation_and_sequence`. Confirm that transport
  failures return the timeout shape and definitive refusals return the
  endpoint's code. Both retain the receipt, the reservation, and the
  sequence. A bounded reservation stays charged through its accounting
  horizon, and an operator clear releases only an untimed one.

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

Start local verification with `bash .github/scripts/preflight.sh` and run the
issue-specific acceptance commands. `bash .github/scripts/preflight.sh --full`
runs the complete local registry, including coverage.

CI runs the offline workspace suite on every pull request. Pull-request
coverage requires the `coverage` label; live acceptance uses its separate
workflow. Local coverage, `cargo machete`, and `cargo deny check` are optional
reproductions. Record each local gate's exit code or unavailable status.

## Self-review before you open a pull request

### Test teeth

For each new test, revert the production lines it checks in a scratch copy, or
introduce the specific defect. Run the test alone and confirm the relevant
assertion fails. Restore the scratch copy afterward. A test that still passes
has no teeth; fix it before the pull request. Name the tests you probed this
way in the pull request description.

### Quality criteria

1. **Comments and docstrings** state what holds and why. Nothing in them is
   stale, narrates the obvious, tells the history, or contrasts the code with
   behavior it does not have.
2. **Dead code.** No branch is unreachable, and no condition tests a state the
   callers cannot produce.
3. **Unused surface.** Every symbol, parameter, field, constant, and import
   has a consumer, and each item's visibility matches what its callers need.
4. **Duplication.** The change repeats no logic within itself and none that
   the workspace already provides. Read the neighboring modules before you add
   a helper.
5. **Dark code.** The purpose of each item follows from its name, structure,
   and comments. Names do not mislead, and the code prefers a plain
   construction to a clever one.
6. **Size and structure.** Each function has one responsibility, and every
   abstraction earns its indirection.
7. **House style.** The change follows the writing rules of
   [CONTRIBUTING.md](../../CONTRIBUTING.md), the lint posture of the root
   `Cargo.toml`, and the test naming of the crate it changes.

## Mainnet release reviews

A release that ships the `mainnet-write` build gets two reviews beyond the
dimensions above: a signing-authority review and an approval-flow review.
Each runs against the commit the release is cut from. Two reviewers who did
not implement the reviewed code carry out each review.

### Signing-authority review

Scope:

- The policy Allow path, from the policy decision to the signature.
- The presence-gated witness path.
- The operation record and its single use.
- The recovery transitions.
- The audit writer and its outbox.

Attacker model:

- An agent process with the wallet's MCP access.
- Another process of the same OS user.
- A malicious or stalled RPC endpoint.
- A replayed or copied approval record.
- A restored older state file.

Pass criteria:

- A test or a named probe reproduces every finding.
- Every blocking finding is closed with a regression test.
- Every claimed invariant has a named test.
- The two reviewers did not implement the reviewed code.

Deliverable: a written verdict that lists the invariants checked, the probes
run, the findings, and the closure of each finding.

### Approval-flow review

Scope:

- The durable approval record.
- The consumption of an approval.
- Revocation.
- Re-sign invalidation: a policy re-sign at a higher sequence invalidates
  every consent, witness, and authorization issued under the earlier
  signature, also when the credentials are unchanged.
  `mainnet_witness_reloads_current_policy` in
  `crates/stellar-agent-core/src/approval/witness.rs` proves it.
- The intent the consent page renders.
- The remote listener's origin and certificate binding.
- Enrollment.

Attacker model: every attacker of the signing-authority review, and a device
on the approving network.

Pass criteria:

- A named test demonstrates single use.
- A named test demonstrates digest binding.
- A named test demonstrates revocation.
- A named test demonstrates re-sign invalidation.
- A named test demonstrates origin binding.
- The browser acceptance suites pass at the configured origin. The
  [serialized driver](building.md#live-testnet-acceptance-tests) runs them.
- The wallet refuses the remote listener without the signed configuration.
- Every finding is reproduced and closed as in the signing-authority review.

Deliverable: a written verdict as for the signing-authority review.
