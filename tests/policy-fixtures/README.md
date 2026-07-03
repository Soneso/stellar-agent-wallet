# tests/policy-fixtures — adversarial policy fixtures and proptest inputs

Per research implementation plan §4 Phase 3 acceptance #7.

## Adversarial fixtures

`adversarial/` subdirectory holds named fixtures per policy-criterion type:

- Per-tx cap boundary values.
- Per-period rollover with clock skew.
- Combinator AND / OR interactions.
- Oracle-staleness-triggers-denial.
- Mutation-by-stale-key (owner rotated out).
- Counterparty lookalike patterns (homoglyph domains, SEP-10 replay).

## Property-based tests

`proptest` harness over the policy evaluator with randomised criteria and transaction payloads. Target: at least 10,000 cases per shrinkable property in CI.

## Mutation testing

`cargo-mutants` runs at Phase 3 closeout and on monthly cadence thereafter; mutation survivors triaged within seven days.

Phase 0 scaffolding — directory is empty.
