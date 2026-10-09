//! OZ on-chain panic discriminant mapping tests.
//!
//! **Note on test placement:** the `augment_with_oz_error_name` function under
//! test is `pub(crate)` in `managers/rules.rs`. Integration tests in `tests/`
//! are compiled as a separate crate and cannot access `pub(crate)` items
//! without either elevating visibility (which would pollute the public API) or
//! a feature-gated re-export (which adds unnecessary surface for a function
//! already exercised in production code paths).
//!
//! Therefore the panic-discriminant mapping tests are implemented as internal
//! `#[cfg(test)]` tests in `src/managers/rules.rs`. This file exists as a
//! required stub so the test inventory remains complete and can be grepped.
//!
//! Run the panic-discriminant tests with:
//!
//! ```text
//! cargo test -p stellar-agent-smart-account augment_with_oz_error
//! ```

// No test code in this file — see src/managers/rules.rs internal #[cfg(test)] block.
