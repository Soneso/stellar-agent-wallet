//! Checked accounting facts for signing admission.

use super::criteria::{WindowEntry, WindowLimit};
use crate::policy::{DenyReason, PolicyError};

/// The value evidence for sizing a call.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SizingBasis {
    /// Authenticated value effects or a bundle view determine the entries.
    MeasuredValue,
    /// The call has no value leg and takes count charges only.
    NoValue,
    /// Value rules permit the unvalued call, which takes count charges only.
    Unvalued,
    /// No matching rule holds a windowed criterion.
    NoApplicableLimit,
}

/// Accounting entries certified by a policy engine.
#[derive(Clone, Debug)]
pub struct CheckedSizing {
    basis: SizingBasis,
    entries: Vec<WindowEntry>,
}

impl CheckedSizing {
    pub(crate) fn new(basis: SizingBasis, entries: Vec<WindowEntry>) -> Result<Self, PolicyError> {
        let valid = match basis {
            SizingBasis::NoApplicableLimit => entries.is_empty(),
            SizingBasis::NoValue | SizingBasis::Unvalued => entries
                .iter()
                .all(|entry| matches!(entry.limit(), WindowLimit::Count { .. })),
            SizingBasis::MeasuredValue => true,
        };
        if !valid {
            return Err(PolicyError::CriterionEvaluationFailed {
                detail: "checked sizing entries do not match their basis".into(),
            });
        }
        Ok(Self { basis, entries })
    }

    /// Returns the evidence for sizing the entries.
    #[must_use]
    pub fn basis(&self) -> SizingBasis {
        self.basis
    }

    /// Returns the certified accounting entries.
    #[must_use]
    pub fn entries(&self) -> &[WindowEntry] {
        &self.entries
    }

    /// Constructs checked sizing for a test fixture.
    ///
    /// # Errors
    /// Refuses entries that do not match the sizing basis.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn for_test(basis: SizingBasis, entries: Vec<WindowEntry>) -> Result<Self, PolicyError> {
        Self::new(basis, entries)
    }
}

/// A certified sizing or a policy refusal before admission.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum SizingOutcome {
    /// The policy engine certifies these entries.
    Sized(CheckedSizing),
    /// A value criterion refuses this call.
    Refused(DenyReason),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::v1::criteria::state_store::StateKey;

    #[test]
    fn checked_sizing_refuses_invalid_basis_entries() {
        let entry = WindowEntry::new(
            StateKey::new("test", 1, "native", 60),
            1000,
            5,
            WindowLimit::Amount {
                asset: "native".into(),
                window: "1m".into(),
                max_stroops: 10,
            },
        );
        for basis in [
            SizingBasis::NoApplicableLimit,
            SizingBasis::NoValue,
            SizingBasis::Unvalued,
        ] {
            assert!(matches!(
                CheckedSizing::for_test(basis, vec![entry.clone()]),
                Err(PolicyError::CriterionEvaluationFailed { .. })
            ));
        }
    }
}
