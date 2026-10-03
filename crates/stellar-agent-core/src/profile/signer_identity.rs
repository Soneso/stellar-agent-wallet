//! Enrolled signer identity rules for loaded profiles.

use super::Profile;
use crate::error::AuthError;

/// The validated enrolled signer pin of a mainnet profile; `None` on testnet.
///
/// # Errors
/// Refuses a placeholder or malformed mainnet signer pin.
pub fn enrolled_signer_pin(
    profile_name: &str,
    profile: &Profile,
) -> Result<Option<String>, AuthError> {
    if !profile.chain_id.is_mainnet() {
        return Ok(None);
    }
    let account = &profile.mcp_signer_default.account;
    let reason = if profile.mcp_signer_default.is_signer_placeholder() {
        Some("placeholder")
    } else if stellar_strkey::ed25519::PublicKey::from_string(account).is_err() {
        Some("malformed")
    } else {
        None
    };
    if let Some(reason) = reason {
        return Err(AuthError::EnrolledSignerUnpinned {
            profile: profile_name.to_owned(),
            reason,
        });
    }
    Ok(Some(account.clone()))
}

/// Refuses a signer that is not the profile's enrolled identity on mainnet.
///
/// # Errors
/// Refuses an invalid pin or a derived key that differs from the pin.
pub fn check_enrolled_signer(
    profile_name: &str,
    profile: &Profile,
    derived_g: &str,
) -> Result<(), AuthError> {
    if let Some(enrolled) = enrolled_signer_pin(profile_name, profile)?
        && derived_g != enrolled
    {
        return Err(AuthError::EnrolledSignerMismatch {
            profile: profile_name.to_owned(),
            enrolled,
            derived: derived_g.to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(account: &str) -> Profile {
        Profile::builder_mainnet_named("identity", "s", account, "n", "a").build()
    }

    fn key(byte: u8) -> String {
        stellar_strkey::ed25519::PublicKey([byte; 32])
            .to_string()
            .to_string()
    }

    #[test]
    fn testnet_placeholder_has_no_pin_and_accepts_any_signer() {
        let p = Profile::builder_testnet_named("identity", "s", "default", "n", "a").build();
        assert!(matches!(enrolled_signer_pin("identity", &p), Ok(None)));
        assert!(check_enrolled_signer("identity", &p, "any key").is_ok());
    }

    #[test]
    fn mainnet_placeholder_refuses() {
        assert!(matches!(
            check_enrolled_signer("identity", &profile("default"), &key(1)),
            Err(AuthError::EnrolledSignerUnpinned {
                reason: "placeholder",
                ..
            })
        ));
    }

    #[test]
    fn mainnet_malformed_refuses() {
        assert!(matches!(
            check_enrolled_signer("identity", &profile("invalid"), &key(1)),
            Err(AuthError::EnrolledSignerUnpinned {
                reason: "malformed",
                ..
            })
        ));
    }

    #[test]
    fn mainnet_differing_key_refuses_with_both_keys() {
        let a = key(1);
        let b = key(2);
        let result = check_enrolled_signer("identity", &profile(&a), &b);
        assert!(
            matches!(&result, Err(AuthError::EnrolledSignerMismatch { enrolled, derived, .. }) if enrolled == &a && derived == &b)
        );
        if let Err(error) = result {
            assert!(error.to_string().contains(&a));
            assert!(error.to_string().contains(&b));
        }
    }

    #[test]
    fn mainnet_equal_key_passes() {
        let a = key(1);
        assert!(check_enrolled_signer("identity", &profile(&a), &a).is_ok());
    }
}
