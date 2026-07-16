//! Shared policy value derivation for MPP charge authorization.

use stellar_agent_core::policy::v1::{ActionKind, ValueEffects, ValueLeg};

use crate::SelectedChallenge;

/// Derives the single authoritative value effect used by preview, commit,
/// policy-window accounting, and audit.
#[must_use]
pub fn mpp_value_effects(selected: &SelectedChallenge) -> ValueEffects {
    ValueEffects::single(ValueLeg {
        kind: ActionKind::MppCharge,
        amount: Some(selected.request().amount()),
        asset: Some(selected.request().currency().to_owned()),
        destination: Some(selected.request().recipient().to_owned()),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "test fixture setup")]

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    use super::*;
    use crate::{ChallengeInput, HttpRequestContext, json::canonical_json, select_and_validate};

    #[test]
    fn derives_mpp_charge_from_validated_terms() {
        let request = serde_json::json!({
            "amount": "42",
            "currency": "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA",
            "methodDetails": { "feePayer": true, "network": "stellar:testnet" },
            "recipient": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
        });
        let encoded = URL_SAFE_NO_PAD.encode(canonical_json(&request).expect("canonical"));
        let selected = select_and_validate(
            &ChallengeInput::Http {
                www_authenticate: vec![format!(
                    "Payment id=one, realm=api.example, method=stellar, intent=charge, request={encoded}"
                )],
                selected_challenge_id: None,
                context: HttpRequestContext::new(
                    "https://api.example",
                    "GET",
                    "https://api.example/paid",
                    None,
                    None,
                )
                .expect("context"),
            },
            1_700_000_000,
        )
        .expect("selected");

        let effects = mpp_value_effects(&selected);
        assert_eq!(effects.legs()[0].kind, ActionKind::MppCharge);
        assert_eq!(effects.legs()[0].amount, Some(42));
    }
}
