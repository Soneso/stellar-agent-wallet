//! Audited, operator-acknowledged reset of a profile's MPP replay history.

use clap::{ArgGroup, Args};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_mpp::MppAuthorizationStore;

use crate::common::{
    profile_access::{load_profile_reconciled_by_requested_name, profile_access_envelope},
    render,
};

/// Arguments for `stellar-agent profile reset-mpp-state`.
#[derive(Debug, Args)]
#[command(group(ArgGroup::new("profile_target").args(["name", "profile"]).required(true)))]
pub(crate) struct ResetMppStateArgs {
    /// Profile name; supply either NAME or --profile NAME.
    #[arg(value_name = "NAME")]
    pub(crate) name: Option<String>,
    /// Profile name; an alternative to the positional NAME.
    #[arg(long, value_name = "NAME")]
    pub(crate) profile: Option<String>,
    /// Operator reason recorded in the audit row.
    #[arg(long, value_name = "REASON")]
    pub(crate) reason: String,
    /// Acknowledges discarding the profile's MPP replay history.
    #[arg(
        long,
        required = true,
        help = "Discard replay markers for every prepared, authorized, indeterminate and settled charge; a charge settled before the reset is no longer recognized as settled."
    )]
    pub(crate) acknowledge: bool,
}

impl ResetMppStateArgs {
    pub(super) fn profile_name(&self) -> &str {
        self.name
            .as_deref()
            .or(self.profile.as_deref())
            .unwrap_or_default()
    }
}

pub(crate) fn run(args: &ResetMppStateArgs) -> i32 {
    if args.reason.trim().is_empty() {
        render::render_json(&Envelope::<()>::err_raw(
            "validation.reason_empty",
            "--reason must contain non-whitespace text",
        ));
        return 1;
    }

    if !args.acknowledge {
        render::render_json(&Envelope::<()>::err_raw(
            "mpp.reset_acknowledgement_required",
            "MPP state reset requires --acknowledge",
        ));
        return 1;
    }
    let profile_name = args.profile_name();
    let profile = match load_profile_reconciled_by_requested_name(profile_name, None) {
        Ok(profile) => profile,
        Err(error) => {
            render::render_json(&profile_access_envelope(&error, profile_name));
            return 1;
        }
    };
    if let Err(error) = stellar_agent_network::keyring::init_platform_keyring_store() {
        render::render_json(&Envelope::err(&error));
        return 1;
    }
    match MppAuthorizationStore::reset_for_profile(profile_name, &profile, &args.reason) {
        Ok(discarded_generation) => {
            render::render_json(&Envelope::ok(serde_json::json!({
                "profile": profile_name,
                "reset": true,
                "discarded_generation": discarded_generation,
                "reason": args.reason,
            })));
            0
        }
        Err(error) => {
            render::render_json(&Envelope::<()>::err_raw(error.code(), error.message()));
            1
        }
    }
}
