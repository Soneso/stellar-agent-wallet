//! Audited MPP recovery that carries authenticated replay history.

use clap::{ArgGroup, Args};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::profile::ResolvedProfileName;
use stellar_agent_mpp::{MppAuthorizationStore, MppStateReset};

use crate::common::{
    profile_access::{load_profile_reconciled, profile_access_envelope},
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
    /// Acknowledges closing unclaimed charges and discarding unauthenticated history.
    #[arg(
        long,
        required = true,
        help = "Keep the records of the MPP snapshot on disk when it authenticates and close charges not yet committed. A state file rolled back before the reset loses the records written after that snapshot; the result reports a carry the generation counter proves stale. When no snapshot authenticates, every replay marker is discarded, and a charge settled before the reset loses its settled status."
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
    let profile = match load_profile_reconciled(&ResolvedProfileName::from_flag(profile_name)) {
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
    match MppAuthorizationStore::reset_for_profile(
        profile_name,
        &profile,
        stellar_agent_core::audit_log::BindingCheck::Enforce,
        &args.reason,
        crate::commands::mpp::now_unix(),
    ) {
        Ok(outcome) => {
            render::render_json(&Envelope::ok(serde_json::json!({
                "profile": profile_name,
                "reset": true,
                "discarded_generation": outcome.discarded_generation,
                "carried_records": outcome.carried_records,
                "carried_generation": outcome.carried_generation,
                "stale_carry": outcome.stale_carry,
                "warnings": stale_carry_warning(&outcome).into_iter().collect::<Vec<_>>(),
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

/// The one-line warning for a carried snapshot the committed counter proves
/// stale.
fn stale_carry_warning(outcome: &MppStateReset) -> Option<String> {
    if !outcome.stale_carry {
        return None;
    }
    let carried = outcome.carried_generation?;
    let committed = outcome.discarded_generation?;
    Some(format!(
        "carried MPP snapshot generation {carried} is older than committed generation {committed}; records written after it are lost"
    ))
}
