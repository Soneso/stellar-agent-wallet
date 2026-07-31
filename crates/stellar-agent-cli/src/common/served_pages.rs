//! The one place the CLI turns a profile's `[served_pages]` block into the
//! identity its HTTP listeners render.
//!
//! Four commands serve operator-facing pages — `approve serve`, `approve serve
//! --remote`, `approve operator enroll --interactive`, and `credentials
//! add-passkey`. All four resolve the identity here, so a profile that
//! configures a name gets it on every surface and one that configures nothing
//! gets neutral pages everywhere.

use stellar_agent_core::profile::schema::Profile;
use stellar_agent_loopback_http::brand::PageIdentity;

/// The identity `profile`'s served pages announce.
///
/// A profile with no `[served_pages]` block, or one whose `display_name` is
/// absent or empty, yields [`PageIdentity::neutral`]: a plain page title, no
/// name, and no project mark. Absent configuration never falls back to the
/// project's own identity — this wallet is a self-hosted runtime, and a
/// third-party deployment must not serve the project's name and mark as if
/// they were its own.
#[must_use]
pub fn page_identity_for(profile: &Profile) -> PageIdentity {
    profile
        .served_pages
        .as_ref()
        .map_or_else(PageIdentity::neutral, |cfg| {
            PageIdentity::new(cfg.display_name.as_deref(), cfg.show_project_mark)
        })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use stellar_agent_core::profile::schema::{
        MAX_SERVED_PAGE_DISPLAY_NAME_CHARS, ServedPagesConfig,
    };

    use super::*;

    fn profile() -> Profile {
        Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
            .with_profile_name("served-pages")
            .build()
    }

    /// The bound the loader enforces must be the bound the renderer applies,
    /// or a value the loader accepts would still render truncated.
    #[test]
    fn served_page_display_name_bound_matches_the_renderer() {
        assert_eq!(
            MAX_SERVED_PAGE_DISPLAY_NAME_CHARS,
            stellar_agent_loopback_http::brand::MAX_DISPLAY_NAME_CHARS
        );
    }

    #[test]
    fn a_profile_without_the_block_serves_a_neutral_identity() {
        let p = profile();
        assert!(p.served_pages.is_none());
        assert_eq!(page_identity_for(&p), PageIdentity::neutral());
    }

    #[test]
    fn an_empty_display_name_serves_a_neutral_name() {
        let mut p = profile();
        p.served_pages = Some(ServedPagesConfig::new(Some("   ".to_owned()), false));
        assert_eq!(page_identity_for(&p).display_name(), None);
    }

    #[test]
    fn a_configured_block_carries_the_name_and_the_mark_flag() {
        let mut p = profile();
        p.served_pages = Some(ServedPagesConfig::new(Some("Acme Ops".to_owned()), true));
        let identity = page_identity_for(&p);
        assert_eq!(identity.display_name(), Some("Acme Ops"));
        assert!(identity.shows_project_mark());
    }

    /// The mark can be enabled without a name, and a name without the mark.
    #[test]
    fn the_two_inputs_are_independent() {
        let mut p = profile();
        p.served_pages = Some(ServedPagesConfig::new(None, true));
        let identity = page_identity_for(&p);
        assert_eq!(identity.display_name(), None);
        assert!(identity.shows_project_mark());

        p.served_pages = Some(ServedPagesConfig::new(Some("Acme Ops".to_owned()), false));
        let identity = page_identity_for(&p);
        assert_eq!(identity.display_name(), Some("Acme Ops"));
        assert!(!identity.shows_project_mark());
    }
}
