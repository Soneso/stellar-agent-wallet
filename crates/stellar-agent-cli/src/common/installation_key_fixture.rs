//! Shared CLI fixtures for reserved installation-key refusals.

use stellar_agent_core::{
    error::WalletError,
    profile::schema::{KeyringEntryRef, Profile},
};

/// Mock installation key and initialization spy for profile-write refusals.
pub(crate) struct InstallationKeyFixture {
    pub(crate) coordinate: KeyringEntryRef,
    init_calls: std::cell::Cell<u32>,
    entry: keyring_core::Entry,
    expected_value: String,
    _home: stellar_agent_test_support::StellarAgentHomeGuard,
    dir: tempfile::TempDir,
}

#[allow(clippy::unwrap_used, reason = "test-only fixture assertions")]
impl InstallationKeyFixture {
    pub(crate) fn new(service: &str) -> Self {
        crate::common::render::take_rendered_for_test();
        let dir = tempfile::tempdir().unwrap();
        let home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let mut coordinate = KeyringEntryRef::toolset_pin_key();
        coordinate.service = service.to_owned();
        let entry = keyring_core::Entry::new(&coordinate.service, &coordinate.account).unwrap();
        let expected_value = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            [0x5a; 32],
        );
        entry.set_password(&expected_value).unwrap();
        Self {
            coordinate,
            init_calls: std::cell::Cell::new(0),
            entry,
            expected_value,
            _home: home,
            dir,
        }
    }

    pub(crate) fn init(&self) -> Result<(), WalletError> {
        self.init_calls.set(self.init_calls.get() + 1);
        Ok(())
    }

    pub(crate) fn home(&self) -> &std::path::Path {
        self.dir.path()
    }

    pub(crate) fn assert_rendered_refusal(&self, code: i32) {
        self.assert_refused(code);
        let rendered = crate::common::render::take_rendered_for_test();
        assert_eq!(rendered.len(), 1);
        assert_eq!(
            rendered[0]["error"]["code"],
            "validation.installation_key_coordinate"
        );
    }

    pub(crate) fn assert_refused(&self, code: i32) {
        assert_eq!(code, 1);
        assert_eq!(self.init_calls.get(), 0, "the refusal precedes the keyring");
        assert!(
            self.entry.get_password().unwrap() == self.expected_value,
            "the installation key stays unchanged"
        );
    }
}

/// Checks both service spellings, the envelope code, and the unchanged key.
pub(crate) async fn assert_installation_profile_refusal(
    coordinate: fn(&mut Profile) -> &mut KeyringEntryRef,
    run: impl AsyncFn(&InstallationKeyFixture, Profile, &'static str) -> i32,
) {
    for service in ["stellar-agent-toolsets", "StElLaR-AgEnT-ToOlSeTs"] {
        let fixture = InstallationKeyFixture::new(service);
        let name = "pin-coordinate-refusal";
        let mut profile = Profile::builder_testnet_named(name, "s", "a", "n", "a").build();
        *coordinate(&mut profile) = fixture.coordinate.clone();
        let code = run(&fixture, profile, name).await;
        fixture.assert_rendered_refusal(code);
    }
}
