thread_local! {
    static AUTHORING_PHASE: std::cell::Cell<&'static str> = const { std::cell::Cell::new("") };
    static AUTHORING_SEEN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(super) fn observe_authoring(phase: &str, path: &Path) {
    if AUTHORING_PHASE.get() == phase {
        AUTHORING_SEEN.set(true);
        assert_eq!(
            acquire(path).err().map(|failure| failure.0),
            Some("sign_policy.authoring_lock_busy")
        );
    }
}

struct AuthoringWatch;
impl Drop for AuthoringWatch {
    fn drop(&mut self) {
        AUTHORING_PHASE.set("");
    }
}

fn held_through(phase: &'static str) {
    let fixture = Fixture::new();
    AUTHORING_PHASE.set(phase);
    AUTHORING_SEEN.set(false);
    let _watch = AuthoringWatch;
    fixture.run().unwrap();
    assert!(AUTHORING_SEEN.get());
    assert!(acquire(&fixture.path()).is_ok());
}

#[test]
#[serial]
fn enablement_holds_the_guard_through_pin() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    held_through("pin");
}

#[test]
#[serial]
fn enablement_holds_the_guard_through_nonce() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    held_through("nonce");
}

#[test]
#[serial]
fn enablement_holds_the_guard_through_replace() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    held_through("replace");
}

#[test]
#[serial]
fn enablement_takes_the_guard() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fixture = Fixture::new();
    let before = std::fs::read(fixture.path()).unwrap();
    let _guard = acquire(&fixture.path()).unwrap();
    let (code, detail) = fixture.run().unwrap_err();
    assert_eq!(code, "sign_policy.authoring_lock_busy");
    let shown: serde_json::Value = serde_json::from_slice(&fixture.preview.borrow()).unwrap();
    let envelope = serde_json::to_value(failure_envelope(code, detail, Some(&shown))).unwrap();
    assert_eq!(envelope["error"]["details"]["preview"], shown);
    assert_eq!(fixture.pin(), PinState::Absent);
    assert!(get(&fixture.nonce_ref()).is_none());
    assert_eq!(std::fs::read(fixture.path()).unwrap(), before);
}

struct AtPreview<F> {
    action: Option<F>,
    bytes: Vec<u8>,
}

impl<F: FnOnce()> std::io::Write for AtPreview<F> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(action) = self.action.take() {
            action();
        }
        Ok(())
    }
}

fn changed_during_preview(fixture: &Fixture, action: impl FnOnce(), detail: &str) {
    let mut writer = AtPreview {
        action: Some(action),
        bytes: Vec::new(),
    };
    let failure = fixture.run_into(&mut writer).unwrap_err();
    assert_eq!(
        failure,
        ("profile.enable_mainnet_precondition", detail.to_owned())
    );
    let shown: serde_json::Value = serde_json::from_slice(&writer.bytes).unwrap();
    let envelope =
        serde_json::to_value(failure_envelope(failure.0, failure.1, Some(&shown))).unwrap();
    assert_eq!(envelope["error"]["details"]["preview"], shown);
    assert!(!fixture.dir.path().join("audit.jsonl").exists());
    assert!(acquire(&fixture.path()).is_ok());
}

#[test]
#[serial]
fn enablement_refuses_a_changed_body() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fixture = Fixture::new();
    changed_during_preview(
        &fixture,
        || {
            let _guard = acquire(&fixture.path()).unwrap();
            atomic_write_string(&fixture.path(), "changed body").unwrap();
        },
        "policy_file: changed during enablement",
    );
    assert_eq!(
        std::fs::read_to_string(fixture.path()).unwrap(),
        "changed body"
    );
    assert_eq!(fixture.pin(), PinState::Absent);
    assert!(get(&fixture.nonce_ref()).is_none());
}

#[test]
#[serial]
fn enablement_refuses_a_changed_nonce() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fixture = Fixture::new();
    let before = std::fs::read(fixture.path()).unwrap();
    changed_during_preview(
        &fixture,
        || {
            let _guard = acquire(&fixture.path()).unwrap();
            put(&fixture.nonce_ref(), "concurrent-nonce");
        },
        "policy_state: changed during enablement",
    );
    assert_eq!(std::fs::read(fixture.path()).unwrap(), before);
    assert_eq!(fixture.pin(), PinState::Absent);
    assert_eq!(
        get(&fixture.nonce_ref()).as_deref(),
        Some("concurrent-nonce")
    );
}

#[test]
#[serial]
fn enablement_refuses_a_changed_pin() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fixture = Fixture::new();
    let before = std::fs::read(fixture.path()).unwrap();
    changed_during_preview(
        &fixture,
        || {
            let _guard = acquire(&fixture.path()).unwrap();
            fixture.put_pin(9);
        },
        "policy_state: changed during enablement",
    );
    assert_eq!(std::fs::read(fixture.path()).unwrap(), before);
    assert!(matches!(fixture.pin(), PinState::Present(pin) if pin.sequence() == 9));
    assert!(get(&fixture.nonce_ref()).is_none());
}

#[test]
#[serial]
fn enablement_check_takes_no_guard() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let mut fixture = Fixture::new();
    fixture.args.check = true;
    let _guard = acquire(&fixture.path()).unwrap();
    assert!(fixture.run().is_ok());
    assert!(fixture.preview.borrow().is_empty());
}

#[test]
#[serial]
fn enablement_state_takes_no_guard() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let mut fixture = Fixture::new();
    fixture.args.state = true;
    let _guard = acquire(&fixture.path()).unwrap();
    assert_eq!(fixture.run().unwrap()["state"], "absent");
    assert!(fixture.preview.borrow().is_empty());
}

#[test]
#[serial]
fn read_pin_checked_refuses_missing_lock() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fixture = Fixture::new();
    let coordinate = stellar_agent_core::profile::schema::policy_pin_entry_ref(
        &fixture.profile.policy_window_state_key_id,
    );
    put(&coordinate, "pin entry");
    let failure = read_pin_checked("operator", &fixture.profile, &fixture.window).unwrap_err();
    assert_eq!(
        failure,
        ("policy.pin_absent", missing_pin_lock_detail("operator"))
    );
    assert_eq!(
        fixture.listing(),
        vec![
            std::path::PathBuf::from("policy.toml"),
            "profiles".into(),
            "profiles/operator.toml".into()
        ]
    );
}

#[test]
#[serial]
fn read_pin_checked_uses_pin_read_failure() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fixture = Fixture::new();
    fixture.put_pin(1);
    let coordinate = stellar_agent_core::profile::schema::policy_pin_entry_ref(
        &fixture.profile.policy_window_state_key_id,
    );
    put(&coordinate, "invalid pin");
    let error = read_pin_without_creating(&fixture.window, &fixture.profile).unwrap_err();
    assert_eq!(
        read_pin_checked("operator", &fixture.profile, &fixture.window).unwrap_err(),
        pin_read_failure("operator", error)
    );
}

#[test]
#[serial]
fn authoring_nonce_recheck_refuses_concurrent_state() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    use std::sync::atomic::{AtomicUsize, Ordering};
    let profile = Fixture::profile();
    let coordinate = mainnet_enablement_entry_ref(&profile.policy_window_state_key_id);
    let hook_coordinate = coordinate.clone();
    let probes = Arc::new(AtomicUsize::new(0));
    let count = probes.clone();
    keyring_mock::install_with_read_hooks(vec![keyring_mock::ReadHook::new(
        &coordinate.service,
        &coordinate.account,
        Arc::new(move || {
            if count.fetch_add(1, Ordering::SeqCst) == 1 {
                put(&hook_coordinate, "concurrent-nonce");
            }
        }),
    )])
    .unwrap();
    let fixture = Fixture::seeded(profile);
    fixture.sign(&unbound_body(false));
    let before = std::fs::read(fixture.path()).unwrap();
    let failure = fixture.run().unwrap_err();
    assert_eq!(
        failure,
        precondition("policy_state: changed during enablement")
    );
    assert_eq!(probes.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.pin(), PinState::Absent);
    assert_eq!(
        get(&fixture.nonce_ref()).as_deref(),
        Some("concurrent-nonce")
    );
    assert_eq!(std::fs::read(fixture.path()).unwrap(), before);
    assert!(!fixture.dir.path().join("audit.jsonl").exists());
}

fn read_failure_during_preview(fixture: &Fixture, action: impl FnOnce()) -> Failure {
    let mut writer = AtPreview {
        action: Some(action),
        bytes: Vec::new(),
    };
    let failure = fixture.run_into(&mut writer).unwrap_err();
    let shown: serde_json::Value = serde_json::from_slice(&writer.bytes).unwrap();
    let envelope =
        serde_json::to_value(failure_envelope(failure.0, failure.1.clone(), Some(&shown))).unwrap();
    assert_eq!(envelope["error"]["details"]["preview"], shown);
    assert!(!fixture.dir.path().join("audit.jsonl").exists());
    assert!(acquire(&fixture.path()).is_ok());
    failure
}

#[test]
#[serial]
fn authoring_nonce_read_error_keeps_its_detail() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fixture = Fixture::new();
    let before = std::fs::read(fixture.path()).unwrap();
    let coordinate = fixture.nonce_ref();
    let failure = read_failure_during_preview(&fixture, || {
        keyring_mock::inject_no_logon_session(&coordinate.service, &coordinate.account).unwrap();
    });
    assert_eq!(failure, precondition("nonce unreadable"));
    assert_eq!(fixture.pin(), PinState::Absent);
    assert!(get(&coordinate).is_none());
    assert_eq!(std::fs::read(fixture.path()).unwrap(), before);
}

fn fixture_with_optional_nonce(present: bool) -> Fixture {
    let mut fixture = Fixture::new();
    if present {
        fixture.put_pin(1);
        put(&fixture.nonce_ref(), "existing-nonce");
        fixture.args.rotate = true;
    }
    fixture
}

#[test]
#[serial]
fn authoring_busy_state_lock_keeps_its_code() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for present in [false, true] {
        let fixture = fixture_with_optional_nonce(present);
        let before = std::fs::read(fixture.path()).unwrap();
        let pin = fixture.pin();
        let nonce = get(&fixture.nonce_ref());
        let held = RefCell::new(None);
        let failure = read_failure_during_preview(&fixture, || {
            *held.borrow_mut() = Some(
                WindowStoreLock::acquire_for(
                    &fixture.window,
                    &fixture.profile.policy_window_state_key_id,
                )
                .unwrap(),
            );
        });
        assert_eq!(failure.0, "policy.state_lock_busy");
        assert!(!failure.1.contains("changed during enablement"));
        drop(held);
        assert_eq!(fixture.pin(), pin);
        assert_eq!(get(&fixture.nonce_ref()), nonce);
        assert_eq!(std::fs::read(fixture.path()).unwrap(), before);
    }
}

#[test]
#[serial]
fn authoring_unusable_pin_keeps_its_recovery() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for present in [false, true] {
        let fixture = fixture_with_optional_nonce(present);
        let before = std::fs::read(fixture.path()).unwrap();
        let nonce = get(&fixture.nonce_ref());
        let coordinate = stellar_agent_core::profile::schema::policy_pin_entry_ref(
            &fixture.profile.policy_window_state_key_id,
        );
        let failure = read_failure_during_preview(&fixture, || {
            fixture.put_pin(1);
            put(&coordinate, "invalid pin");
        });
        let error = read_pin_without_creating(&fixture.window, &fixture.profile).unwrap_err();
        assert_eq!(failure, pin_read_failure("operator", error));
        assert_eq!(failure.0, "policy.pin_unusable");
        assert!(
            failure
                .1
                .contains("Rerun this command once the keyring is reachable")
        );
        assert_eq!(get(&coordinate).as_deref(), Some("invalid pin"));
        assert_eq!(get(&fixture.nonce_ref()), nonce);
        assert_eq!(std::fs::read(fixture.path()).unwrap(), before);
    }
}

#[test]
#[serial]
fn authoring_policy_read_error_keeps_its_detail() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fixture = Fixture::new();
    let failure = read_failure_during_preview(&fixture, || {
        std::fs::write(fixture.path(), [0xff]).unwrap();
    });
    let error = std::fs::read_to_string(fixture.path()).unwrap_err();
    assert_eq!(failure, precondition(format!("policy_file: {error}")));
    assert_eq!(fixture.pin(), PinState::Absent);
    assert!(get(&fixture.nonce_ref()).is_none());
    assert_eq!(std::fs::read(fixture.path()).unwrap(), [0xff]);
}
