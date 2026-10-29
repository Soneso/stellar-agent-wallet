//! `stellar-agent profile enroll-rpc-credential`: store an RPC provider key
//! in the keyring and name it in the role's provider record.
//!
//! A provider record (`[providers.primary]`, `[providers.secondary]`, or
//! `[providers.oracle]`) can name a keyring `credential` and a `placement`
//! for its endpoint. This command stores the provider's key at that entry,
//! read from a hidden terminal prompt or from standard input. When the record
//! names no entry yet, the command adds the default reference
//! (`stellar-agent-rpc-<profile>` / `<role>`) and the placement to the record
//! and changes nothing else in the profile file.
//!
//! # Order
//!
//! 1. Load and reconcile the profile; the loader checks every provider record.
//! 2. Require the role's endpoint URL and record.
//! 3. Choose the reference (the record's, else the default) and the placement
//!    (the record's, else the flag; a flag must equal the record's), then run
//!    the loader's credential checks on that record against the role's merged
//!    URL. A refusal leaves the file and the keyring unchanged.
//! 4. Register the keyring store.
//! 5. Refuse an existing entry without `--force`, before any input is read.
//! 6. Read the value and apply the value rules.
//! 7. Add the reference and the placement to the record when it had none.
//!    This precedes the keyring write: when the write fails, a rerun finds
//!    the reference and retries the write.
//! 8. Write the keyring entry.
//! 9. Record a `keyring_key_written` audit row, best effort.
//!
//! # Secret handling
//!
//! The value lives in [`Zeroizing`] holders from the read to the keyring
//! write. From standard input it is read into a fixed buffer of
//! [`MAX_INPUT_BYTES`] plus one byte and copied into a string allocated once
//! with room for the longest accepted input, so the read never reallocates.
//! Neither the value nor its length reaches the output, a log line, or the
//! audit row.
//!
//! # Output (JSON envelope)
//!
//! ```json
//! {
//!   "ok": true,
//!   "data": {
//!     "profile": "default",
//!     "role": "primary",
//!     "keyring_service": "stellar-agent-rpc-default",
//!     "keyring_account": "primary",
//!     "placement": { "kind": "header", "name": "X-API-Key" },
//!     "replaced": false,
//!     "record_patched": true
//!   },
//!   "request_id": "..."
//! }
//! ```

use std::io::{IsTerminal as _, Read};
use std::path::PathBuf;

use clap::{ArgGroup, Args, ValueEnum};
use serde::Serialize;
use zeroize::Zeroizing;

use stellar_agent_core::audit_log::KeyPurpose;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{InternalError, NetworkError, WalletError};
use stellar_agent_core::profile::loader::{self, ProfileLoadError, ProfileSaveError};
use stellar_agent_core::profile::schema::{
    KeyringEntryRef, MAX_RPC_CREDENTIAL_BYTES, Profile, ProviderRole, RpcCredentialDefect,
    RpcCredentialPlacement, check_rpc_credential_value,
};
use stellar_agent_network::keyring::{
    init_platform_keyring_store, rpc_credential_present, write_rpc_credential,
};
use uuid::Uuid;

use crate::common::profile_access::{
    injected_profile_load, profile_access_envelope, reconcile_loaded_profile,
};
use crate::common::{render, resolve_profile_name};

use super::audit_emit::emit_keyring_key_written;

/// The most bytes read from standard input: the value limit plus a `\r\n`
/// line end and one byte, so a longer input is known to be too long without
/// decoding it.
pub(crate) const MAX_INPUT_BYTES: usize = MAX_RPC_CREDENTIAL_BYTES + 3;

/// The RPC role whose provider record and credential the command sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum RoleArg {
    /// The endpoint of `rpc_url`.
    Primary,
    /// The endpoint of `secondary_rpc_url`.
    Secondary,
    /// The endpoint of `oracle_provider_url`.
    Oracle,
}

impl From<RoleArg> for ProviderRole {
    fn from(role: RoleArg) -> Self {
        match role {
            RoleArg::Primary => Self::Primary,
            RoleArg::Secondary => Self::Secondary,
            RoleArg::Oracle => Self::Oracle,
        }
    }
}

/// Arguments for `stellar-agent profile enroll-rpc-credential`.
#[derive(Debug, Args)]
#[command(group(ArgGroup::new("placement").args(["header", "query", "path"])))]
#[non_exhaustive]
pub(crate) struct EnrollRpcCredentialArgs {
    /// Profile whose provider credential is stored.
    ///
    /// Defaults to the `STELLAR_AGENT_PROFILE` env var, then `"default"`.
    #[arg(long = "profile", value_name = "NAME")]
    pub(crate) profile: Option<String>,

    /// The RPC role: `primary`, `secondary`, or `oracle`.
    #[arg(long, value_enum)]
    pub(crate) role: RoleArg,

    /// Send the credential as the value of this request header.
    #[arg(long, value_name = "NAME")]
    pub(crate) header: Option<String>,

    /// Send the credential as this query parameter.
    #[arg(long, value_name = "NAME")]
    pub(crate) query: Option<String>,

    /// Send the credential as the last segment of the URL path.
    #[arg(long, default_value_t = false)]
    pub(crate) path: bool,

    /// Read the credential from standard input instead of a hidden prompt.
    #[arg(long, default_value_t = false)]
    pub(crate) stdin: bool,

    /// Replace a credential already stored at the entry.
    #[arg(long, default_value_t = false)]
    pub(crate) force: bool,
}

impl EnrollRpcCredentialArgs {
    /// The placement the flags name, if any.
    fn flag_placement(&self) -> Option<RpcCredentialPlacement> {
        if let Some(name) = &self.header {
            Some(RpcCredentialPlacement::Header { name: name.clone() })
        } else if let Some(name) = &self.query {
            Some(RpcCredentialPlacement::Query { name: name.clone() })
        } else if self.path {
            Some(RpcCredentialPlacement::Path {})
        } else {
            None
        }
    }
}

/// Success payload for the `enroll-rpc-credential` envelope.
#[derive(Debug, Serialize)]
struct EnrollRpcCredentialData {
    /// Name of the profile.
    profile: String,
    /// The RPC role.
    role: &'static str,
    /// Keyring service the credential was written to.
    keyring_service: String,
    /// Keyring account the credential was written to.
    keyring_account: String,
    /// Where requests carry the credential.
    placement: RpcCredentialPlacement,
    /// `true` when a stored credential was replaced (`--force`).
    replaced: bool,
    /// `true` when this run added the reference and the placement to the
    /// provider record.
    record_patched: bool,
}

/// Where the credential value comes from.
pub(crate) enum ValueSource<'a> {
    /// `--stdin`: the given reader.
    Stdin(&'a mut dyn Read),
    /// The hidden terminal prompt.
    Terminal {
        /// Whether standard input is a terminal.
        is_terminal: bool,
        /// Reads one line from the terminal without echo.
        read_hidden: &'a dyn Fn() -> std::io::Result<String>,
    },
}

/// Runs `stellar-agent profile enroll-rpc-credential`.
///
/// Returns `0` on success, `1` on any refusal.
pub(crate) fn run(args: &EnrollRpcCredentialArgs) -> i32 {
    let stdin = std::io::stdin();
    let is_terminal = stdin.is_terminal();
    let mut locked = stdin.lock();
    let source = if args.stdin {
        ValueSource::Stdin(&mut locked)
    } else {
        ValueSource::Terminal {
            is_terminal,
            read_hidden: &read_hidden_line,
        }
    };
    run_with_dependencies(
        args,
        injected_profile_load,
        loader::check_provider_credential_for_write,
        loader::set_provider_credential,
        init_platform_keyring_store,
        source,
        &mut std::io::stdout(),
    )
}

/// Writes the prompt to standard error and reads one terminal line without
/// echo.
#[allow(
    clippy::print_stderr,
    reason = "the prompt belongs on standard error so standard output stays the JSON envelope"
)]
fn read_hidden_line() -> std::io::Result<String> {
    eprint!("RPC credential: ");
    rpassword::read_password()
}

/// The command with profile access, the write check, the record patch, the
/// keyring registration, the value source, and the output injected.
pub(crate) fn run_with_dependencies<LoadProfile, CheckWrite, PatchRecord, InitKeyring>(
    args: &EnrollRpcCredentialArgs,
    load_profile: LoadProfile,
    check_write: CheckWrite,
    patch_record: PatchRecord,
    init_keyring: InitKeyring,
    source: ValueSource<'_>,
    out: &mut dyn std::io::Write,
) -> i32
where
    LoadProfile: Fn(&str) -> Result<Profile, ProfileLoadError>,
    CheckWrite: Fn(
        &str,
        &Profile,
        ProviderRole,
        &KeyringEntryRef,
        &RpcCredentialPlacement,
    ) -> Result<(), ProfileLoadError>,
    PatchRecord: Fn(
        &str,
        ProviderRole,
        &KeyringEntryRef,
        &RpcCredentialPlacement,
    ) -> Result<PathBuf, ProfileSaveError>,
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    let resolved = resolve_profile_name(args.profile.as_deref());
    let name = resolved.name.clone();
    let role = ProviderRole::from(args.role);
    let refuse = |out: &mut dyn std::io::Write, code: &str, message: String| {
        render::write_envelope(out, &Envelope::<()>::err_raw(code, message), 1)
    };

    // 1. Load and reconcile; the loader validates every provider record.
    let profile = match reconcile_loaded_profile(load_profile(&name), &resolved) {
        Ok(profile) => profile,
        Err(e) => return render::write_envelope(out, &profile_access_envelope(&e, &name), 1),
    };

    // 2. The role's URL and record.
    let record = profile
        .role_url(role)
        .and(profile.providers.as_ref())
        .and_then(|providers| providers.record_for(role));
    let Some(record) = record else {
        return refuse(
            out,
            "enroll_rpc_credential.record_missing",
            format!(
                "profile '{name}' has no `{}` with a [{}] record; set `{}` and add \
                 [{}] with operator and host to the profile file first",
                role.url_field(),
                role.record_field(),
                role.url_field(),
                role.record_field()
            ),
        );
    };

    // 3. Reference and placement, then the loader's checks on that record.
    let entry = record
        .credential
        .cloned()
        .unwrap_or_else(|| KeyringEntryRef::default_rpc_credential(&name, role));
    if let Err(e) = stellar_agent_core::profile::owner_key::refuse_installation_key_coordinate(
        &entry,
        match args.role {
            RoleArg::Primary => "providers.primary.credential",
            RoleArg::Secondary => "providers.secondary.credential",
            RoleArg::Oracle => "providers.oracle.credential",
        },
    ) {
        return render::write_envelope(out, &Envelope::<()>::err(&e), 1);
    }
    let placement = match (record.placement, args.flag_placement()) {
        (Some(stored), Some(flag)) if *stored != flag => {
            return refuse(
                out,
                "enroll_rpc_credential.placement_mismatch",
                format!(
                    "the placement flag differs from the placement [{}] names; pass that \
                     placement or no placement flag",
                    role.record_field()
                ),
            );
        }
        (Some(stored), _) => stored.clone(),
        (None, Some(flag)) => flag,
        (None, None) => {
            return refuse(
                out,
                "enroll_rpc_credential.placement_required",
                format!(
                    "[{}] names no placement; pass --header NAME, --query NAME, or --path",
                    role.record_field()
                ),
            );
        }
    };
    if let Err(e) = check_write(&name, &profile, role, &entry, &placement) {
        let error = WalletError::Validation(e.to_validation_error(&name));
        return render::write_envelope(out, &Envelope::<()>::err(&error), 1);
    }
    let record_patched = record.credential.is_none();

    // 4. Keyring store.
    if let Err(e) = init_keyring() {
        return render::write_envelope(out, &Envelope::<()>::err(&e), 1);
    }

    // 5. An existing entry refuses without --force, before any input.
    let replaced = match rpc_credential_present(&entry) {
        Ok(present) => present,
        Err(e) => return render::write_envelope(out, &Envelope::<()>::err(&e), 1),
    };
    if replaced && !args.force {
        return refuse(
            out,
            "enroll_rpc_credential.entry_exists",
            format!(
                "an RPC credential is already stored at keyring service '{}' account '{}'; \
                 pass --force to replace it",
                entry.service, entry.account
            ),
        );
    }

    // 6. The value.
    let value = match read_value(source, &entry) {
        Ok(value) => value,
        Err(ReadFailure::Refused(error)) => {
            return render::write_envelope(out, &Envelope::<()>::err(&error), 1);
        }
        Err(ReadFailure::Raw { code, message }) => return refuse(out, code, message.to_owned()),
    };

    // 7. The record gains the reference before the keyring write.
    if record_patched && let Err(e) = patch_record(&name, role, &entry, &placement) {
        let error = WalletError::Internal(InternalError::UnexpectedState {
            detail: format!(
                "failed to add the credential reference to [{}] of profile '{name}': {e}",
                role.record_field()
            ),
        });
        return render::write_envelope(out, &Envelope::<()>::err(&error), 1);
    }

    // 8. The keyring write.
    let written = write_rpc_credential(&entry, &value);
    drop(value);
    if let Err(e) = written {
        tracing::debug!("enroll-rpc-credential: keyring write failed");
        return render::write_envelope(out, &Envelope::<()>::err(&e), 1);
    }

    // 9. Best-effort audit row.
    let request_id = Uuid::new_v4().to_string();
    emit_keyring_key_written(
        &profile,
        &name,
        "profile_enroll_rpc_credential",
        KeyPurpose::RpcCredential,
        &entry,
        None,
        &request_id,
    );
    tracing::info!("RPC credential enrolled for profile '{name}'");
    render::write_envelope(
        out,
        &Envelope::ok(EnrollRpcCredentialData {
            profile: name.clone(),
            role: role.as_str(),
            keyring_service: entry.service.clone(),
            keyring_account: entry.account.clone(),
            placement,
            replaced,
            record_patched,
        }),
        0,
    )
}

/// Why no value was read.
enum ReadFailure {
    /// The value breaks a value rule.
    Refused(WalletError),
    /// The input could not be read.
    Raw {
        code: &'static str,
        message: &'static str,
    },
}

/// Reads the credential value from `source` and applies the value rules,
/// reporting a refused value under the label of `entry`.
fn read_value(
    source: ValueSource<'_>,
    entry: &KeyringEntryRef,
) -> Result<Zeroizing<String>, ReadFailure> {
    let refused = |reason| {
        ReadFailure::Refused(WalletError::Network(NetworkError::RpcCredentialInvalid {
            entry: format!("{}/{}", entry.service, entry.account),
            reason,
        }))
    };
    let unreadable = |message| ReadFailure::Raw {
        code: "enroll_rpc_credential.input_unreadable",
        message,
    };
    let value = match source {
        ValueSource::Stdin(reader) => {
            let mut buffer = Zeroizing::new([0u8; MAX_INPUT_BYTES + 1]);
            let mut filled = 0;
            while filled < buffer.len() {
                match reader.read(&mut buffer[filled..]) {
                    Ok(0) => break,
                    Ok(read) => filled += read,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => return Err(unreadable("standard input could not be read")),
                }
            }
            if filled > MAX_INPUT_BYTES {
                return Err(refused(RpcCredentialDefect::TooLong));
            }
            let mut bytes = &buffer[..filled];
            if let Some(rest) = bytes.strip_suffix(b"\n") {
                bytes = rest.strip_suffix(b"\r").unwrap_or(rest);
            }
            if bytes.len() > MAX_RPC_CREDENTIAL_BYTES {
                return Err(refused(RpcCredentialDefect::TooLong));
            }
            let text = std::str::from_utf8(bytes)
                .map_err(|_| unreadable("the credential on standard input is not UTF-8 text"))?;
            let mut value = Zeroizing::new(String::with_capacity(MAX_INPUT_BYTES));
            value.push_str(text);
            value
        }
        ValueSource::Terminal {
            is_terminal,
            read_hidden,
        } => {
            if !is_terminal {
                return Err(ReadFailure::Raw {
                    code: "enroll_rpc_credential.terminal_required",
                    message: "standard input is not a terminal; pass --stdin to read the \
                              credential from standard input",
                });
            }
            Zeroizing::new(
                read_hidden().map_err(|_| unreadable("the terminal input could not be read"))?,
            )
        }
    };
    check_rpc_credential_value(&value).map_err(refused)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only assertions"
    )]

    use std::io::Cursor;
    use std::path::Path;

    use serial_test::serial;
    use stellar_agent_core::profile::schema::PrimaryProviderRecord;
    use stellar_agent_network::keyring::read_rpc_credential;
    use stellar_agent_test_support::keyring_mock;

    use super::*;

    const NAME: &str = "p";
    const SENTINEL: &str = "SENTINEL-k3y value";

    fn args(role: RoleArg, flag: Option<RpcCredentialPlacement>) -> EnrollRpcCredentialArgs {
        let mut args = EnrollRpcCredentialArgs {
            profile: Some(NAME.to_owned()),
            role,
            header: None,
            query: None,
            path: false,
            stdin: true,
            force: false,
        };
        match flag {
            Some(RpcCredentialPlacement::Header { name }) => args.header = Some(name),
            Some(RpcCredentialPlacement::Query { name }) => args.query = Some(name),
            Some(_) => args.path = true,
            None => {}
        }
        args
    }

    fn header(name: &str) -> RpcCredentialPlacement {
        RpcCredentialPlacement::Header {
            name: name.to_owned(),
        }
    }

    /// A testnet profile named [`NAME`] on `rpc_url` with a primary record
    /// and no credential, edited by `edit`, saved under `dir`.
    fn save_profile(dir: &Path, rpc_url: &str, edit: impl FnOnce(&mut Profile)) {
        let mut profile = Profile::builder_testnet_named(NAME, "s", "a", "n", "a")
            .rpc_url(rpc_url)
            .primary_provider(PrimaryProviderRecord::new("Primary", "rpc.example"))
            .build();
        edit(&mut profile);
        loader::save_to_dir(NAME, &profile, dir).unwrap();
    }

    fn profile_text(dir: &Path) -> String {
        std::fs::read_to_string(dir.join(format!("{NAME}.toml"))).unwrap()
    }

    fn default_entry() -> KeyringEntryRef {
        KeyringEntryRef::default_rpc_credential(NAME, ProviderRole::Primary)
    }

    /// Runs the command against the profile under `dir` with the real loader
    /// functions, the given source, and the mock keyring.
    fn run_in(
        dir: &Path,
        args: &EnrollRpcCredentialArgs,
        source: ValueSource<'_>,
    ) -> (i32, String) {
        let mut out = Vec::new();
        let code = run_with_dependencies(
            args,
            |name| loader::load_from_dir(name, dir, None),
            |name, profile, role, entry, placement| {
                loader::check_provider_credential_for_write_in_dir(
                    name, dir, profile, role, entry, placement,
                )
            },
            |name, role, entry, placement| {
                loader::set_provider_credential_on_disk(name, dir, role, entry, placement)
            },
            || Ok(()),
            source,
            &mut out,
        );
        (code, String::from_utf8(out).unwrap())
    }

    fn run_stdin(dir: &Path, args: &EnrollRpcCredentialArgs, input: &[u8]) -> (i32, String) {
        run_in(
            dir,
            args,
            ValueSource::Stdin(&mut Cursor::new(input.to_vec())),
        )
    }

    fn error_code(output: &str) -> String {
        let value: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        value["error"]["code"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }

    fn stored() -> Option<String> {
        read_rpc_credential(&default_entry())
            .ok()
            .map(|value| value.as_str().to_owned())
    }

    #[test]
    #[serial]
    fn enroll_rpc_credential_stores_the_value_and_patches_the_record() {
        keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        save_profile(dir.path(), "https://rpc.example/v1", |_| {});
        let (code, output) = run_stdin(
            dir.path(),
            &args(RoleArg::Primary, Some(header("X-API-Key"))),
            format!("{SENTINEL}\r\n").as_bytes(),
        );
        assert_eq!(code, 0, "{output}");
        assert!(!output.contains("SENTINEL"), "{output}");
        let data: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(
            data["data"],
            serde_json::json!({
                "profile": NAME,
                "role": "primary",
                "keyring_service": "stellar-agent-rpc-p",
                "keyring_account": "primary",
                "placement": {"kind": "header", "name": "X-API-Key"},
                "replaced": false,
                "record_patched": true
            })
        );
        assert_eq!(stored().as_deref(), Some(SENTINEL));
        let loaded = loader::load_from_dir(NAME, dir.path(), None).unwrap();
        assert_eq!(
            loaded.providers.unwrap().credential(ProviderRole::Primary),
            Some((&default_entry(), &header("X-API-Key")))
        );

        let before = profile_text(dir.path());
        let (code, output) = run_stdin(dir.path(), &args(RoleArg::Primary, None), b"other\n");
        assert_eq!(code, 1);
        assert_eq!(error_code(&output), "enroll_rpc_credential.entry_exists");
        assert_eq!(stored().as_deref(), Some(SENTINEL));

        let mut forced = args(RoleArg::Primary, Some(header("X-API-Key")));
        forced.force = true;
        let (code, output) = run_stdin(dir.path(), &forced, b"replacement");
        assert_eq!(code, 0, "{output}");
        let data: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(data["data"]["replaced"], true);
        assert_eq!(data["data"]["record_patched"], false);
        assert_eq!(stored().as_deref(), Some("replacement"));
        assert_eq!(profile_text(dir.path()), before);
    }

    /// The record gains the reference before the keyring write: a failed
    /// write leaves the record patched, and a rerun writes the value.
    #[test]
    #[serial]
    fn enroll_rpc_credential_patches_before_writing() {
        let entry = default_entry();
        keyring_mock::install_with_write_error(
            &entry.service,
            &entry.account,
            None,
            keyring_core::Error::PlatformFailure(Box::new(std::io::Error::other("write"))),
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        save_profile(dir.path(), "https://rpc.example", |_| {});
        let (code, output) = run_stdin(
            dir.path(),
            &args(RoleArg::Primary, Some(RpcCredentialPlacement::Path {})),
            b"value",
        );
        assert_eq!(code, 1, "{output}");
        assert_eq!(error_code(&output), "auth.keyring_platform_error");
        let loaded = loader::load_from_dir(NAME, dir.path(), None).unwrap();
        assert_eq!(
            loaded.providers.unwrap().credential(ProviderRole::Primary),
            Some((&entry, &RpcCredentialPlacement::Path {}))
        );
        assert_eq!(stored(), None);

        let (code, output) = run_stdin(dir.path(), &args(RoleArg::Primary, None), b"value");
        assert_eq!(code, 0, "{output}");
        let data: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(data["data"]["record_patched"], false);
        assert_eq!(stored().as_deref(), Some("value"));
    }

    /// The input limit applies to the raw bytes before decoding; one trailing
    /// line end is removed; an exactly 1024-byte value is stored whole.
    #[test]
    #[serial]
    fn stdin_input_rules_apply_before_decoding() {
        let exact = "k".repeat(1024);
        let exact_lf = format!("{exact}\n");
        let exact_crlf = format!("{exact}\r\n");
        let over = format!("{exact}k");
        let mut cut = vec![b'a'; 1026];
        cut.push(0xC3);
        let mut long_cut = vec![b'a'; 1026];
        long_cut.extend("\u{e9}".repeat(40).as_bytes());
        let cases: [(&[u8], Result<&str, &str>); 9] = [
            (exact_lf.as_bytes(), Ok(exact.as_str())),
            (exact_crlf.as_bytes(), Ok(exact.as_str())),
            (b"Bearer abc\r\n", Ok("Bearer abc")),
            (over.as_bytes(), Err("network.rpc_credential_refused")),
            (&cut, Err("network.rpc_credential_refused")),
            (&long_cut, Err("network.rpc_credential_refused")),
            (b"abc\n\n", Err("network.rpc_credential_refused")),
            (b"\xff\xfe\n", Err("enroll_rpc_credential.input_unreadable")),
            (b"\n", Err("network.rpc_credential_refused")),
        ];
        for (input, expected) in cases {
            keyring_mock::install().unwrap();
            let dir = tempfile::tempdir().unwrap();
            save_profile(dir.path(), "https://rpc.example", |_| {});
            let before = profile_text(dir.path());
            let (code, output) = run_stdin(
                dir.path(),
                &args(RoleArg::Primary, Some(header("X-Key"))),
                input,
            );
            match expected {
                Ok(value) => {
                    assert_eq!(code, 0, "{output}");
                    assert_eq!(stored().as_deref(), Some(value));
                }
                Err(expected_code) => {
                    assert_eq!(code, 1, "{output}");
                    assert_eq!(error_code(&output), expected_code, "{output}");
                    assert_eq!(stored(), None);
                    assert_eq!(profile_text(dir.path()), before, "the file stays unchanged");
                }
            }
        }
    }

    /// Without `--stdin` the value comes from the hidden prompt, which needs
    /// a terminal on standard input.
    #[test]
    #[serial]
    fn enroll_rpc_credential_requires_a_terminal_without_stdin() {
        keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        save_profile(dir.path(), "https://rpc.example", |_| {});
        let before = profile_text(dir.path());
        let mut prompt_args = args(RoleArg::Primary, Some(header("X-Key")));
        prompt_args.stdin = false;
        let never = || -> std::io::Result<String> { panic!("no prompt without a terminal") };
        let (code, output) = run_in(
            dir.path(),
            &prompt_args,
            ValueSource::Terminal {
                is_terminal: false,
                read_hidden: &never,
            },
        );
        assert_eq!(code, 1);
        assert_eq!(
            error_code(&output),
            "enroll_rpc_credential.terminal_required"
        );
        assert_eq!(profile_text(dir.path()), before);
        assert_eq!(stored(), None);

        let typed = || Ok(SENTINEL.to_owned());
        let (code, output) = run_in(
            dir.path(),
            &prompt_args,
            ValueSource::Terminal {
                is_terminal: true,
                read_hidden: &typed,
            },
        );
        assert_eq!(code, 0, "{output}");
        assert!(!output.contains("SENTINEL"));
        assert_eq!(stored().as_deref(), Some(SENTINEL));
    }

    #[test]
    #[serial]
    fn enroll_rpc_credential_refuses_without_record() {
        keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        save_profile(dir.path(), "https://rpc.example", |profile| {
            profile.providers = None;
        });
        let before = profile_text(dir.path());
        for role in [RoleArg::Primary, RoleArg::Secondary, RoleArg::Oracle] {
            let (code, output) = run_stdin(dir.path(), &args(role, Some(header("X"))), b"v");
            assert_eq!(code, 1);
            assert_eq!(error_code(&output), "enroll_rpc_credential.record_missing");
        }
        assert_eq!(profile_text(dir.path()), before);
        assert_eq!(stored(), None);
    }

    #[test]
    #[serial]
    fn enroll_rpc_credential_requires_or_matches_placement() {
        keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        save_profile(dir.path(), "https://rpc.example", |profile| {
            profile.providers.as_mut().unwrap().primary = Some(
                PrimaryProviderRecord::new("Primary", "rpc.example")
                    .with_credential(default_entry(), header("X-Key")),
            );
        });
        let (code, output) = run_stdin(
            dir.path(),
            &args(
                RoleArg::Primary,
                Some(RpcCredentialPlacement::Query {
                    name: "apikey".to_owned(),
                }),
            ),
            b"v",
        );
        assert_eq!(code, 1);
        assert_eq!(
            error_code(&output),
            "enroll_rpc_credential.placement_mismatch"
        );
        assert_eq!(stored(), None);
        let (code, output) = run_stdin(
            dir.path(),
            &args(RoleArg::Primary, Some(header("X-Key"))),
            b"v",
        );
        assert_eq!(code, 0, "{output}");

        let bare = tempfile::tempdir().unwrap();
        save_profile(bare.path(), "https://rpc.example", |_| {});
        let (code, output) = run_stdin(bare.path(), &args(RoleArg::Primary, None), b"v");
        assert_eq!(code, 1);
        assert_eq!(
            error_code(&output),
            "enroll_rpc_credential.placement_required"
        );
        let (code, output) = run_stdin(
            bare.path(),
            &args(RoleArg::Primary, Some(header("Host"))),
            b"v",
        );
        assert_eq!(code, 1);
        assert_eq!(
            error_code(&output),
            "validation.provider_attestation_invalid"
        );
    }

    /// An endpoint URL, a placement flag, a profile edit, and the refused
    /// field.
    type PrecheckCase = (
        &'static str,
        RpcCredentialPlacement,
        fn(&mut Profile),
        &'static str,
    );

    /// The loader's credential checks run on the record about to be written:
    /// a refusal leaves the file and the keyring unchanged.
    #[test]
    #[serial]
    fn enroll_rpc_credential_runs_the_loader_checks_first() {
        let cases: [PrecheckCase; 4] = [
            (
                "https://rpc.example",
                header("X-Key"),
                |profile| {
                    profile.audit_log_hash_chain_key_id =
                        KeyringEntryRef::new("stellar-agent-rpc-p", "default");
                },
                "providers.primary.credential",
            ),
            (
                "http://rpc.example:8000",
                header("X-Key"),
                |_| {},
                "rpc_url",
            ),
            (
                "https://user@rpc.example",
                header("X-Key"),
                |_| {},
                "rpc_url",
            ),
            (
                "https://rpc.example/?apikey=old",
                RpcCredentialPlacement::Query {
                    name: "apikey".to_owned(),
                },
                |_| {},
                "providers.primary.placement.name",
            ),
        ];
        for (url, placement, edit, field) in cases {
            keyring_mock::install().unwrap();
            let dir = tempfile::tempdir().unwrap();
            save_profile(dir.path(), url, edit);
            let before = profile_text(dir.path());
            let (code, output) = run_stdin(
                dir.path(),
                &args(RoleArg::Primary, Some(placement)),
                b"value",
            );
            assert_eq!(code, 1, "{url}: {output}");
            assert_eq!(
                error_code(&output),
                "validation.provider_attestation_invalid"
            );
            assert!(output.contains(field), "{url}: {output}");
            assert_eq!(profile_text(dir.path()), before);
            assert_eq!(stored(), None);
        }
    }

    /// Provider enrollment refuses installation coordinates before checking writes or opening keys.
    #[test]
    #[serial]
    fn installation_coordinate_refuses_without_writing() {
        use crate::common::installation_key_fixture::InstallationKeyFixture;
        let fixture = InstallationKeyFixture::new("stellar-agent-toolsets");
        let profile = Profile::builder_testnet_named(NAME, "s", "a", "n", "a")
            .rpc_url("https://rpc.example")
            .primary_provider(
                PrimaryProviderRecord::new("Primary", "rpc.example")
                    .with_credential(fixture.coordinate.clone(), header("X-Key")),
            )
            .build();
        let mut output = Vec::new();
        let code = run_with_dependencies(
            &args(RoleArg::Primary, None),
            |_| Ok(profile.clone()),
            |_, _, _, _, _| panic!("refusal precedes the write check"),
            |_, _, _, _| panic!("refusal precedes the profile patch"),
            || fixture.init(),
            ValueSource::Stdin(&mut Cursor::new(b"unused")),
            &mut output,
        );
        fixture.assert_refused(code);
        let output: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(
            output["error"]["code"],
            "validation.installation_key_coordinate"
        );
    }
}
