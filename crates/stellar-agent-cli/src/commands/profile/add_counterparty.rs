//! `stellar-agent profile policy add-counterparty` adds one payment recipient
//! to the policy of a profile.
//!
//! The command reads `<state_dir>/policies/<profile>.toml`. A body without a
//! root `signature` key is a draft; any present `signature` value selects the
//! signed path, whatever its type.
//!
//! # Signed path
//!
//! The body must verify against the enrolled owner key. The command adds the
//! recipient, assigns the next sequence, and repeats every check of
//! `profile sign-policy`. It previews the body it signs on stderr, takes the
//! authoring guard, and checks again that the file, the profile, the pin, and
//! the prepared body are unchanged. It prompts for the owner seed on the
//! terminal and repeats those checks before it signs. It verifies the
//! rendered text and reloads the profile. Under the policy-state lock it
//! compares the pin, re-reads the file, and replaces it once.
//! The lock order is the authoring lock, then the policy-state lock.
//! Without a terminal it refuses; `profile sign-policy` with `--secret-env`
//! covers unattended signing.
//!
//! # Draft path
//!
//! An unsigned body carries no authority, so the command edits it without a
//! seed, a keyring read, a pin read, or a terminal. The edited draft keeps its
//! sequence and gains no `signature`. The next step is `profile sign-policy`.
//!
//! # Output
//!
//! One JSON envelope on stdout. A listed recipient exits `0` with
//! `changed = false` and writes nothing. Before the replace the policy file is
//! unchanged; after it the change is complete. A stdout failure after the
//! replace exits `1`, and the file then holds the change.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::Args;
use serde::Serialize;
use serde_json::Value;
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::WalletError;
use stellar_agent_core::policy::PolicyError;
use stellar_agent_core::policy::pin::{self, PinScope, PinState};
use stellar_agent_core::policy::v1::canonical::canonical_bytes;
use stellar_agent_core::policy::v1::loader::load_signed_policy_text;
use stellar_agent_core::policy::v1::mainnet_minimum::MAINNET_VALUE_OUT_TOOLS;
use stellar_agent_core::policy::v1::presets::{
    AuthorityStatus, RecipientAddition, RecipientEdit, RecipientForm, RecipientListed,
    RecipientRefusal, RuleScope, SpendingSummary, add_payment_recipient, classify_recipient,
    summarize,
};
use stellar_agent_core::policy::v1::signature::digest;
use stellar_agent_core::policy::v1::validate_unsigned_policy;
use stellar_agent_core::profile::loader;
use stellar_agent_core::profile::owner_key::owner_key_fingerprint;
use stellar_agent_core::profile::schema::{
    KeyringEntryRef, Profile, default_policy_dir, default_policy_window_state_path_for,
};
use stellar_agent_core::wallet::MlockRequired;
use toml_edit::DocumentMut;
use zeroize::Zeroizing;

use stellar_agent_core::policy::v1::verified::acquire_state_lock;

use super::policy_authoring::{acquire, pin_read_failure, read_pin_checked};
use super::sign_policy::{
    OwnerReadError, OwnerSignError, PreparedPolicy, atomic_write_string, engine_profile_name,
    prepare_policy, read_owner_pubkey, render_with_signature, sign_with_seed_text, to_hex,
};
use crate::common::profile_access::{
    injected_profile_load, profile_access_envelope, reconcile_loaded_profile,
};
use crate::common::spending_preview::{SpendingPreview, with_shown_preview};
use crate::common::tty::stdin_and_stderr_are_terminals;
use crate::common::{render, resolve_profile_name};

/// The code of a policy file or pin that changed after the preview.
const CHANGED_DURING_EDIT: &str = "profile.policy_changed_during_edit";
/// The code of a signed edit that cannot prompt for the owner seed.
const PROMPT_REQUIRED: &str = "profile.policy_owner_prompt_required";
/// The prompt written to stderr before the hidden seed read.
const SEED_PROMPT: &str = "Policy owner seed (hidden): ";
/// The note for a W recipient, without its `Note: ` prefix.
const W_NOTE: &str =
    "the wallet does not pay W destinations yet; this entry takes effect when it does.";
/// The ambiguity hint when the command line gives `--tool`.
const HINT_WITH_TOOLS: &str = "Add the other payment tools the rule governs with --tool, or run \
                               without --tool to edit with the scope the preview states.";
/// The ambiguity hint when the command line gives no `--tool`.
const HINT_WITHOUT_TOOLS: &str =
    "Select one payment tool with --tool to edit only the lists of its rule.";

/// A refusal code and its message.
type Failure = (&'static str, String);
/// The signed body, the derived key, the signature, and the digest.
type Signed = (String, [u8; 32], [u8; 64], [u8; 32]);

/// Arguments for `stellar-agent profile policy add-counterparty`.
#[derive(Debug, Args)]
pub(crate) struct AddCounterpartyArgs {
    /// Profile whose policy gains the recipient.
    #[arg(long, value_name = "NAME")]
    pub(crate) profile: String,

    /// The G, M, C, or W address to add.
    #[arg(long, value_name = "ADDRESS")]
    recipient: String,

    /// A payment tool whose rule gains the recipient. Repeat it for several
    /// tools; without it every payment tool is selected.
    #[arg(
        long = "tool",
        value_name = "TOOL",
        value_parser = clap::builder::PossibleValuesParser::new(MAINNET_VALUE_OUT_TOOLS.iter().copied())
    )]
    tools: Vec<String>,
}

/// The seams of the command, each replaceable in tests.
struct Dependencies<
    'a,
    LoadProfile,
    InitKeyring,
    IsTerminal,
    ReadPolicy,
    ReadSeed,
    Sign,
    WritePolicy,
> {
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
    is_terminal: IsTerminal,
    /// Serves the first read of the policy file and every re-read.
    read_policy: ReadPolicy,
    read_seed: ReadSeed,
    sign: Sign,
    write_policy: WritePolicy,
    /// Receives the preview, the prompt, and the notes.
    stderr: &'a mut dyn Write,
}

/// Success payload of the envelope.
#[derive(Debug, Serialize)]
struct AddCounterpartyData {
    profile: String,
    recipient: String,
    kind: &'static str,
    changed: bool,
    signed: bool,
    policy_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    covered_by: Option<String>,
    updated_rules: Vec<usize>,
    kinds_added: Vec<usize>,
    split_rules: Vec<usize>,
    edit_scope: Value,
    ungated_tools: Vec<String>,
    denied_tools: Vec<String>,
    spending_summary: SpendingSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination_note: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_steps: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_sequence: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sequence: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    digest: Option<String>,
    warnings: Vec<String>,
}

/// What the common start established.
struct Start {
    form: RecipientForm,
    profile: Profile,
    profile_name: String,
    engine_name: String,
    policy_path: PathBuf,
    window_path: PathBuf,
    raw: String,
    document: DocumentMut,
}

/// Runs `stellar-agent profile policy add-counterparty`.
///
/// Returns `0` on success and on a listed recipient, `1` on a refusal. A
/// stdout failure after the replace exits `1` through the shared renderer.
pub(crate) async fn run(args: &AddCounterpartyArgs) -> i32 {
    let mut stderr = io::stderr();
    run_with(
        args,
        Dependencies {
            load_profile: injected_profile_load,
            init_keyring: stellar_agent_network::keyring::init_platform_keyring_store,
            is_terminal: stdin_and_stderr_are_terminals,
            read_policy: |path: &Path| std::fs::read_to_string(path),
            read_seed: read_owner_seed,
            sign: sign_with_seed_text,
            write_policy: atomic_write_string,
            stderr: &mut stderr,
        },
    )
    .await
}

/// Reads the owner seed from the terminal without echo.
fn read_owner_seed() -> io::Result<Zeroizing<String>> {
    rpassword::read_password().map(Zeroizing::new)
}

/// Renders a refusal, with the preview once one is shown, and returns `1`.
fn refuse(code: &str, message: impl Into<String>, shown: Option<&Value>) -> i32 {
    render_refusal(Envelope::<()>::err_raw(code, message), shown)
}

/// Renders `refusal`, with the preview once one is shown, and returns `1`.
fn render_refusal(refusal: Envelope<()>, shown: Option<&Value>) -> i32 {
    render::render_json(&with_shown_preview(refusal, shown));
    1
}

/// The envelope of a refusal code and message.
fn raw_refusal((code, message): Failure) -> Envelope<()> {
    Envelope::<()>::err_raw(code, message)
}

/// The signed path after its checks.
enum SignedStep {
    /// Every target list covers the recipient.
    Listed(Box<AddCounterpartyData>),
    /// The edit to sign and the state it rests on.
    Edit(Box<SignedEdit>),
}

/// The enrolled owner, the edit, and the pin the preview rests on.
struct SignedEdit {
    enrolled: [u8; 32],
    edited: RecipientAddition,
    pin: PinState,
}

/// The refusal of a file, pin, or profile that differs from the state the
/// preview rests on.
fn changed(detail: &str) -> Envelope<()> {
    Envelope::<()>::err_raw(
        CHANGED_DURING_EDIT,
        format!("{detail}: changed during edit"),
    )
}

/// Reloads the profile and refuses one whose stored fields differ from the
/// profile the preparation, the preview, and the signing use.
///
/// The comparison covers every serialized field, so it covers every profile
/// input of those steps. A load error keeps its own code.
fn recheck_profile(
    load_profile: &impl Fn(&str) -> Result<Profile, loader::ProfileLoadError>,
    args: &AddCounterpartyArgs,
    start: &Start,
) -> Result<(), Envelope<()>> {
    let resolved = resolve_profile_name(Some(&args.profile));
    let fresh = reconcile_loaded_profile(load_profile(&resolved.name), &resolved).map_err(|e| {
        tracing::debug!(error = %e, "profile access refused");
        profile_access_envelope(&e)
    })?;
    match (
        serde_json::to_value(&fresh),
        serde_json::to_value(&start.profile),
    ) {
        (Ok(fresh), Ok(captured)) if fresh == captured => Ok(()),
        _ => Err(changed("profile")),
    }
}

/// A core refusal with its code and text; an ambiguity gains the hint.
fn recipient_failure(refusal: &RecipientRefusal, tools_given: bool) -> Failure {
    let mut text = refusal.to_string();
    if refusal.code() == "profile.policy_counterparty_ambiguous" {
        text.push(' ');
        text.push_str(if tools_given {
            HINT_WITH_TOOLS
        } else {
            HINT_WITHOUT_TOOLS
        });
    }
    (refusal.code(), text)
}

/// One `{"rule", "tools", "wildcard"}` object per edited rule.
fn edit_scope(scope: &[RuleScope]) -> Value {
    Value::Array(
        scope
            .iter()
            .map(|rule| {
                serde_json::json!({
                    "rule": rule.rule,
                    "tools": rule.tools,
                    "wildcard": rule.wildcard,
                })
            })
            .collect(),
    )
}

/// Whether any rule of `document` carries a `total_budget` criterion.
fn has_total_budget(document: &DocumentMut) -> bool {
    document
        .get("rules")
        .and_then(toml_edit::Item::as_array_of_tables)
        .into_iter()
        .flat_map(toml_edit::ArrayOfTables::iter)
        .filter_map(|rule| rule.get("criteria").and_then(toml_edit::Item::as_array))
        .flat_map(toml_edit::Array::iter)
        .filter_map(toml_edit::Value::as_inline_table)
        .any(|criterion| {
            criterion.get("kind").and_then(toml_edit::Value::as_str) == Some("total_budget")
        })
}

/// The refusal of a body below or forking the pin.
fn sequence_failure(
    state: &PinState,
    sequence: i64,
    body_digest: [u8; 32],
    path: &Path,
) -> Option<Failure> {
    let PinState::Present(pin) = state else {
        return None;
    };
    let path = path.display();
    if sequence < pin.sequence() {
        return Some((
            PolicyError::SequenceRollback.wire_code(),
            format!(
                "the sequence of policy file {path} is below the installation's policy pin, so \
                 it is an older body. Re-signing it would revive limits or recipients the owner \
                 replaced. The policy file is unchanged."
            ),
        ));
    }
    if sequence == pin.sequence() && body_digest != pin.digest() {
        return Some((
            PolicyError::SequenceFork.wire_code(),
            format!(
                "policy file {path} has the pinned sequence with another body. Re-signing it \
                 would revive limits or recipients the owner replaced. The policy file is unchanged."
            ),
        ));
    }
    None
}

/// The refusal of a pin whose owner differs from the enrolled owner.
fn rotation_failure(state: &PinState, enrolled: &[u8; 32]) -> Option<Failure> {
    match state {
        PinState::Present(pin) if pin.owner() != *enrolled => Some((
            "profile.policy_owner_rotation_pending",
            "the installation's policy pin names another owner than the enrolled owner key. \
             The rotation statement signs the body digest, and only the previous owner can \
             sign a new one. Complete the rotation with `stellar-agent profile sign-policy \
             --previous-owner-secret-env <VAR>`. The policy file is unchanged."
                .to_owned(),
        )),
        _ => None,
    }
}

/// The sequence and canonical digest of a verified body.
fn body_position(document: &DocumentMut, raw: &str) -> Result<(i64, [u8; 32]), Failure> {
    let failure = |e: PolicyError| (e.wire_code(), e.to_string());
    let sequence = stellar_agent_core::policy::v1::verified::sequence(document).map_err(failure)?;
    let canonical = canonical_bytes(raw).map_err(failure)?;
    Ok((sequence, digest(&canonical)))
}

/// Testable core of [`run`] with every seam injected.
async fn run_with<LoadProfile, InitKeyring, IsTerminal, ReadPolicy, ReadSeed, Sign, WritePolicy>(
    args: &AddCounterpartyArgs,
    mut deps: Dependencies<
        '_,
        LoadProfile,
        InitKeyring,
        IsTerminal,
        ReadPolicy,
        ReadSeed,
        Sign,
        WritePolicy,
    >,
) -> i32
where
    LoadProfile: Fn(&str) -> Result<Profile, loader::ProfileLoadError>,
    InitKeyring: Fn() -> Result<(), WalletError>,
    IsTerminal: Fn() -> bool,
    ReadPolicy: FnMut(&Path) -> io::Result<String>,
    ReadSeed: FnMut() -> io::Result<Zeroizing<String>>,
    Sign: AsyncFnOnce(
        Zeroizing<String>,
        MlockRequired,
        u32,
        &[u8; 32],
        &str,
    ) -> Result<Signed, OwnerSignError>,
    WritePolicy: FnOnce(&Path, &str) -> io::Result<()>,
{
    let start = match deps.start(args) {
        Ok(start) => start,
        Err(refusal) => return render_refusal(refusal, None),
    };
    if start.document.contains_key("signature") {
        deps.signed(args, start).await
    } else {
        deps.draft(args, &start)
    }
}

impl<LoadProfile, InitKeyring, IsTerminal, ReadPolicy, ReadSeed, Sign, WritePolicy>
    Dependencies<'_, LoadProfile, InitKeyring, IsTerminal, ReadPolicy, ReadSeed, Sign, WritePolicy>
where
    LoadProfile: Fn(&str) -> Result<Profile, loader::ProfileLoadError>,
    InitKeyring: Fn() -> Result<(), WalletError>,
    IsTerminal: Fn() -> bool,
    ReadPolicy: FnMut(&Path) -> io::Result<String>,
    ReadSeed: FnMut() -> io::Result<Zeroizing<String>>,
    Sign: AsyncFnOnce(
        Zeroizing<String>,
        MlockRequired,
        u32,
        &[u8; 32],
        &str,
    ) -> Result<Signed, OwnerSignError>,
    WritePolicy: FnOnce(&Path, &str) -> io::Result<()>,
{
    /// The recipient form, the profile, the paths, and the parsed body.
    fn start(&mut self, args: &AddCounterpartyArgs) -> Result<Start, Envelope<()>> {
        let form = classify_recipient(&args.recipient)
            .map_err(|refusal| raw_refusal(recipient_failure(&refusal, !args.tools.is_empty())))?;
        let resolved = resolve_profile_name(Some(&args.profile));
        let profile_name = resolved.name.clone();
        let profile = reconcile_loaded_profile((self.load_profile)(&profile_name), &resolved)
            .map_err(|e| {
                tracing::debug!(error = %e, "profile access refused");
                profile_access_envelope(&e)
            })?;
        stellar_agent_core::profile::owner_key::refuse_installation_key_coordinate(
            &profile.policy_window_state_key_id,
            "policy_window_state_key_id",
        )
        .map_err(|e| Envelope::<()>::err(&e))?;
        let engine_name = engine_profile_name(&profile).map_err(|message| {
            Envelope::<()>::err_raw("sign_policy.invalid_owner_service", message)
        })?;
        let policy_path = default_policy_dir()
            .map_err(|e| {
                Envelope::<()>::err_raw(
                    "sign_policy.policy_dir_unavailable",
                    format!("the OS policy state directory is unavailable ({e})"),
                )
            })?
            .join(format!("{engine_name}.toml"));
        let window_path = default_policy_window_state_path_for(&profile_name);
        let raw = read_file(&mut self.read_policy, &policy_path).map_err(raw_refusal)?;
        let document = raw.parse::<DocumentMut>().map_err(|error| {
            let refusal = RecipientRefusal::Body(error.span().map_or(0, |span| span.start));
            Envelope::<()>::err_raw(refusal.code(), refusal.to_string())
        })?;
        Ok(Start {
            form,
            profile,
            profile_name,
            engine_name,
            policy_path,
            window_path,
            raw,
            document,
        })
    }

    /// The signed path: verify, edit, prepare, preview, guard, prompt, sign,
    /// and replace.
    async fn signed(mut self, args: &AddCounterpartyArgs, start: Start) -> i32 {
        let SignedEdit {
            enrolled,
            edited,
            pin,
        } = match self.signed_checks(args, &start) {
            Ok(SignedStep::Edit(edit)) => *edit,
            Ok(SignedStep::Listed(listed)) => return finish(self.stderr, &listed),
            Err(refusal) => return render_refusal(refusal, None),
        };
        let Self {
            load_profile,
            is_terminal,
            mut read_policy,
            mut read_seed,
            sign,
            write_policy,
            stderr,
            ..
        } = self;
        let path = start.policy_path.as_path();
        let first = match prepare(&start, &edited.body) {
            Ok(prepared) => prepared,
            Err((code, message)) => return refuse(code, message, None),
        };
        if !is_terminal() {
            return refuse(
                PROMPT_REQUIRED,
                "a signed policy change needs the owner seed from a terminal prompt, and stdin \
                 or stderr is not a terminal. Run the command in a terminal, or sign the edited \
                 body with `stellar-agent profile sign-policy --secret-env <VAR>`. The policy \
                 file is unchanged.",
                None,
            );
        }
        let mut summary = match first.raw.parse::<DocumentMut>() {
            Ok(document) => summarize(
                &document,
                &start.profile.network_passphrase,
                AuthorityStatus::RequiresSignature,
            ),
            Err(e) => return refuse("sign_policy.policy_body_invalid", e.to_string(), None),
        };
        let shown = match preview(stderr, &summary, &edited.scope) {
            Ok(shown) => shown,
            Err((code, message)) => return refuse(code, message, None),
        };
        let shown = Some(&shown);
        let guard = match acquire(path) {
            Ok(guard) => guard,
            Err((code, message)) => return refuse(code, message, shown),
        };
        let recheck = Recheck {
            args,
            start: &start,
            body: &edited.body,
            pin: &pin,
            previewed: &first.raw,
        };
        if let Err(refusal) = recheck.revalidate(&load_profile, &mut read_policy) {
            return render_refusal(refusal, shown);
        }
        if write!(stderr, "{SEED_PROMPT}")
            .and_then(|()| stderr.flush())
            .is_err()
        {
            return refuse(
                PROMPT_REQUIRED,
                "the owner seed prompt could not be written to stderr. The policy file is unchanged.",
                shown,
            );
        }
        let seed = match read_seed() {
            Ok(seed) => seed,
            Err(_) => {
                return refuse(
                    PROMPT_REQUIRED,
                    "the owner seed could not be read from the terminal. The policy file is unchanged.",
                    shown,
                );
            }
        };
        // The prompt can wait for minutes, so the state is checked again
        // before the seed is used.
        if let Err(refusal) = recheck.revalidate(&load_profile, &mut read_policy) {
            return render_refusal(refusal, shown);
        }
        let signed = sign(
            seed,
            start.profile.wallet.mlock_required,
            start.profile.wallet.unlock_ttl_seconds,
            &enrolled,
            &first.raw,
        )
        .await;
        let (body, derived, signature, body_digest) = match signed {
            Ok(signed) => signed,
            Err(error) => {
                let (code, message) = sign_failure(error, &enrolled);
                return refuse(code, message, shown);
            }
        };
        let owner_address = stellar_strkey::ed25519::PublicKey(derived)
            .to_string()
            .to_string();
        let rendered = match verified_rendering(
            &start,
            &first.raw,
            &body,
            &owner_address,
            &signature,
            &enrolled,
        ) {
            Ok(rendered) => rendered,
            Err((code, message)) => return refuse(code, message, shown),
        };
        if let Err(refusal) =
            recheck.publish(&load_profile, &mut read_policy, write_policy, &rendered)
        {
            return render_refusal(refusal, shown);
        }
        drop(guard);
        tracing::info!(
            "add-counterparty adds a payment recipient to the signed policy of profile '{}'",
            start.profile_name
        );
        summary.authority_status = AuthorityStatus::Verified;
        let mut warnings = first.warnings;
        if first
            .raw
            .parse::<DocumentMut>()
            .is_ok_and(|document| has_total_budget(&document))
        {
            warnings.push("The new signature starts a new total_budget allocation.".to_owned());
        }
        let data = AddCounterpartyData {
            profile: start.profile_name.clone(),
            recipient: args.recipient.clone(),
            kind: edited.kind,
            changed: true,
            signed: true,
            policy_path: path.display().to_string(),
            covered_by: None,
            updated_rules: edited.updated_rules,
            kinds_added: edited.kinds_added,
            split_rules: edited.split_rules,
            edit_scope: edit_scope(&edited.scope),
            ungated_tools: edited.ungated_tools,
            denied_tools: edited.denied_tools,
            spending_summary: summary,
            destination_note: start.form.muxed_contract.then_some(W_NOTE),
            next_steps: None,
            owner_address: Some(owner_address),
            previous_sequence: first.previous_sequence,
            sequence: first.sequence,
            digest: Some(to_hex(&body_digest)),
            warnings,
        };
        finish(stderr, &data)
    }

    /// The keyring, the signature, the coverage, the pin, and the version
    /// checks of the signed path. A listed recipient returns its result.
    fn signed_checks(
        &mut self,
        args: &AddCounterpartyArgs,
        start: &Start,
    ) -> Result<SignedStep, Envelope<()>> {
        (self.init_keyring)().map_err(|e| Envelope::<()>::err(&e))?;
        let coordinate = KeyringEntryRef::default_owner_key(&start.engine_name);
        let enrolled = read_owner_pubkey(&coordinate).map_err(|error| {
            let code = match &error {
                OwnerReadError::OlderForm => "sign_policy.owner_key_older_form",
                OwnerReadError::Unavailable(_) => "sign_policy.owner_key_unavailable",
            };
            Envelope::<()>::err_raw(code, error.message())
        })?;
        let passphrase = &start.profile.network_passphrase;
        load_signed_policy_text(&start.raw, &start.engine_name, &enrolled, passphrase).map_err(
            |e| {
                Envelope::<()>::err_raw(
                    e.wire_code(),
                    format!(
                        "the signature of policy file {} does not verify against the enrolled \
                         owner key ({e}). The body changed since the owner signed it, or another \
                         owner signed it, and re-signing would adopt that change unseen. Review \
                         the body, then sign it with `stellar-agent profile sign-policy`. \
                         The policy file is unchanged.",
                        start.policy_path.display()
                    ),
                )
            },
        )?;
        let tools: Vec<&str> = args.tools.iter().map(String::as_str).collect();
        let edited = match add_payment_recipient(&start.raw, passphrase, &args.recipient, &tools)
            .map_err(|refusal| raw_refusal(recipient_failure(&refusal, !tools.is_empty())))?
        {
            RecipientEdit::Listed(listed) => {
                let summary = summarize(&start.document, passphrase, AuthorityStatus::Verified);
                return Ok(SignedStep::Listed(Box::new(listed_data(
                    args, start, listed, summary, false,
                ))));
            }
            RecipientEdit::Added(edited) => edited,
        };
        let state = read_pin_checked(&start.profile_name, &start.profile, &start.window_path)
            .map_err(raw_refusal)?;
        if let Some(failure) = rotation_failure(&state, &enrolled) {
            return Err(raw_refusal(failure));
        }
        if start
            .document
            .get("version")
            .and_then(toml_edit::Item::as_integer)
            != Some(2)
        {
            return Err(Envelope::<()>::err_raw(
                "profile.policy_version_required",
                format!(
                    "policy file {} is a version 1 body, which carries no sequence, so an older \
                     version 1 signature could be restored after this change. Raise the body to \
                     version 2, then sign it with `stellar-agent profile sign-policy`. The \
                     policy file is unchanged.",
                    start.policy_path.display()
                ),
            ));
        }
        let (sequence, body_digest) =
            body_position(&start.document, &start.raw).map_err(raw_refusal)?;
        if let Some(failure) = sequence_failure(&state, sequence, body_digest, &start.policy_path) {
            return Err(raw_refusal(failure));
        }
        Ok(SignedStep::Edit(Box::new(SignedEdit {
            enrolled,
            edited,
            pin: state,
        })))
    }

    /// The draft path: edit, validate, preview, guard, and replace.
    fn draft(self, args: &AddCounterpartyArgs, start: &Start) -> i32 {
        let Self {
            load_profile,
            mut read_policy,
            write_policy,
            stderr,
            ..
        } = self;
        let tools: Vec<&str> = args.tools.iter().map(String::as_str).collect();
        let passphrase = &start.profile.network_passphrase;
        let edited = match add_payment_recipient(&start.raw, passphrase, &args.recipient, &tools) {
            Ok(RecipientEdit::Added(edited)) => edited,
            Ok(RecipientEdit::Listed(listed)) => {
                let summary = summarize(&start.document, passphrase, AuthorityStatus::Draft);
                return finish(stderr, &listed_data(args, start, listed, summary, true));
            }
            Err(refusal) => {
                let (code, message) = recipient_failure(&refusal, !tools.is_empty());
                return refuse(code, message, None);
            }
        };
        let path = start.policy_path.as_path();
        if let Err(e) = validate_unsigned_policy(&edited.body, &start.engine_name, passphrase) {
            return refuse(
                "sign_policy.policy_body_invalid",
                format!(
                    "the V1 policy loader refuses the edited draft of policy file {} ({e}); \
                     correct the draft, then run the command again. The policy file is unchanged.",
                    path.display()
                ),
                None,
            );
        }
        let summary = match edited.body.parse::<DocumentMut>() {
            Ok(document) => summarize(&document, passphrase, AuthorityStatus::Draft),
            Err(e) => return refuse("sign_policy.policy_body_invalid", e.to_string(), None),
        };
        let shown = match preview(stderr, &summary, &edited.scope) {
            Ok(shown) => shown,
            Err((code, message)) => return refuse(code, message, None),
        };
        let shown = Some(&shown);
        let guard = match acquire(path) {
            Ok(guard) => guard,
            Err((code, message)) => return refuse(code, message, shown),
        };
        if let Err((code, message)) = reread(&mut read_policy, path, &start.raw) {
            return refuse(code, message, shown);
        }
        if let Err(refusal) = recheck_profile(&load_profile, args, start) {
            return render_refusal(refusal, shown);
        }
        if let Err(e) = write_policy(path, &edited.body) {
            return refuse(
                "sign_policy.policy_file_write_failed",
                format!("could not write policy file {}: {e}", path.display()),
                shown,
            );
        }
        drop(guard);
        tracing::info!(
            "add-counterparty adds a payment recipient to the draft policy of profile '{}'",
            start.profile_name
        );
        let data = AddCounterpartyData {
            profile: start.profile_name.clone(),
            recipient: args.recipient.clone(),
            kind: edited.kind,
            changed: true,
            signed: false,
            policy_path: path.display().to_string(),
            covered_by: None,
            updated_rules: edited.updated_rules,
            kinds_added: edited.kinds_added,
            split_rules: edited.split_rules,
            edit_scope: edit_scope(&edited.scope),
            ungated_tools: edited.ungated_tools,
            denied_tools: edited.denied_tools,
            spending_summary: summary,
            destination_note: start.form.muxed_contract.then_some(W_NOTE),
            next_steps: Some(vec![next_step(&start.profile_name)]),
            owner_address: None,
            previous_sequence: None,
            sequence: None,
            digest: None,
            warnings: Vec::new(),
        };
        finish(stderr, &data)
    }
}

/// Runs every signing check of `profile sign-policy` on the edited body and
/// assigns its sequence.
fn prepare(start: &Start, body: &str) -> Result<PreparedPolicy, Failure> {
    prepare_policy(
        body,
        &start.profile,
        &start.engine_name,
        &start.policy_path,
        &start.window_path,
    )
}

/// Reads the policy file through the seam.
fn read_file(
    read_policy: &mut impl FnMut(&Path) -> io::Result<String>,
    path: &Path,
) -> Result<String, Failure> {
    read_policy(path).map_err(|e| {
        (
            "sign_policy.policy_file_unreadable",
            format!("could not read policy file {}: {e}", path.display()),
        )
    })
}

/// Re-reads the policy file and refuses bytes that differ from `raw`.
fn reread(
    read_policy: &mut impl FnMut(&Path) -> io::Result<String>,
    path: &Path,
    raw: &str,
) -> Result<(), Failure> {
    if read_file(read_policy, path)? == raw {
        Ok(())
    } else {
        Err((
            CHANGED_DURING_EDIT,
            "policy_file: changed during edit".into(),
        ))
    }
}

/// The state a signed edit rests on: the file bytes, the profile, the pin,
/// and the previewed body.
struct Recheck<'r> {
    args: &'r AddCounterpartyArgs,
    start: &'r Start,
    /// The edited body before the sequence is assigned.
    body: &'r str,
    /// The pin read before the preview.
    pin: &'r PinState,
    /// The prepared body the preview states and the owner signs.
    previewed: &'r str,
}

impl Recheck<'_> {
    /// Checks the file bytes, a fresh profile, a fresh pin, and a fresh
    /// preparation of the edited body against the state the preview rests on.
    /// A read or load error keeps its own code.
    fn revalidate(
        &self,
        load_profile: &impl Fn(&str) -> Result<Profile, loader::ProfileLoadError>,
        read_policy: &mut impl FnMut(&Path) -> io::Result<String>,
    ) -> Result<(), Envelope<()>> {
        let start = self.start;
        reread(read_policy, &start.policy_path, &start.raw).map_err(raw_refusal)?;
        recheck_profile(load_profile, self.args, start)?;
        let state = read_pin_checked(&start.profile_name, &start.profile, &start.window_path)
            .map_err(raw_refusal)?;
        if state != *self.pin {
            return Err(changed("policy_state"));
        }
        if prepare(start, self.body).map_err(raw_refusal)?.raw != self.previewed {
            return Err(changed("policy_state"));
        }
        Ok(())
    }

    /// Replaces the policy file with `rendered` after a last check of the
    /// profile, the pin, and the file bytes.
    ///
    /// The pin comparison, the file check, and the replacement run under the
    /// policy-state lock, which every pin writer takes. The authoring guard is
    /// already held, so the lock order is the authoring lock, then the
    /// policy-state lock. Without a window-state directory no pin exists, and
    /// no lock is taken.
    fn publish(
        &self,
        load_profile: &impl Fn(&str) -> Result<Profile, loader::ProfileLoadError>,
        read_policy: &mut impl FnMut(&Path) -> io::Result<String>,
        write_policy: impl FnOnce(&Path, &str) -> io::Result<()>,
        rendered: &str,
    ) -> Result<(), Envelope<()>> {
        let start = self.start;
        recheck_profile(load_profile, self.args, start)?;
        let window = start.window_path.as_path();
        let lock = if window.parent().is_some_and(Path::exists) {
            Some(
                acquire_state_lock(window, &start.profile)
                    .map_err(|e| raw_refusal(pin_read_failure(&start.profile_name, e)))?,
            )
        } else {
            None
        };
        let state = match &lock {
            Some(lock) => {
                pin::read(lock, &PinScope::for_profile(window, &start.profile)).map_err(|e| {
                    raw_refusal(pin_read_failure(&start.profile_name, PolicyError::from(e)))
                })?
            }
            None => PinState::Absent,
        };
        if state != *self.pin {
            return Err(changed("policy_state"));
        }
        reread(read_policy, &start.policy_path, &start.raw).map_err(raw_refusal)?;
        let path = start.policy_path.as_path();
        write_policy(path, rendered).map_err(|e| {
            Envelope::<()>::err_raw(
                "sign_policy.policy_file_write_failed",
                format!("could not write policy file {}: {e}", path.display()),
            )
        })?;
        drop(lock);
        Ok(())
    }
}

/// Writes the preview line and returns the value it wrote.
fn preview(
    stderr: &mut dyn Write,
    summary: &SpendingSummary,
    scope: &[RuleScope],
) -> Result<Value, Failure> {
    let mut preview = SpendingPreview::new(stderr);
    preview.show_with(
        Some(summary),
        None,
        &[("edit_scope", edit_scope(scope))],
        OutputFormat::Json,
    )?;
    Ok(preview.shown().cloned().unwrap_or(Value::Null))
}

/// Writes the notes the envelope repeats, then renders the envelope.
fn finish(stderr: &mut dyn Write, data: &AddCounterpartyData) -> i32 {
    let notes = data
        .destination_note
        .iter()
        .map(|note| format!("Note: {note}"))
        .chain(
            data.next_steps
                .iter()
                .flatten()
                .map(|step| format!("Next: {step}")),
        );
    for note in notes {
        if writeln!(stderr, "{note}")
            .and_then(|()| stderr.flush())
            .is_err()
        {
            tracing::debug!("a note could not be written to stderr; the envelope carries it");
        }
    }
    render::render_json(&Envelope::ok(data));
    0
}

/// The command that signs a draft.
fn next_step(profile: &str) -> String {
    format!("stellar-agent profile sign-policy --profile {profile} --secret-env <VAR>")
}

/// The result of a recipient every target list already covers.
fn listed_data(
    args: &AddCounterpartyArgs,
    start: &Start,
    listed: RecipientListed,
    summary: SpendingSummary,
    draft: bool,
) -> AddCounterpartyData {
    AddCounterpartyData {
        profile: start.profile_name.clone(),
        recipient: args.recipient.clone(),
        kind: listed.kind,
        changed: false,
        signed: false,
        policy_path: start.policy_path.display().to_string(),
        covered_by: Some(listed.covered_by),
        updated_rules: Vec::new(),
        kinds_added: Vec::new(),
        split_rules: Vec::new(),
        edit_scope: edit_scope(&listed.scope),
        ungated_tools: listed.ungated_tools,
        denied_tools: listed.denied_tools,
        spending_summary: summary,
        destination_note: start.form.muxed_contract.then_some(W_NOTE),
        next_steps: draft.then(|| vec![next_step(&start.profile_name)]),
        owner_address: None,
        previous_sequence: None,
        sequence: None,
        digest: None,
        warnings: Vec::new(),
    }
}

/// Checks the signer's body against the preview, renders the signature, and
/// verifies the rendered text against the enrolled owner.
fn verified_rendering(
    start: &Start,
    previewed: &str,
    body: &str,
    owner_address: &str,
    signature: &[u8; 64],
    enrolled: &[u8; 32],
) -> Result<String, Failure> {
    let invalid = |detail: &dyn std::fmt::Display| {
        (
            "sign_policy.policy_body_invalid",
            format!(
                "the signed text of policy file {} does not match the previewed body ({detail}). \
                 The policy file is unchanged.",
                start.policy_path.display()
            ),
        )
    };
    if body != previewed {
        return Err(invalid(&"the signer returned another body"));
    }
    let (rendered, _, _) =
        render_with_signature(body, owner_address, &to_hex(signature)).map_err(|e| invalid(&e))?;
    load_signed_policy_text(
        &rendered,
        &start.engine_name,
        enrolled,
        &start.profile.network_passphrase,
    )
    .map_err(|e| invalid(&e))?;
    Ok(rendered)
}

/// The code and message of a failed signing ceremony.
fn sign_failure(error: OwnerSignError, enrolled: &[u8; 32]) -> Failure {
    match error {
        OwnerSignError::Policy(e) => (e.wire_code(), e.to_string()),
        OwnerSignError::Env(message) => ("sign_policy.invalid_owner_seed", message),
        OwnerSignError::Unlock(message) => ("sign_policy.owner_seed_unlock_failed", message),
        OwnerSignError::Mismatch { derived } | OwnerSignError::PreviousMismatch { derived, .. } => {
            let derived_address = stellar_strkey::ed25519::PublicKey(derived)
                .to_string()
                .to_string();
            (
                "sign_policy.owner_key_mismatch",
                format!(
                    "the entered seed derives to owner key {derived_address} (fingerprint {}), \
                     but the profile's enrolled owner key has fingerprint {}. Enter the enrolled \
                     owner's seed, or enroll the owner public key again with `stellar-agent \
                     profile enroll-owner-key --force`. The policy file is unchanged.",
                    owner_key_fingerprint(&derived),
                    owner_key_fingerprint(enrolled)
                ),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only assertions"
    )]

    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use serial_test::serial;
    use stellar_agent_core::policy::pin::{self, Pin, PinScope};
    use stellar_agent_core::policy::state_lock::WindowStoreLock;
    use stellar_agent_core::policy::v1::signature::sign;
    use stellar_agent_core::policy::v1::verified::read_pin_without_creating;
    use stellar_agent_core::profile::schema::policy_pin_entry_ref;
    use stellar_agent_test_support::{StellarAgentHomeGuard, keyring_mock};
    use tempfile::TempDir;

    use super::super::policy_authoring::{missing_pin_lock_detail, pin_read_failure};
    use super::super::sign_policy::tests::{
        enroll_owner_pubkey, nonce_state, profile_for, provisioning_body, provisioning_profile,
        seed_material,
    };
    use super::*;

    const NAME: &str = "add-counterparty";
    const OWNER: [u8; 32] = [0x61; 32];
    const BOTH_KINDS: &str = "\"G_ACCOUNT\", \"C_ACCOUNT\"";

    fn account(seed: u8) -> String {
        stellar_strkey::ed25519::PublicKey([seed; 32])
            .to_string()
            .to_string()
    }

    fn contract(seed: u8) -> String {
        format!("{}", stellar_strkey::Contract([seed; 32]))
    }

    fn w_address(seed: u8, id: u64) -> String {
        format!(
            "{}",
            stellar_strkey::MuxedContract {
                contract_id: [seed; 32],
                id
            }
        )
    }

    fn owner_seed() -> String {
        seed_material(OWNER).0
    }

    fn owner_public() -> [u8; 32] {
        seed_material(OWNER).1
    }

    /// A version 2 body of `name` with one rule for `tool` and one list.
    fn rule_body(name: &str, tool: &str, kinds: &str, entries: &[String]) -> String {
        let entries = entries
            .iter()
            .map(|entry| format!("{entry:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "version = 2\nscope = \"profile:{name}\"\nsequence = 1\n\n[[rules]]\nmatch = {{ tool \
             = \"{tool}\", chain = \"*\" }}\ncriteria = [{{ kind = \"counterparty_allowlist\", \
             kinds = [{kinds}], allowlist = [{entries}] }}]\ndecision = \"allow\"\n"
        )
    }

    /// The standard body: a `stellar_pay` rule with an empty G and C list.
    fn body() -> String {
        rule_body(NAME, "stellar_pay", BOTH_KINDS, &[])
    }

    /// The standard body with `entries` listed.
    fn body_listing(entries: &[String]) -> String {
        rule_body(NAME, "stellar_pay", BOTH_KINDS, entries)
    }

    /// `raw` with a `[signature]` of the owner key.
    fn signed(raw: &str) -> String {
        let key = ed25519_dalek::SigningKey::from_bytes(&OWNER);
        let body_digest = digest(&canonical_bytes(raw).unwrap());
        let (_, _, address) = seed_material(OWNER);
        render_with_signature(raw, &address, &to_hex(&sign(&body_digest, &key)))
            .unwrap()
            .0
    }

    fn write_pin(profile: &Profile, window: &Path, sequence: i64, at: [u8; 32], owner: [u8; 32]) {
        std::fs::create_dir_all(window.parent().unwrap()).unwrap();
        let lock =
            WindowStoreLock::acquire_for(window, &profile.policy_window_state_key_id).unwrap();
        pin::write_for_test(
            &lock,
            &PinScope::for_profile(window, profile),
            &Pin::new(sequence, at, owner).unwrap(),
        )
        .unwrap();
    }

    fn put_entry(coordinate: &KeyringEntryRef, value: &str) {
        keyring_core::Entry::new(&coordinate.service, &coordinate.account)
            .unwrap()
            .set_password(value)
            .unwrap();
    }

    struct Fixture {
        dir: TempDir,
        _home: StellarAgentHomeGuard,
        profile: Profile,
        path: PathBuf,
        window: PathBuf,
    }

    impl Fixture {
        fn with(profile: impl FnOnce() -> Profile, raw: &str, enroll: bool) -> Self {
            keyring_mock::install().unwrap();
            let dir = TempDir::new().unwrap();
            let home = StellarAgentHomeGuard::new(dir.path());
            let mut profile = profile();
            profile.audit_log_path = dir.path().join("audit.jsonl");
            let name = engine_profile_name(&profile).unwrap();
            if enroll {
                enroll_owner_pubkey(&name, &owner_public());
            }
            let policies = default_policy_dir().unwrap();
            std::fs::create_dir_all(&policies).unwrap();
            let path = policies.join(format!("{name}.toml"));
            std::fs::write(&path, raw).unwrap();
            let window = default_policy_window_state_path_for(&name);
            Self {
                dir,
                _home: home,
                profile,
                path,
                window,
            }
        }

        fn draft(raw: &str) -> Self {
            Self::with(|| profile_for(NAME), raw, false)
        }

        fn signed(raw: &str) -> Self {
            Self::with(|| profile_for(NAME), &signed(raw), true)
        }

        fn contents(&self) -> String {
            std::fs::read_to_string(&self.path).unwrap()
        }

        fn digest(&self) -> [u8; 32] {
            digest(&canonical_bytes(&self.contents()).unwrap())
        }

        fn pin(&self, sequence: i64, at: [u8; 32], owner: [u8; 32]) {
            write_pin(&self.profile, &self.window, sequence, at, owner);
        }

        fn lock_path(&self) -> PathBuf {
            let mut path = self.path.as_os_str().to_owned();
            path.push(".authoring.lock");
            PathBuf::from(path)
        }
    }

    /// Bytes shared between the stderr seam and the other seams.
    #[derive(Clone, Default)]
    struct Buffer(Rc<RefCell<Vec<u8>>>);

    impl Buffer {
        fn text(&self) -> String {
            String::from_utf8(self.0.borrow().clone()).unwrap()
        }

        fn has_preview(&self) -> bool {
            self.text()
                .lines()
                .next()
                .and_then(|line| serde_json::from_str::<Value>(line).ok())
                .is_some_and(|line| line["phase"] == "before_write")
        }
    }

    /// A stderr seam: records into a [`Buffer`], fails from its n-th write,
    /// and runs `hook` on its first write.
    struct TestStderr {
        buffer: Buffer,
        writes: usize,
        fail_from: Option<usize>,
        hook: Option<Box<dyn FnOnce()>>,
    }

    impl Write for TestStderr {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            if self.fail_from.is_some_and(|n| self.writes >= n) {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "stderr refused"));
            }
            if let Some(hook) = self.hook.take() {
                hook();
            }
            self.buffer.0.borrow_mut().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    type SignResult = Result<Signed, OwnerSignError>;
    type LoadSeam = Box<dyn Fn(&str) -> Result<Profile, loader::ProfileLoadError>>;
    type ReadSeam = Box<dyn FnMut(&Path) -> io::Result<String>>;
    type WriteSeam = Box<dyn FnOnce(&Path, &str) -> io::Result<()>>;

    struct Seams {
        load: LoadSeam,
        terminal: bool,
        read_policy: ReadSeam,
        read_seed: Box<dyn FnMut() -> io::Result<Zeroizing<String>>>,
        before_sign: Box<dyn FnOnce()>,
        after_sign: Box<dyn FnOnce(SignResult) -> SignResult>,
        write_policy: WriteSeam,
        stderr: Option<Box<dyn Write>>,
        fail_from: Option<usize>,
        hook: Option<Box<dyn FnOnce()>>,
        buffer: Buffer,
    }

    impl Seams {
        fn new(fixture: &Fixture) -> Self {
            let profile = fixture.profile.clone();
            Self {
                load: Box::new(move |_| Ok(profile.clone())),
                terminal: true,
                read_policy: Box::new(|path| std::fs::read_to_string(path)),
                read_seed: Box::new(|| Ok(Zeroizing::new(owner_seed()))),
                before_sign: Box::new(|| {}),
                after_sign: Box::new(|result| result),
                write_policy: Box::new(atomic_write_string),
                stderr: None,
                fail_from: None,
                hook: None,
                buffer: Buffer::default(),
            }
        }

        /// `read_policy` serves the file, and its call `n` (from 1) runs
        /// `action` first.
        fn on_read(mut self, n: usize, action: impl FnOnce() + 'static) -> Self {
            let calls = Cell::new(0);
            let mut action = Some(action);
            self.read_policy = Box::new(move |path| {
                calls.set(calls.get() + 1);
                if calls.get() == n
                    && let Some(action) = action.take()
                {
                    action();
                }
                std::fs::read_to_string(path)
            });
            self
        }

        fn seed_panics(mut self) -> Self {
            self.read_seed = Box::new(|| panic!("the seed must not be read"));
            self
        }

        fn write_panics(mut self) -> Self {
            self.write_policy = Box::new(|_, _| panic!("the policy must not be written"));
            self
        }
    }

    struct Outcome {
        status: i32,
        envelope: Value,
        stderr: String,
    }

    impl Outcome {
        fn code(&self) -> &str {
            self.envelope["error"]["code"].as_str().unwrap_or_default()
        }

        fn message(&self) -> &str {
            self.envelope["error"]["message"]
                .as_str()
                .unwrap_or_default()
        }

        fn data(&self) -> &Value {
            &self.envelope["data"]
        }

        fn preview(&self) -> Value {
            serde_json::from_str(self.stderr.lines().next().unwrap()).unwrap()
        }

        fn refused(&self, code: &str) {
            assert_eq!(self.status, 1, "{}", self.envelope);
            assert_eq!(self.code(), code, "{}", self.envelope);
        }

        fn succeeded(&self) {
            assert_eq!(self.status, 0, "{}", self.envelope);
            assert_eq!(self.envelope["ok"], true, "{}", self.envelope);
        }
    }

    fn args_for(profile: &str, recipient: &str, tools: &[&str]) -> AddCounterpartyArgs {
        AddCounterpartyArgs {
            profile: profile.to_owned(),
            recipient: recipient.to_owned(),
            tools: tools.iter().map(|tool| (*tool).to_owned()).collect(),
        }
    }

    fn args(recipient: &str) -> AddCounterpartyArgs {
        args_for(NAME, recipient, &[])
    }

    async fn drive(args: &AddCounterpartyArgs, seams: Seams) -> Outcome {
        let Seams {
            load,
            terminal,
            read_policy,
            read_seed,
            before_sign,
            after_sign,
            write_policy,
            stderr,
            fail_from,
            hook,
            buffer,
        } = seams;
        let mut stderr = stderr.unwrap_or_else(|| {
            Box::new(TestStderr {
                buffer: buffer.clone(),
                writes: 0,
                fail_from,
                hook,
            })
        });
        render::take_rendered_for_test();
        let status = run_with(
            args,
            Dependencies {
                load_profile: load,
                init_keyring: || Ok::<(), WalletError>(()),
                is_terminal: move || terminal,
                read_policy,
                read_seed,
                sign: async move |seed: Zeroizing<String>,
                                  mlock: MlockRequired,
                                  ttl: u32,
                                  enrolled: &[u8; 32],
                                  raw: &str| {
                    before_sign();
                    after_sign(sign_with_seed_text(seed, mlock, ttl, enrolled, raw).await)
                },
                write_policy,
                stderr: &mut *stderr,
            },
        )
        .await;
        let mut rendered = render::take_rendered_for_test();
        assert_eq!(rendered.len(), 1, "{rendered:?}");
        Outcome {
            status,
            envelope: rendered.remove(0),
            stderr: buffer.text(),
        }
    }

    // ── Common start ─────────────────────────────────────────────────────────

    #[tokio::test]
    #[serial]
    async fn invalid_recipient_precedes_profile_io() {
        let fixture = Fixture::draft(&body());
        let mut seams = Seams::new(&fixture);
        seams.load = Box::new(|_| panic!("the profile must not load"));
        seams.read_policy = Box::new(|_| panic!("the policy must not be read"));
        let outcome = drive(&args("invalid"), seams).await;
        outcome.refused("profile.policy_recipient_invalid");
        assert_eq!(
            outcome.message(),
            "the recipient must be a G, M, C, or W payment address"
        );
    }

    #[tokio::test]
    #[serial]
    async fn mistyped_seed_as_recipient_is_not_echoed() {
        let fixture = Fixture::draft(&body());
        let outcome = drive(&args(&owner_seed()), Seams::new(&fixture)).await;
        outcome.refused("profile.policy_recipient_invalid");
        assert!(!outcome.envelope.to_string().contains(&owner_seed()));
        assert!(!outcome.stderr.contains(&owner_seed()));
    }

    #[test]
    fn tool_flag_accepts_payment_tools_only() {
        use clap::Parser as _;
        let parse = |tool: &str| {
            crate::Cli::try_parse_from([
                "stellar-agent",
                "profile",
                "policy",
                "add-counterparty",
                "--profile",
                NAME,
                "--recipient",
                "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
                "--tool",
                tool,
            ])
        };
        for tool in MAINNET_VALUE_OUT_TOOLS {
            assert!(parse(tool).is_ok(), "{tool}");
        }
        for tool in ["stellar_balances", "stellar_trustline", "*", ""] {
            let error = parse(tool).err().unwrap();
            assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue, "{tool}");
        }
    }

    #[tokio::test]
    #[serial]
    async fn add_counterparty_unparsable_body_refuses() {
        let fixture = Fixture::draft("version = 2\n[");
        let outcome = drive(&args(&account(7)), Seams::new(&fixture).write_panics()).await;
        outcome.refused("profile.policy_body_invalid");
        assert_eq!(
            outcome.message(),
            "the policy body does not parse at byte 13"
        );
        assert_eq!(fixture.contents(), "version = 2\n[");
    }

    /// `body()` with `signature` set to `value` as a root key.
    fn with_root_signature(value: &str) -> String {
        body().replacen(
            "sequence = 1\n",
            &format!("sequence = 1\nsignature = {value}\n"),
            1,
        )
    }

    async fn takes_signed_path(value: &str) {
        let raw = with_root_signature(value);
        let fixture = Fixture::with(|| profile_for(NAME), &raw, true);
        let outcome = drive(&args(&account(7)), Seams::new(&fixture).write_panics()).await;
        assert_eq!(outcome.status, 1, "{}", outcome.envelope);
        assert!(
            outcome.code().starts_with("policy."),
            "{}",
            outcome.envelope
        );
        assert_eq!(fixture.contents(), raw);
    }

    #[tokio::test]
    #[serial]
    async fn scalar_signature_takes_signed_path() {
        takes_signed_path("\"x\"").await;
    }

    #[tokio::test]
    #[serial]
    async fn inline_signature_takes_signed_path() {
        takes_signed_path("{ owner_id = \"G\", sig = \"00\" }").await;
    }

    #[tokio::test]
    #[serial]
    async fn array_signature_takes_signed_path() {
        takes_signed_path("[\"x\"]").await;
    }

    #[tokio::test]
    #[serial]
    async fn failed_signature_refuses_with_reason() {
        let mut document = signed(&body()).parse::<DocumentMut>().unwrap();
        document["signature"]["sig"] = toml_edit::value("00".repeat(64));
        let raw = document.to_string();
        let fixture = Fixture::with(|| profile_for(NAME), &raw, true);
        let outcome = drive(&args(&account(7)), Seams::new(&fixture).write_panics()).await;
        outcome.refused("policy.owner_signature_invalid");
        let message = outcome.message();
        assert!(
            message.contains("The body changed since the owner signed it, or another owner"),
            "{message}"
        );
        assert!(
            message
                .contains("Review the body, then sign it with `stellar-agent profile sign-policy`"),
            "{message}"
        );
        assert_eq!(fixture.contents(), raw);
    }

    #[tokio::test]
    #[serial]
    async fn tampered_body_refuses() {
        let raw =
            signed(&body()).replace("decision = \"allow\"", "decision = \"require_approval\"");
        let fixture = Fixture::with(|| profile_for(NAME), &raw, true);
        let outcome = drive(&args(&account(7)), Seams::new(&fixture).write_panics()).await;
        outcome.refused("policy.owner_signature_invalid");
        assert_eq!(fixture.contents(), raw);
    }

    #[tokio::test]
    #[serial]
    async fn core_refusal_keeps_its_code() {
        let raw = rule_body(NAME, "stellar_pay", "\"G_ACCOUNT\"", &[contract(8)]);
        let fixture = Fixture::draft(&raw);
        let outcome = drive(&args(&contract(9)), Seams::new(&fixture).write_panics()).await;
        outcome.refused("profile.policy_recipient_kind_conflict");
        let expected =
            add_payment_recipient(&raw, &fixture.profile.network_passphrase, &contract(9), &[])
                .unwrap_err();
        assert_eq!(outcome.message(), expected.to_string());
        assert_eq!(fixture.contents(), raw);
    }

    #[tokio::test]
    #[serial]
    async fn ambiguous_refusal_adds_the_tool_hint() {
        let wildcard = rule_body(NAME, "*", BOTH_KINDS, &[]);
        let fixture = Fixture::draft(&wildcard);
        let outcome = drive(
            &args_for(NAME, &account(7), &["stellar_pay"]),
            Seams::new(&fixture).write_panics(),
        )
        .await;
        outcome.refused("profile.policy_counterparty_ambiguous");
        let core = add_payment_recipient(
            &wildcard,
            &fixture.profile.network_passphrase,
            &account(7),
            &["stellar_pay"],
        )
        .unwrap_err();
        assert_eq!(outcome.message(), format!("{core} {HINT_WITH_TOOLS}"));
        drop(fixture);

        let differing = format!(
            "{}\n[[rules]]\nmatch = {{ tool = \"stellar_pay_commit\", chain = \"*\" }}\ncriteria \
             = [{{ kind = \"counterparty_allowlist\", kinds = [{BOTH_KINDS}], allowlist = [] }}]\n\
             decision = \"allow\"\n",
            body_listing(&[account(5)])
        );
        let fixture = Fixture::draft(&differing);
        let outcome = drive(&args(&account(7)), Seams::new(&fixture).write_panics()).await;
        outcome.refused("profile.policy_counterparty_ambiguous");
        let core = add_payment_recipient(
            &differing,
            &fixture.profile.network_passphrase,
            &account(7),
            &[],
        )
        .unwrap_err();
        assert!(
            core.to_string()
                .ends_with("Supply a selection whose target lists hold the same entries.")
        );
        assert_eq!(outcome.message(), format!("{core} {HINT_WITHOUT_TOOLS}"));
    }

    // ── Signed success ───────────────────────────────────────────────────────

    #[tokio::test]
    #[serial]
    async fn signed_success_fields_are_exact() {
        let fixture = Fixture::signed(&body());
        let outcome = drive(&args(&account(7)), Seams::new(&fixture)).await;
        outcome.succeeded();
        let data = outcome.data();
        let mut keys: Vec<&str> = data
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "changed",
                "denied_tools",
                "digest",
                "edit_scope",
                "kind",
                "kinds_added",
                "owner_address",
                "policy_path",
                "previous_sequence",
                "profile",
                "recipient",
                "sequence",
                "signed",
                "spending_summary",
                "split_rules",
                "ungated_tools",
                "updated_rules",
                "warnings",
            ]
        );
        assert_eq!(data["profile"], NAME);
        assert_eq!(data["recipient"], account(7));
        assert_eq!(data["kind"], "G_ACCOUNT");
        assert_eq!(data["changed"], true);
        assert_eq!(data["signed"], true);
        assert_eq!(data["policy_path"], fixture.path.display().to_string());
        assert_eq!(data["updated_rules"], serde_json::json!([0]));
        assert_eq!(data["kinds_added"], serde_json::json!([]));
        assert_eq!(data["split_rules"], serde_json::json!([]));
        assert_eq!(
            data["edit_scope"],
            serde_json::json!([{"rule": 0, "tools": ["stellar_pay"], "wildcard": false}])
        );
        assert_eq!(data["ungated_tools"], serde_json::json!([]));
        assert_eq!(
            data["denied_tools"],
            serde_json::json!(&MAINNET_VALUE_OUT_TOOLS[1..])
        );
        assert_eq!(data["owner_address"], seed_material(OWNER).2);
        assert_eq!(data["previous_sequence"], 1);
        assert_eq!(data["sequence"], 2);
        assert_eq!(data["digest"], to_hex(&fixture.digest()));
        assert_eq!(data["warnings"], serde_json::json!([]));
        load_signed_policy_text(
            &fixture.contents(),
            NAME,
            &owner_public(),
            &fixture.profile.network_passphrase,
        )
        .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn success_carries_no_seed_derived_text() {
        let fixture = Fixture::signed(&body());
        let outcome = drive(&args(&account(7)), Seams::new(&fixture)).await;
        outcome.succeeded();
        let text = outcome.envelope.to_string();
        let address = seed_material(OWNER).2;
        assert_eq!(text.matches(&address).count(), 1, "{text}");
        assert!(!text.contains(&to_hex(&owner_public())), "{text}");
        assert!(
            !text.contains(&owner_key_fingerprint(&owner_public())),
            "{text}"
        );
        assert!(!text.contains(&owner_seed()), "{text}");
    }

    // ── Preview ──────────────────────────────────────────────────────────────

    #[tokio::test]
    #[serial]
    async fn preview_precedes_guard() {
        let fixture = Fixture::signed(&body());
        let mut seams = Seams::new(&fixture);
        let path = fixture.path.clone();
        seams.hook = Some(Box::new(move || {
            assert!(
                acquire(&path).is_ok(),
                "the guard is taken after the preview"
            );
        }));
        drive(&args(&account(7)), seams).await.succeeded();
    }

    #[tokio::test]
    #[serial]
    async fn preview_precedes_prompt() {
        let fixture = Fixture::signed(&body());
        let mut seams = Seams::new(&fixture);
        let buffer = seams.buffer.clone();
        seams.read_seed = Box::new(move || {
            assert!(buffer.has_preview(), "{}", buffer.text());
            Ok(Zeroizing::new(owner_seed()))
        });
        drive(&args(&account(7)), seams).await.succeeded();
    }

    #[tokio::test]
    #[serial]
    async fn preview_precedes_write() {
        let fixture = Fixture::draft(&body());
        let mut seams = Seams::new(&fixture);
        let buffer = seams.buffer.clone();
        seams.write_policy = Box::new(move |path, text| {
            assert!(buffer.has_preview(), "{}", buffer.text());
            atomic_write_string(path, text)
        });
        drive(&args(&account(7)), seams).await.succeeded();
    }

    #[tokio::test]
    #[serial]
    async fn preview_matches_the_signed_body() {
        let fixture = Fixture::signed(&body());
        let outcome = drive(&args(&account(7)), Seams::new(&fixture)).await;
        outcome.succeeded();
        let written = fixture.contents().parse::<DocumentMut>().unwrap();
        let expected = summarize(
            &written,
            &fixture.profile.network_passphrase,
            AuthorityStatus::RequiresSignature,
        );
        assert_eq!(
            outcome.preview()["spending_summary"],
            serde_json::to_value(&expected).unwrap()
        );
        assert_eq!(outcome.preview()["spending_summary"]["sequence"], 2);
    }

    #[tokio::test]
    #[serial]
    async fn preview_states_wildcard_scope() {
        let fixture = Fixture::signed(&rule_body(NAME, "*", BOTH_KINDS, &[]));
        let outcome = drive(&args(&account(7)), Seams::new(&fixture)).await;
        outcome.succeeded();
        let scope = &outcome.preview()["edit_scope"];
        assert_eq!(scope[0]["rule"], 0);
        assert_eq!(scope[0]["wildcard"], true);
        let tools: Vec<&str> = scope[0]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool.as_str().unwrap())
            .collect();
        for tool in [
            "stellar_balances",
            "stellar_pay",
            "stellar_trustline",
            "stellar_claim",
        ] {
            assert!(tools.contains(&tool), "{tool}: {tools:?}");
        }
        assert_eq!(outcome.data()["edit_scope"], *scope);
    }

    #[tokio::test]
    #[serial]
    async fn envelope_summary_is_verified_preview() {
        let fixture = Fixture::signed(&body());
        let outcome = drive(&args(&account(7)), Seams::new(&fixture)).await;
        outcome.succeeded();
        let mut previewed = outcome.preview()["spending_summary"].clone();
        previewed["authority_status"] = Value::from("verified");
        assert_eq!(outcome.data()["spending_summary"], previewed);
    }

    #[tokio::test]
    #[serial]
    async fn envelope_summary_label_is_verified() {
        let fixture = Fixture::signed(&body());
        let outcome = drive(&args(&account(7)), Seams::new(&fixture)).await;
        outcome.succeeded();
        assert_eq!(
            outcome.data()["spending_summary"]["authority_status"],
            "verified"
        );
        assert_eq!(
            outcome.preview()["spending_summary"]["authority_status"],
            "requires_signature"
        );
    }

    #[tokio::test]
    #[serial]
    async fn signer_body_must_equal_preview() {
        let fixture = Fixture::signed(&body());
        let before = fixture.contents();
        let mut seams = Seams::new(&fixture);
        seams.after_sign = Box::new(|result| {
            let (body, derived, _, _) = result?;
            let altered = body.replace("decision = \"allow\"", "decision = \"require_approval\"");
            let key = ed25519_dalek::SigningKey::from_bytes(&OWNER);
            let altered_digest = digest(&canonical_bytes(&altered).unwrap());
            Ok((
                altered,
                derived,
                sign(&altered_digest, &key),
                altered_digest,
            ))
        });
        let outcome = drive(&args(&account(7)), seams).await;
        outcome.refused("sign_policy.policy_body_invalid");
        assert_eq!(fixture.contents(), before);
    }

    #[tokio::test]
    #[serial]
    async fn rendered_text_is_verified_before_replace() {
        let fixture = Fixture::signed(&body());
        let before = fixture.contents();
        let mut seams = Seams::new(&fixture);
        seams.after_sign = Box::new(|result| {
            let (body, derived, mut signature, body_digest) = result?;
            signature[0] ^= 1;
            Ok((body, derived, signature, body_digest))
        });
        let outcome = drive(&args(&account(7)), seams).await;
        outcome.refused("sign_policy.policy_body_invalid");
        assert_eq!(fixture.contents(), before);
    }

    #[tokio::test]
    #[serial]
    async fn preview_failure_writes_nothing() {
        let fixture = Fixture::draft(&body());
        let mut seams = Seams::new(&fixture).write_panics();
        seams.stderr = Some(Box::new(render::FailingWriter::Write));
        let outcome = drive(&args(&account(7)), seams).await;
        outcome.refused("profile.spending_preview_unwritable");
        assert_eq!(fixture.contents(), body());
        assert!(!fixture.lock_path().exists());
    }

    #[tokio::test]
    #[serial]
    async fn refusal_after_preview_carries_it() {
        let fixture = Fixture::signed(&body());
        let _guard = acquire(&fixture.path).unwrap();
        let outcome = drive(&args(&account(7)), Seams::new(&fixture).seed_panics()).await;
        outcome.refused("sign_policy.authoring_lock_busy");
        assert_eq!(
            outcome.envelope["error"]["details"]["preview"],
            outcome.preview()
        );
    }

    // ── Listed recipients ────────────────────────────────────────────────────

    fn listed_fixture() -> Fixture {
        Fixture::signed(&body_listing(&[account(7)]))
    }

    #[tokio::test]
    #[serial]
    async fn listed_signed_recipient_exits_zero() {
        let fixture = listed_fixture();
        let outcome = drive(&args(&account(7)), Seams::new(&fixture)).await;
        outcome.succeeded();
        let data = outcome.data();
        assert_eq!(data["changed"], false);
        assert_eq!(data["signed"], false);
        assert_eq!(data["covered_by"], account(7));
        assert_eq!(data["updated_rules"], serde_json::json!([]));
        assert_eq!(data["spending_summary"]["authority_status"], "verified");
        assert!(data.get("next_steps").is_none());
        assert_eq!(outcome.stderr, "");
    }

    #[tokio::test]
    #[serial]
    async fn listed_signed_recipient_needs_no_seed() {
        let fixture = listed_fixture();
        let outcome = drive(&args(&account(7)), Seams::new(&fixture).seed_panics()).await;
        outcome.succeeded();
    }

    #[tokio::test]
    #[serial]
    async fn listed_signed_recipient_reads_no_pin() {
        let fixture = listed_fixture();
        put_entry(
            &policy_pin_entry_ref(&fixture.profile.policy_window_state_key_id),
            "pin entry",
        );
        let outcome = drive(&args(&account(7)), Seams::new(&fixture)).await;
        outcome.succeeded();
    }

    #[tokio::test]
    #[serial]
    async fn listed_signed_recipient_writes_nothing() {
        let fixture = listed_fixture();
        let before = fixture.contents();
        let outcome = drive(&args(&account(7)), Seams::new(&fixture).write_panics()).await;
        outcome.succeeded();
        assert_eq!(fixture.contents(), before);
    }

    #[tokio::test]
    #[serial]
    async fn listed_signed_recipient_takes_no_guard() {
        let fixture = listed_fixture();
        let _guard = acquire(&fixture.path).unwrap();
        let outcome = drive(&args(&account(7)), Seams::new(&fixture)).await;
        outcome.succeeded();
    }

    #[tokio::test]
    #[serial]
    async fn listed_precedes_rotation_refusal() {
        let fixture = listed_fixture();
        fixture.pin(1, fixture.digest(), seed_material([0x62; 32]).1);
        let outcome = drive(&args(&account(7)), Seams::new(&fixture)).await;
        outcome.succeeded();
    }

    fn version_1(raw: &str) -> String {
        raw.replace("version = 2\n", "version = 1\n")
            .replace("sequence = 1\n", "")
    }

    #[tokio::test]
    #[serial]
    async fn listed_precedes_version_refusal() {
        let fixture = Fixture::signed(&version_1(&body_listing(&[account(7)])));
        let outcome = drive(&args(&account(7)), Seams::new(&fixture)).await;
        outcome.succeeded();
        assert_eq!(outcome.data()["changed"], false);
    }

    // ── W notes ──────────────────────────────────────────────────────────────

    #[tokio::test]
    #[serial]
    async fn w_recipient_note_is_exact() {
        let fixture = Fixture::draft(&body());
        let outcome = drive(&args(&w_address(8, 9)), Seams::new(&fixture)).await;
        outcome.succeeded();
        assert!(
            outcome.stderr.contains(
                "\nNote: the wallet does not pay W destinations yet; this entry takes effect \
                 when it does.\n"
            ),
            "{}",
            outcome.stderr
        );
    }

    #[tokio::test]
    #[serial]
    async fn w_recipient_field_is_exact() {
        let fixture = Fixture::draft(&body());
        let outcome = drive(&args(&w_address(8, 9)), Seams::new(&fixture)).await;
        outcome.succeeded();
        assert_eq!(
            outcome.data()["destination_note"],
            "the wallet does not pay W destinations yet; this entry takes effect when it does."
        );
        assert_eq!(outcome.data()["kind"], "C_ACCOUNT");
    }

    #[tokio::test]
    #[serial]
    async fn w_note_absent_for_contract() {
        let fixture = Fixture::draft(&body());
        let outcome = drive(&args(&contract(8)), Seams::new(&fixture)).await;
        outcome.succeeded();
        assert!(outcome.data().get("destination_note").is_none());
        assert!(!outcome.stderr.contains("Note:"), "{}", outcome.stderr);
    }

    #[tokio::test]
    #[serial]
    async fn note_failure_keeps_exit_zero() {
        let fixture = Fixture::draft(&body());
        let mut seams = Seams::new(&fixture);
        seams.fail_from = Some(2);
        let outcome = drive(&args(&w_address(8, 9)), seams).await;
        outcome.succeeded();
        assert!(fixture.contents().contains(&w_address(8, 9)));
        assert!(!outcome.stderr.contains("Note:"));
    }

    // ── Draft path ───────────────────────────────────────────────────────────

    #[tokio::test]
    #[serial]
    async fn unsigned_draft_needs_no_seed() {
        let fixture = Fixture::draft(&body());
        let outcome = drive(&args(&account(7)), Seams::new(&fixture).seed_panics()).await;
        outcome.succeeded();
        assert!(!outcome.stderr.contains(SEED_PROMPT));
    }

    #[tokio::test]
    #[serial]
    async fn unsigned_draft_reads_no_keyring() {
        let fixture = Fixture::draft(&body());
        let mut seams = Seams::new(&fixture);
        seams.before_sign = Box::new(|| panic!("a draft is not signed"));
        let outcome = drive(&args(&account(7)), seams).await;
        outcome.succeeded();
        let coordinate = KeyringEntryRef::default_owner_key(NAME);
        assert!(
            read_owner_pubkey(&coordinate).is_err(),
            "no owner is enrolled"
        );
    }

    #[tokio::test]
    #[serial]
    async fn unsigned_draft_needs_no_terminal() {
        let fixture = Fixture::draft(&body());
        let mut seams = Seams::new(&fixture);
        seams.terminal = false;
        drive(&args(&account(7)), seams).await.succeeded();
    }

    #[tokio::test]
    #[serial]
    async fn unsigned_draft_stays_unsigned() {
        let fixture = Fixture::draft(&body());
        drive(&args(&account(7)), Seams::new(&fixture))
            .await
            .succeeded();
        let written = fixture.contents().parse::<DocumentMut>().unwrap();
        assert!(!written.contains_key("signature"));
        assert!(fixture.contents().contains(&account(7)));
    }

    #[tokio::test]
    #[serial]
    async fn unsigned_draft_keeps_its_sequence() {
        let fixture = Fixture::draft(&body());
        let outcome = drive(&args(&account(7)), Seams::new(&fixture)).await;
        outcome.succeeded();
        let written = fixture.contents().parse::<DocumentMut>().unwrap();
        assert_eq!(written["sequence"].as_integer(), Some(1));
        assert!(outcome.data().get("sequence").is_none());
    }

    #[tokio::test]
    #[serial]
    async fn draft_preview_is_labeled_draft() {
        let fixture = Fixture::draft(&body());
        let outcome = drive(&args(&account(7)), Seams::new(&fixture)).await;
        outcome.succeeded();
        assert_eq!(
            outcome.preview()["spending_summary"]["authority_status"],
            "draft"
        );
    }

    #[tokio::test]
    #[serial]
    async fn draft_envelope_is_labeled_draft() {
        let fixture = Fixture::draft(&body());
        let outcome = drive(&args(&account(7)), Seams::new(&fixture)).await;
        outcome.succeeded();
        assert_eq!(
            outcome.data()["spending_summary"]["authority_status"],
            "draft"
        );
        assert_eq!(outcome.data()["signed"], false);
        assert_eq!(outcome.data()["changed"], true);
    }

    fn next_step_text() -> String {
        format!("stellar-agent profile sign-policy --profile {NAME} --secret-env <VAR>")
    }

    #[tokio::test]
    #[serial]
    async fn draft_names_sign_policy_next_in_envelope() {
        let fixture = Fixture::draft(&body());
        let outcome = drive(&args(&account(7)), Seams::new(&fixture)).await;
        outcome.succeeded();
        assert_eq!(
            outcome.data()["next_steps"],
            serde_json::json!([next_step_text()])
        );
    }

    #[tokio::test]
    #[serial]
    async fn draft_names_sign_policy_next_on_stderr() {
        let fixture = Fixture::draft(&body());
        let outcome = drive(&args(&account(7)), Seams::new(&fixture)).await;
        outcome.succeeded();
        assert!(
            outcome
                .stderr
                .ends_with(&format!("\nNext: {}\n", next_step_text())),
            "{}",
            outcome.stderr
        );
    }

    #[tokio::test]
    #[serial]
    async fn unchanged_draft_names_next_step() {
        let raw = body_listing(&[account(7)]);
        let fixture = Fixture::draft(&raw);
        let outcome = drive(&args(&account(7)), Seams::new(&fixture).write_panics()).await;
        outcome.succeeded();
        assert_eq!(outcome.data()["changed"], false);
        assert_eq!(
            outcome.data()["spending_summary"]["authority_status"],
            "draft"
        );
        assert_eq!(
            outcome.data()["next_steps"],
            serde_json::json!([next_step_text()])
        );
        assert_eq!(outcome.stderr, format!("Next: {}\n", next_step_text()));
        assert_eq!(fixture.contents(), raw);
    }

    #[tokio::test]
    #[serial]
    async fn draft_edit_takes_the_guard() {
        let fixture = Fixture::draft(&body());
        let _guard = acquire(&fixture.path).unwrap();
        let outcome = drive(&args(&account(7)), Seams::new(&fixture).write_panics()).await;
        outcome.refused("sign_policy.authoring_lock_busy");
        assert_eq!(fixture.contents(), body());
    }

    #[tokio::test]
    #[serial]
    async fn changed_draft_reread_refuses() {
        let fixture = Fixture::draft(&body());
        let calls = Cell::new(0);
        let mut seams = Seams::new(&fixture).write_panics();
        seams.read_policy = Box::new(move |path| {
            calls.set(calls.get() + 1);
            let text = std::fs::read_to_string(path)?;
            Ok(if calls.get() == 2 {
                format!("{text}\n")
            } else {
                text
            })
        });
        let outcome = drive(&args(&account(7)), seams).await;
        outcome.refused(CHANGED_DURING_EDIT);
        assert_eq!(outcome.message(), "policy_file: changed during edit");
        assert_eq!(fixture.contents(), body());
    }

    #[tokio::test]
    #[serial]
    async fn draft_that_does_not_load_refuses() {
        let raw = rule_body("another-profile", "stellar_pay", BOTH_KINDS, &[]);
        let fixture = Fixture::draft(&raw);
        let outcome = drive(&args(&account(7)), Seams::new(&fixture).write_panics()).await;
        outcome.refused("sign_policy.policy_body_invalid");
        assert!(
            outcome
                .message()
                .contains("policy scope does not match the selected profile"),
            "{}",
            outcome.message()
        );
        assert_eq!(fixture.contents(), raw);
    }

    #[tokio::test]
    #[serial]
    async fn warnings_present_when_empty() {
        let fixture = Fixture::draft(&body());
        let outcome = drive(&args(&account(7)), Seams::new(&fixture)).await;
        outcome.succeeded();
        assert_eq!(outcome.data()["warnings"], serde_json::json!([]));
    }

    // ── Revalidation ─────────────────────────────────────────────────────────

    fn failing_reread(seams: &mut Seams) {
        let calls = Cell::new(0);
        seams.read_policy = Box::new(move |path| {
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"));
            }
            std::fs::read_to_string(path)
        });
    }

    #[tokio::test]
    #[serial]
    async fn reread_failure_refuses() {
        let fixture = Fixture::signed(&body());
        let before = fixture.contents();
        let mut seams = Seams::new(&fixture).seed_panics().write_panics();
        failing_reread(&mut seams);
        let outcome = drive(&args(&account(7)), seams).await;
        assert_eq!(outcome.status, 1);
        assert!(!outcome.stderr.contains(SEED_PROMPT));
        assert_eq!(fixture.contents(), before);
    }

    #[tokio::test]
    #[serial]
    async fn reread_failure_keeps_its_code() {
        let fixture = Fixture::signed(&body());
        let mut seams = Seams::new(&fixture).seed_panics();
        failing_reread(&mut seams);
        let outcome = drive(&args(&account(7)), seams).await;
        outcome.refused("sign_policy.policy_file_unreadable");
        assert_eq!(
            outcome.message(),
            format!(
                "could not read policy file {}: denied",
                fixture.path.display()
            )
        );
    }

    #[tokio::test]
    #[serial]
    async fn pending_rotation_refuses_before_prompt() {
        let fixture = Fixture::signed(&body());
        let before = fixture.contents();
        fixture.pin(1, fixture.digest(), seed_material([0x62; 32]).1);
        let outcome = drive(&args(&account(7)), Seams::new(&fixture).seed_panics()).await;
        outcome.refused("profile.policy_owner_rotation_pending");
        assert!(
            outcome
                .message()
                .contains("stellar-agent profile sign-policy --previous-owner-secret-env"),
            "{}",
            outcome.message()
        );
        assert_eq!(fixture.contents(), before);
    }

    #[tokio::test]
    #[serial]
    async fn version_1_body_refuses() {
        let fixture = Fixture::signed(&version_1(&body()));
        let before = fixture.contents();
        let outcome = drive(&args(&account(7)), Seams::new(&fixture).seed_panics()).await;
        outcome.refused("profile.policy_version_required");
        assert_eq!(fixture.contents(), before);
    }

    #[tokio::test]
    #[serial]
    async fn body_below_pin_refuses_rollback() {
        let fixture = Fixture::signed(&body());
        let before = fixture.contents();
        fixture.pin(5, [3; 32], owner_public());
        let outcome = drive(&args(&account(7)), Seams::new(&fixture).seed_panics()).await;
        outcome.refused("policy.sequence_rollback");
        assert_eq!(fixture.contents(), before);
    }

    #[tokio::test]
    #[serial]
    async fn body_forking_pin_refuses() {
        let fixture = Fixture::signed(&body());
        let before = fixture.contents();
        fixture.pin(1, [3; 32], owner_public());
        let outcome = drive(&args(&account(7)), Seams::new(&fixture).seed_panics()).await;
        outcome.refused("policy.sequence_fork");
        assert_eq!(fixture.contents(), before);
    }

    #[tokio::test]
    #[serial]
    async fn missing_lock_with_pin_refuses() {
        let fixture = Fixture::signed(&body());
        put_entry(
            &policy_pin_entry_ref(&fixture.profile.policy_window_state_key_id),
            "pin entry",
        );
        let outcome = drive(&args(&account(7)), Seams::new(&fixture).seed_panics()).await;
        outcome.refused("policy.pin_absent");
        assert_eq!(outcome.message(), missing_pin_lock_detail(NAME));
    }

    #[tokio::test]
    #[serial]
    async fn unusable_pin_names_its_recovery() {
        let fixture = Fixture::signed(&body());
        fixture.pin(1, fixture.digest(), owner_public());
        put_entry(
            &policy_pin_entry_ref(&fixture.profile.policy_window_state_key_id),
            "invalid pin",
        );
        let error = read_pin_without_creating(&fixture.window, &fixture.profile).unwrap_err();
        let expected = pin_read_failure(NAME, error);
        let outcome = drive(&args(&account(7)), Seams::new(&fixture).seed_panics()).await;
        outcome.refused(expected.0);
        assert_eq!(outcome.message(), expected.1);
    }

    /// A pin above the body, and a pin at the body's sequence with another
    /// digest, that appear under the guard refuse before the prompt.
    #[tokio::test]
    #[serial]
    async fn pin_change_under_guard_refuses() {
        for sequence in [5, 1] {
            let fixture = Fixture::signed(&body());
            let before = fixture.contents();
            let (profile, window) = (fixture.profile.clone(), fixture.window.clone());
            let seams = Seams::new(&fixture).seed_panics().on_read(2, move || {
                write_pin(&profile, &window, sequence, [3; 32], owner_public());
            });
            let outcome = drive(&args(&account(7)), seams).await;
            outcome.refused(CHANGED_DURING_EDIT);
            assert_eq!(outcome.message(), "policy_state: changed during edit");
            assert_eq!(
                outcome.envelope["error"]["details"]["preview"],
                outcome.preview()
            );
            assert_eq!(fixture.contents(), before);
        }
    }

    #[tokio::test]
    #[serial]
    async fn nonce_change_under_guard_is_revalidated() {
        let fixture = Fixture::with(
            provisioning_profile,
            &signed(&provisioning_body(false)),
            true,
        );
        let before = fixture.contents();
        let profile = fixture.profile.clone();
        let seams = Seams::new(&fixture)
            .seed_panics()
            .on_read(2, move || nonce_state(&profile, "present"));
        let outcome = drive(&args_for("operator", &account(7), &[]), seams).await;
        outcome.refused("policy.policy_file_parse_failed");
        assert!(
            outcome
                .message()
                .contains("mainnet.installation_nonce_sha256 must be a string"),
            "{}",
            outcome.message()
        );
        assert_eq!(fixture.contents(), before);
    }

    #[tokio::test]
    #[serial]
    async fn rotation_under_guard_refuses() {
        let fixture = Fixture::signed(&body());
        let before = fixture.contents();
        let (profile, window, at) = (
            fixture.profile.clone(),
            fixture.window.clone(),
            fixture.digest(),
        );
        let seams = Seams::new(&fixture).seed_panics().on_read(2, move || {
            write_pin(&profile, &window, 1, at, seed_material([0x62; 32]).1);
        });
        let outcome = drive(&args(&account(7)), seams).await;
        outcome.refused(CHANGED_DURING_EDIT);
        assert_eq!(outcome.message(), "policy_state: changed during edit");
        assert_eq!(fixture.contents(), before);
    }

    /// Saves `profile` as the fixture profile file and loads through the real
    /// loader from then on.
    fn real_profile(seams: &mut Seams, profile: &Profile) {
        stellar_agent_core::profile::loader::save(NAME, profile).unwrap();
        seams.load = Box::new(injected_profile_load);
    }

    /// `profile` with another unlock lifetime, a value the signing uses.
    fn changed_profile(profile: &Profile) -> Profile {
        let mut changed = profile.clone();
        changed.wallet.unlock_ttl_seconds += 1;
        changed
    }

    #[tokio::test]
    #[serial]
    async fn profile_change_after_preview_refuses() {
        let fixture = Fixture::signed(&body());
        let before = fixture.contents();
        let mut seams = Seams::new(&fixture).seed_panics().write_panics();
        real_profile(&mut seams, &fixture.profile);
        let (buffer, changed) = (seams.buffer.clone(), changed_profile(&fixture.profile));
        let seams = seams.on_read(2, move || {
            assert!(buffer.has_preview(), "{}", buffer.text());
            stellar_agent_core::profile::loader::save(NAME, &changed).unwrap();
        });
        let outcome = drive(&args(&account(7)), seams).await;
        outcome.refused(CHANGED_DURING_EDIT);
        assert_eq!(outcome.message(), "profile: changed during edit");
        assert_eq!(fixture.contents(), before);
    }

    #[tokio::test]
    #[serial]
    async fn profile_change_during_prompt_refuses() {
        let fixture = Fixture::signed(&body());
        let before = fixture.contents();
        let mut seams = Seams::new(&fixture).write_panics();
        real_profile(&mut seams, &fixture.profile);
        let changed = changed_profile(&fixture.profile);
        seams.read_seed = Box::new(move || {
            stellar_agent_core::profile::loader::save(NAME, &changed).unwrap();
            Ok(Zeroizing::new(owner_seed()))
        });
        seams.before_sign = Box::new(|| panic!("a changed profile must not reach the signer"));
        let outcome = drive(&args(&account(7)), seams).await;
        outcome.refused(CHANGED_DURING_EDIT);
        assert_eq!(outcome.message(), "profile: changed during edit");
        assert_eq!(fixture.contents(), before);
    }

    /// A profile saved while the signer runs refuses at the reload that
    /// precedes the replacement.
    #[tokio::test]
    #[serial]
    async fn profile_change_before_replacement_refuses() {
        let fixture = Fixture::signed(&body());
        let before = fixture.contents();
        let mut seams = Seams::new(&fixture).write_panics();
        real_profile(&mut seams, &fixture.profile);
        let changed = changed_profile(&fixture.profile);
        seams.after_sign = Box::new(move |result| {
            stellar_agent_core::profile::loader::save(NAME, &changed).unwrap();
            result
        });
        let outcome = drive(&args(&account(7)), seams).await;
        outcome.refused(CHANGED_DURING_EDIT);
        assert_eq!(outcome.message(), "profile: changed during edit");
        assert_eq!(fixture.contents(), before);
    }

    #[tokio::test]
    #[serial]
    async fn draft_profile_change_after_preview_refuses() {
        let fixture = Fixture::draft(&body());
        let mut seams = Seams::new(&fixture).write_panics();
        real_profile(&mut seams, &fixture.profile);
        let changed = changed_profile(&fixture.profile);
        let seams = seams.on_read(2, move || {
            stellar_agent_core::profile::loader::save(NAME, &changed).unwrap();
        });
        let outcome = drive(&args(&account(7)), seams).await;
        outcome.refused(CHANGED_DURING_EDIT);
        assert_eq!(outcome.message(), "profile: changed during edit");
        assert_eq!(fixture.contents(), body());
    }

    #[tokio::test]
    #[serial]
    async fn profile_load_error_under_guard_keeps_its_code() {
        let fixture = Fixture::signed(&body());
        let before = fixture.contents();
        let mut seams = Seams::new(&fixture).seed_panics().write_panics();
        real_profile(&mut seams, &fixture.profile);
        let file = stellar_agent_core::profile::schema::default_profile_dir()
            .unwrap()
            .join(format!("{NAME}.toml"));
        let seams = seams.on_read(2, move || std::fs::write(&file, "[").unwrap());
        let outcome = drive(&args(&account(7)), seams).await;
        outcome.refused("validation.config_invalid");
        assert_eq!(fixture.contents(), before);
    }

    #[tokio::test]
    #[serial]
    async fn real_profile_load_signs_an_unchanged_edit() {
        let fixture = Fixture::signed(&body());
        fixture.pin(1, fixture.digest(), owner_public());
        let mut seams = Seams::new(&fixture);
        real_profile(&mut seams, &fixture.profile);
        let outcome = drive(&args(&account(7)), seams).await;
        outcome.succeeded();
        assert_eq!(outcome.data()["sequence"], 2);
    }

    #[tokio::test]
    #[serial]
    async fn pin_change_during_prompt_refuses() {
        let fixture = Fixture::signed(&body());
        let before = fixture.contents();
        let mut seams = Seams::new(&fixture).write_panics();
        let (profile, window) = (fixture.profile.clone(), fixture.window.clone());
        seams.read_seed = Box::new(move || {
            write_pin(&profile, &window, 5, [3; 32], owner_public());
            Ok(Zeroizing::new(owner_seed()))
        });
        seams.before_sign = Box::new(|| panic!("a changed pin must not reach the signer"));
        let outcome = drive(&args(&account(7)), seams).await;
        outcome.refused(CHANGED_DURING_EDIT);
        assert_eq!(outcome.message(), "policy_state: changed during edit");
        assert_eq!(fixture.contents(), before);
    }

    /// A pin written after the post-prompt checks, while the signer runs,
    /// refuses at the comparison that precedes the replacement.
    #[tokio::test]
    #[serial]
    async fn pin_change_before_replacement_refuses() {
        let fixture = Fixture::signed(&body());
        fixture.pin(1, fixture.digest(), owner_public());
        let before = fixture.contents();
        let mut seams = Seams::new(&fixture).write_panics();
        let (profile, window, at) = (
            fixture.profile.clone(),
            fixture.window.clone(),
            fixture.digest(),
        );
        seams.after_sign = Box::new(move |result| {
            write_pin(&profile, &window, 1, at, seed_material([0x62; 32]).1);
            result
        });
        let outcome = drive(&args(&account(7)), seams).await;
        outcome.refused(CHANGED_DURING_EDIT);
        assert_eq!(outcome.message(), "policy_state: changed during edit");
        assert_eq!(fixture.contents(), before);
    }

    /// The replacement runs under the policy-state lock, so no pin writer
    /// changes the pin between the last comparison and the replacement.
    #[tokio::test]
    #[serial]
    async fn replacement_holds_the_state_lock() {
        let fixture = Fixture::signed(&body());
        fixture.pin(1, fixture.digest(), owner_public());
        let mut seams = Seams::new(&fixture);
        let (window, key) = (
            fixture.window.clone(),
            fixture.profile.policy_window_state_key_id.clone(),
        );
        seams.write_policy = Box::new(move |path, text| {
            assert!(matches!(
                WindowStoreLock::acquire_for(&window, &key),
                Err(stellar_agent_core::policy::state_lock::StateLockError::WriterLocked)
            ));
            atomic_write_string(path, text)
        });
        drive(&args(&account(7)), seams).await.succeeded();
        assert!(
            WindowStoreLock::acquire_for(
                &fixture.window,
                &fixture.profile.policy_window_state_key_id
            )
            .is_ok()
        );
    }

    /// The signed writer receives the body whose summary the preview states.
    #[tokio::test]
    #[serial]
    async fn signed_writer_receives_the_previewed_body() {
        let fixture = Fixture::signed(&body());
        let mut seams = Seams::new(&fixture);
        let (buffer, passphrase) = (
            seams.buffer.clone(),
            fixture.profile.network_passphrase.clone(),
        );
        seams.write_policy = Box::new(move |path, text| {
            let line = buffer.text();
            let previewed: Value = serde_json::from_str(line.lines().next().unwrap()).unwrap();
            let written = summarize(
                &text.parse::<DocumentMut>().unwrap(),
                &passphrase,
                AuthorityStatus::RequiresSignature,
            );
            assert_eq!(
                previewed["spending_summary"],
                serde_json::to_value(&written).unwrap()
            );
            atomic_write_string(path, text)
        });
        drive(&args(&account(7)), seams).await.succeeded();
    }

    #[tokio::test]
    #[serial]
    async fn hand_edit_during_prompt_refuses() {
        let fixture = Fixture::signed(&body());
        let mut seams = Seams::new(&fixture).write_panics();
        let path = fixture.path.clone();
        seams.read_seed = Box::new(move || {
            std::fs::write(&path, "hand edit").unwrap();
            Ok(Zeroizing::new(owner_seed()))
        });
        let outcome = drive(&args(&account(7)), seams).await;
        outcome.refused(CHANGED_DURING_EDIT);
        assert_eq!(outcome.message(), "policy_file: changed during edit");
        assert_eq!(fixture.contents(), "hand edit");
    }

    #[tokio::test]
    #[serial]
    async fn changed_body_after_preview_refuses() {
        let fixture = Fixture::signed(&body());
        let other = signed(&body_listing(&[account(5)]));
        let mut seams = Seams::new(&fixture).seed_panics().write_panics();
        let (path, replacement) = (fixture.path.clone(), other.clone());
        seams.hook = Some(Box::new(move || {
            atomic_write_string(&path, &replacement).unwrap();
        }));
        let outcome = drive(&args(&account(7)), seams).await;
        outcome.refused(CHANGED_DURING_EDIT);
        assert_eq!(outcome.message(), "policy_file: changed during edit");
        assert_eq!(fixture.contents(), other);
    }

    #[tokio::test]
    #[serial]
    async fn add_counterparty_holds_the_guard_through_replace() {
        let fixture = Fixture::signed(&body());
        let mut seams = Seams::new(&fixture);
        seams.write_policy = Box::new(|path, text| {
            assert_eq!(
                acquire(path).err().map(|failure| failure.0),
                Some("sign_policy.authoring_lock_busy")
            );
            atomic_write_string(path, text)
        });
        drive(&args(&account(7)), seams).await.succeeded();
        assert!(acquire(&fixture.path).is_ok());
    }

    // ── Seed prompt ──────────────────────────────────────────────────────────

    #[tokio::test]
    #[serial]
    async fn seed_prompt_requires_terminal() {
        let fixture = Fixture::signed(&body());
        let before = fixture.contents();
        let mut seams = Seams::new(&fixture).seed_panics().write_panics();
        seams.terminal = false;
        let outcome = drive(&args(&account(7)), seams).await;
        outcome.refused(PROMPT_REQUIRED);
        assert_eq!(outcome.stderr, "");
        assert_eq!(fixture.contents(), before);
    }

    #[tokio::test]
    #[serial]
    async fn seed_prompt_text_is_exact() {
        let fixture = Fixture::signed(&body());
        let outcome = drive(&args(&account(7)), Seams::new(&fixture)).await;
        outcome.succeeded();
        let mut lines = outcome.stderr.split_inclusive('\n');
        lines.next();
        assert_eq!(lines.next(), Some("Policy owner seed (hidden): "));
        assert_eq!(lines.next(), None);
    }

    #[tokio::test]
    #[serial]
    async fn seed_prompt_goes_to_stderr() {
        let fixture = Fixture::signed(&body());
        let mut seams = Seams::new(&fixture);
        let buffer = seams.buffer.clone();
        seams.read_seed = Box::new(move || {
            assert!(
                buffer.text().ends_with("\nPolicy owner seed (hidden): "),
                "{}",
                buffer.text()
            );
            Ok(Zeroizing::new(owner_seed()))
        });
        drive(&args(&account(7)), seams).await.succeeded();
    }

    #[tokio::test]
    #[serial]
    async fn prompt_write_failure_reads_nothing() {
        let fixture = Fixture::signed(&body());
        let mut seams = Seams::new(&fixture).seed_panics().write_panics();
        seams.fail_from = Some(2);
        let outcome = drive(&args(&account(7)), seams).await;
        outcome.refused(PROMPT_REQUIRED);
    }

    #[tokio::test]
    #[serial]
    async fn seed_read_failure_refuses() {
        let fixture = Fixture::signed(&body());
        let before = fixture.contents();
        let mut seams = Seams::new(&fixture).write_panics();
        seams.read_seed = Box::new(|| Err(io::Error::other("no terminal")));
        let outcome = drive(&args(&account(7)), seams).await;
        outcome.refused(PROMPT_REQUIRED);
        assert_eq!(fixture.contents(), before);
    }

    #[tokio::test]
    #[serial]
    async fn invalid_seed_uses_prompt_wording() {
        let fixture = Fixture::signed(&body());
        let mut seams = Seams::new(&fixture).write_panics();
        seams.read_seed = Box::new(|| Ok(Zeroizing::new("not a seed".to_owned())));
        let outcome = drive(&args(&account(7)), seams).await;
        outcome.refused("sign_policy.invalid_owner_seed");
        assert_eq!(
            outcome.message(),
            "the entered text is not a valid S-strkey"
        );
    }

    #[tokio::test]
    #[serial]
    async fn seed_mismatch_names_the_prompt() {
        let fixture = Fixture::signed(&body());
        let (other_seed, other_public, other_address) = seed_material([0x62; 32]);
        let mut seams = Seams::new(&fixture).write_panics();
        seams.read_seed = Box::new(move || Ok(Zeroizing::new(other_seed.clone())));
        let outcome = drive(&args(&account(7)), seams).await;
        outcome.refused("sign_policy.owner_key_mismatch");
        let message = outcome.message();
        assert!(
            message.starts_with("the entered seed derives to owner key "),
            "{message}"
        );
        assert!(message.contains(&other_address), "{message}");
        assert!(
            message.contains(&owner_key_fingerprint(&other_public)),
            "{message}"
        );
        assert!(
            message.contains(&owner_key_fingerprint(&owner_public())),
            "{message}"
        );
        assert!(!message.contains("--secret-env"), "{message}");
        assert!(!message.contains(&seed_material([0x62; 32]).0), "{message}");
    }

    #[tokio::test]
    #[serial]
    async fn seed_sentinel_absent_from_outputs() {
        let fixture = Fixture::signed(&body());
        let outcome = drive(&args(&account(7)), Seams::new(&fixture)).await;
        outcome.succeeded();
        assert!(!outcome.envelope.to_string().contains(&owner_seed()));
        assert!(!outcome.stderr.contains(&owner_seed()));
        assert!(!fixture.contents().contains(&owner_seed()));
    }

    #[test]
    #[serial]
    fn seed_sentinel_absent_from_logs() {
        let fixture = Fixture::signed(&body());
        let outcome = RefCell::new(None);
        let logs = stellar_agent_test_support::log_capture::with_captured_trace_logs(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            *outcome.borrow_mut() =
                Some(runtime.block_on(drive(&args(&account(7)), Seams::new(&fixture))));
        });
        outcome.into_inner().unwrap().succeeded();
        assert!(logs.contains("adds a payment recipient to"), "{logs}");
        assert!(!logs.contains(&owner_seed()), "{logs}");
    }

    #[tokio::test]
    #[serial]
    async fn seed_absent_from_environment_during_signing() {
        let fixture = Fixture::signed(&body());
        let mut seams = Seams::new(&fixture);
        let scan = || {
            assert!(
                std::env::vars_os()
                    .all(|(_, value)| !value.to_string_lossy().contains(&owner_seed())),
                "the seed is in the environment"
            );
        };
        let signed_once = Rc::new(Cell::new(false));
        let seen = signed_once.clone();
        seams.before_sign = Box::new(scan);
        seams.after_sign = Box::new(move |result| {
            scan();
            seen.set(true);
            result
        });
        drive(&args(&account(7)), seams).await.succeeded();
        assert!(signed_once.get());
    }

    /// The text before the test module, so test-only shims count as
    /// production text too.
    fn before_tests(source: &str) -> &str {
        source.split("\nmod tests {").next().unwrap()
    }

    #[test]
    fn production_source_sets_no_env() {
        let own = include_str!("add_counterparty.rs");
        let seed = include_str!("owner_seed.rs");
        for (file, text) in [
            (
                "add_counterparty.rs",
                stellar_agent_test_support::source_order::production_half(own),
            ),
            ("add_counterparty.rs", before_tests(own)),
            ("owner_seed.rs", before_tests(seed)),
        ] {
            assert!(!text.contains("set_var"), "{file}");
            assert!(!text.contains("remove_var"), "{file}");
        }
    }

    #[test]
    fn production_source_spawns_no_process() {
        let text = stellar_agent_test_support::source_order::production_half(include_str!(
            "add_counterparty.rs"
        ));
        assert!(!text.contains("Command::new"));
        assert!(!text.contains("process::Command"));
    }

    // ── Failure boundary ─────────────────────────────────────────────────────

    #[tokio::test]
    #[serial]
    async fn owner_mismatch_preserves_policy() {
        let fixture = Fixture::signed(&body());
        let before = fixture.contents();
        let mut seams = Seams::new(&fixture).write_panics();
        seams.read_seed = Box::new(|| Ok(Zeroizing::new(seed_material([0x62; 32]).0)));
        drive(&args(&account(7)), seams)
            .await
            .refused("sign_policy.owner_key_mismatch");
        assert_eq!(fixture.contents(), before);
    }

    #[tokio::test]
    #[serial]
    async fn sequence_exhaustion_preserves_policy() {
        let raw = body().replace("sequence = 1\n", &format!("sequence = {}\n", i64::MAX));
        let fixture = Fixture::signed(&raw);
        let before = fixture.contents();
        let outcome = drive(&args(&account(7)), Seams::new(&fixture).seed_panics()).await;
        outcome.refused("sign_policy.sequence_exhausted");
        assert_eq!(fixture.contents(), before);
    }

    #[tokio::test]
    #[serial]
    async fn persist_failure_preserves_original() {
        let fixture = Fixture::signed(&body());
        let before = fixture.contents();
        let mut seams = Seams::new(&fixture);
        seams.write_policy = Box::new(|_, _| Err(io::Error::other("disk full")));
        let outcome = drive(&args(&account(7)), seams).await;
        outcome.refused("sign_policy.policy_file_write_failed");
        assert_eq!(fixture.contents(), before);
        assert!(acquire(&fixture.path).is_ok());
    }

    #[tokio::test]
    #[serial]
    async fn resign_warns_new_allocation() {
        let raw = body().replace(
            "allowlist = [] }]",
            "allowlist = [] }, { kind = \"total_budget\", asset = \"native\", max_stroops = \
             \"200000000\" }]",
        );
        let fixture = Fixture::signed(&raw);
        let outcome = drive(&args(&account(7)), Seams::new(&fixture)).await;
        outcome.succeeded();
        assert_eq!(
            outcome.data()["warnings"],
            serde_json::json!(["The new signature starts a new total_budget allocation."])
        );
    }

    #[tokio::test]
    #[serial]
    async fn add_counterparty_writes_no_pin() {
        let fixture = Fixture::signed(&body());
        drive(&args(&account(7)), Seams::new(&fixture))
            .await
            .succeeded();
        assert_eq!(
            read_pin_without_creating(&fixture.window, &fixture.profile).unwrap(),
            PinState::Absent
        );
        assert!(!pin::entry_present(&fixture.profile.policy_window_state_key_id).unwrap());
    }

    #[tokio::test]
    #[serial]
    async fn add_counterparty_writes_no_window_counters() {
        let fixture = Fixture::signed(&body());
        drive(&args(&account(7)), Seams::new(&fixture))
            .await
            .succeeded();
        assert!(!fixture.window.parent().unwrap().exists());
    }

    #[tokio::test]
    #[serial]
    async fn add_counterparty_writes_no_keyring_entry() {
        let fixture = Fixture::signed(&body());
        let log = keyring_mock::record_mutations().unwrap();
        drive(&args(&account(7)), Seams::new(&fixture))
            .await
            .succeeded();
        assert!(log.mutations().is_empty(), "{:?}", log.mutations());
    }

    #[tokio::test]
    #[serial]
    async fn add_counterparty_writes_no_audit_row() {
        let fixture = Fixture::signed(&body());
        drive(&args(&account(7)), Seams::new(&fixture))
            .await
            .succeeded();
        assert!(!fixture.profile.audit_log_path.exists());
        assert!(!fixture.dir.path().join("audit").exists());
    }
}
