//! Immutable signing plans and the capabilities that admit their exposure.

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use stellar_agent_core::error::{SubmissionError, WalletError};
use stellar_agent_core::policy::v1::criteria::WindowEntry;
use stellar_agent_core::sc_address::scaddress_to_strkey;
use stellar_agent_core::smart_account::auth_payload::{AuthPayloadSigner, decode_auth_payload};
use stellar_agent_core::smart_account::rule_id::{ContextRuleId, encode_context_rule_ids};
use stellar_xdr::{
    Hash, Limits, OperationBody, ScAddress, ScVal, SorobanAuthorizationEntry,
    SorobanAuthorizedInvocation, SorobanCredentials, TransactionEnvelope, WriteXdr,
};

use crate::policy_state::ChainScope;
use crate::signing::{SmartAccountAuthDigest, SorobanAuthPayload};

/// A signer whose authority the admitted plan permits.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SignerDescriptor {
    /// A classic account key signing address authorization or the envelope.
    AccountKey {
        /// The Ed25519 public key.
        #[serde(with = "hash_hex")]
        public_key: [u8; 32],
    },
    /// A delegated account in the smart account payload.
    Delegated {
        /// The delegated Ed25519 public key.
        #[serde(with = "hash_hex")]
        account: [u8; 32],
    },
    /// A verifier contract and the hash of its encoded key data.
    External {
        /// The verifier's contract strkey.
        verifier: String,
        /// SHA-256 of the verifier's key data.
        #[serde(with = "hash_hex")]
        key_data_sha256: [u8; 32],
    },
}

impl SignerDescriptor {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            Self::AccountKey { public_key } => {
                bytes.push(0);
                bytes.extend(public_key);
            }
            Self::Delegated { account } => {
                bytes.push(1);
                bytes.extend(account);
            }
            Self::External {
                verifier,
                key_data_sha256,
            } => {
                bytes.push(2);
                string(&mut bytes, verifier);
                bytes.extend(key_data_sha256);
            }
        }
        bytes
    }
}

/// The credential domain a signature authorizes.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SubjectKind {
    /// A smart account contract credential.
    SmartAccount,
    /// A classic account address credential.
    AccountKey,
    /// The transaction source credential.
    SourceAccount,
}

/// A canonical credential and its authorization domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthSubject {
    kind: SubjectKind,
    credential: String,
}

impl AuthSubject {
    /// Returns the credential domain.
    #[must_use]
    pub fn kind(&self) -> SubjectKind {
        self.kind
    }

    /// Names a smart account credential.
    ///
    /// # Errors
    /// Refuses an address that is not a contract.
    pub fn smart_account(address: &ScAddress) -> Result<Self, &'static str> {
        if !matches!(address, ScAddress::Contract(_)) {
            return Err("auth_subjects");
        }
        Self::address(SubjectKind::SmartAccount, address)
    }

    /// Names a classic account credential.
    ///
    /// # Errors
    /// Refuses an address that is not an account.
    pub fn account_key(address: &ScAddress) -> Result<Self, &'static str> {
        if !matches!(address, ScAddress::Account(_)) {
            return Err("auth_subjects");
        }
        Self::address(SubjectKind::AccountKey, address)
    }

    fn address(kind: SubjectKind, address: &ScAddress) -> Result<Self, &'static str> {
        Ok(Self {
            kind,
            credential: scaddress_to_strkey(address).map_err(|_| "auth_subjects")?,
        })
    }

    /// Names the source account's envelope signing authority.
    ///
    /// # Errors
    /// Refuses a source that is not a canonical account strkey.
    pub fn source(envelope_source: &str) -> Result<Self, &'static str> {
        account_key(envelope_source)?;
        Ok(Self {
            kind: SubjectKind::SourceAccount,
            credential: envelope_source.into(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SubjectFacts {
    pub kind: SubjectKind,
    pub credential: String,
    pub nonce: Option<i64>,
    pub signature_expiration_ledger: Option<u32>,
    #[serde(with = "hash_hex")]
    pub invocation_sha256: [u8; 32],
    pub context_rule_ids: Vec<u32>,
    pub signers: Vec<SignerDescriptor>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SubjectStage {
    Credential,
    Nonce,
    Expiration,
    Invocation,
    RuleIds,
    Signers,
}

impl SubjectFacts {
    fn encode_through(&self, stage: SubjectStage) -> Vec<u8> {
        let mut bytes = vec![match self.kind {
            SubjectKind::SmartAccount => 0,
            SubjectKind::AccountKey => 1,
            SubjectKind::SourceAccount => 2,
        }];
        string(&mut bytes, &self.credential);
        if stage >= SubjectStage::Nonce {
            option(&mut bytes, self.nonce, |out, value| {
                out.extend(value.to_be_bytes())
            });
        }
        if stage >= SubjectStage::Expiration {
            option(
                &mut bytes,
                self.signature_expiration_ledger,
                |out, value| out.extend(value.to_be_bytes()),
            );
        }
        if stage >= SubjectStage::Invocation {
            bytes.extend(self.invocation_sha256);
        }
        if stage >= SubjectStage::RuleIds {
            count(&mut bytes, self.context_rule_ids.len());
            for id in &self.context_rule_ids {
                bytes.extend(id.to_be_bytes());
            }
        }
        if stage >= SubjectStage::Signers {
            count(&mut bytes, self.signers.len());
            for signer in &self.signers {
                bytes.extend(signer.encode());
            }
        }
        bytes
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        self.encode_through(SubjectStage::Signers)
    }

    fn validate(&self, envelope_source: &str) -> Result<(), &'static str> {
        match self.kind {
            SubjectKind::SmartAccount => {
                contract_key(&self.credential)?;
                if self.nonce.is_none()
                    || self.signature_expiration_ledger.is_none()
                    || self.context_rule_ids.is_empty()
                    || self.signers.is_empty()
                {
                    return Err("plan");
                }
                for signer in &self.signers {
                    match signer {
                        SignerDescriptor::AccountKey { .. } => return Err("plan"),
                        SignerDescriptor::External { verifier, .. } => {
                            contract_key(verifier)?;
                        }
                        SignerDescriptor::Delegated { .. } => {}
                    }
                }
            }
            SubjectKind::AccountKey => {
                let key = account_key(&self.credential)?;
                if self.nonce.is_none()
                    || self.signature_expiration_ledger.is_none()
                    || !self.context_rule_ids.is_empty()
                    || self.signers != [SignerDescriptor::AccountKey { public_key: key }]
                {
                    return Err("plan");
                }
            }
            SubjectKind::SourceAccount => {
                if self.credential != envelope_source
                    || self.nonce.is_some()
                    || self.signature_expiration_ledger.is_some()
                    || !self.context_rule_ids.is_empty()
                    || !self.signers.is_empty()
                {
                    return Err("plan");
                }
            }
        }
        if !self
            .signers
            .windows(2)
            .all(|pair| pair[0].encode() <= pair[1].encode())
        {
            return Err("plan");
        }
        Ok(())
    }

    fn auth_subject(&self) -> AuthSubject {
        AuthSubject {
            kind: self.kind,
            credential: self.credential.clone(),
        }
    }
}

/// An authorization subject whose invocation determines its payload.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntentSubject {
    facts: SubjectFacts,
    root_invocation: SorobanAuthorizedInvocation,
}

impl IntentSubject {
    /// Constructs a smart account subject from its authorization facts.
    ///
    /// # Errors
    /// Refuses a malformed credential or an invocation that cannot encode.
    pub fn smart_account(
        address: &ScAddress,
        nonce: i64,
        expiration: u32,
        root_invocation: &SorobanAuthorizedInvocation,
        rule_ids: Vec<u32>,
        mut signers: Vec<SignerDescriptor>,
    ) -> Result<Self, &'static str> {
        let subject = AuthSubject::smart_account(address)?;
        signers.sort_by_key(SignerDescriptor::encode);
        Ok(Self {
            facts: SubjectFacts {
                kind: subject.kind,
                credential: subject.credential,
                nonce: Some(nonce),
                signature_expiration_ledger: Some(expiration),
                invocation_sha256: xdr_hash(root_invocation)?,
                context_rule_ids: rule_ids,
                signers,
            },
            root_invocation: root_invocation.clone(),
        })
    }

    /// Constructs a classic account authorization subject.
    ///
    /// # Errors
    /// Refuses a malformed credential or an invocation that cannot encode.
    pub fn account_key(
        address: &ScAddress,
        nonce: i64,
        expiration: u32,
        root_invocation: &SorobanAuthorizedInvocation,
    ) -> Result<Self, &'static str> {
        let subject = AuthSubject::account_key(address)?;
        let key = account_key(&subject.credential)?;
        Ok(Self {
            facts: SubjectFacts {
                kind: subject.kind,
                credential: subject.credential,
                nonce: Some(nonce),
                signature_expiration_ledger: Some(expiration),
                invocation_sha256: xdr_hash(root_invocation)?,
                context_rule_ids: Vec::new(),
                signers: vec![SignerDescriptor::AccountKey { public_key: key }],
            },
            root_invocation: root_invocation.clone(),
        })
    }

    /// Constructs a source account authorization subject.
    ///
    /// # Errors
    /// Refuses a malformed source or an invocation that cannot encode.
    pub fn source_account(
        envelope_source: &str,
        root_invocation: &SorobanAuthorizedInvocation,
    ) -> Result<Self, &'static str> {
        let subject = AuthSubject::source(envelope_source)?;
        Ok(Self {
            facts: SubjectFacts {
                kind: subject.kind,
                credential: subject.credential,
                nonce: None,
                signature_expiration_ledger: None,
                invocation_sha256: xdr_hash(root_invocation)?,
                context_rule_ids: Vec::new(),
                signers: Vec::new(),
            },
            root_invocation: root_invocation.clone(),
        })
    }

    /// Decodes the authorization subject of an envelope entry.
    ///
    /// # Errors
    /// Refuses unsupported credentials or malformed signature payloads.
    pub fn of_entry(
        entry: &SorobanAuthorizationEntry,
        envelope_source: &str,
    ) -> Result<Self, &'static str> {
        match &entry.credentials {
            SorobanCredentials::SourceAccount => {
                Self::source_account(envelope_source, &entry.root_invocation)
            }
            SorobanCredentials::Address(credentials) => match &credentials.address {
                ScAddress::Contract(_) => {
                    let facts =
                        decode_auth_payload(&credentials.signature).map_err(|_| "auth_subjects")?;
                    let signers = facts
                        .signers
                        .into_iter()
                        .map(|signer| match signer {
                            AuthPayloadSigner::Delegated(account) => {
                                SignerDescriptor::Delegated { account }
                            }
                            AuthPayloadSigner::External { verifier, key_data } => {
                                SignerDescriptor::External {
                                    verifier: stellar_strkey::Contract(verifier)
                                        .to_string()
                                        .as_str()
                                        .into(),
                                    key_data_sha256: Sha256::digest(key_data).into(),
                                }
                            }
                        })
                        .collect();
                    Self::smart_account(
                        &credentials.address,
                        credentials.nonce,
                        credentials.signature_expiration_ledger,
                        &entry.root_invocation,
                        facts.context_rule_ids,
                        signers,
                    )
                }
                ScAddress::Account(_) => {
                    let mut subject = Self::account_key(
                        &credentials.address,
                        credentials.nonce,
                        credentials.signature_expiration_ledger,
                        &entry.root_invocation,
                    )?;
                    subject.facts.signers = classic_signers(&credentials.signature)?;
                    Ok(subject)
                }
                _ => Err("auth_subjects"),
            },
            _ => Err("auth_subjects"),
        }
    }

    /// Returns the authorization nonce when the subject has one.
    #[must_use]
    pub fn nonce(&self) -> Option<i64> {
        self.facts.nonce
    }
    /// Returns the authorization expiration when the subject has one.
    #[must_use]
    pub fn expiration(&self) -> Option<u32> {
        self.facts.signature_expiration_ledger
    }
    /// Returns the exact invocation this subject authorizes.
    #[must_use]
    pub fn root_invocation(&self) -> &SorobanAuthorizedInvocation {
        &self.root_invocation
    }
    /// Returns the canonical credential this subject authorizes.
    #[must_use]
    pub fn auth_subject(&self) -> AuthSubject {
        self.facts.auth_subject()
    }
}

fn classic_signers(signature: &ScVal) -> Result<Vec<SignerDescriptor>, &'static str> {
    let ScVal::Vec(Some(signatures)) = signature else {
        return Err("auth_subjects");
    };
    let mut signers = Vec::new();
    for signature in signatures.iter() {
        let ScVal::Map(Some(map)) = signature else {
            return Err("auth_subjects");
        };
        if map.len() != 2 {
            return Err("auth_subjects");
        }
        let (ScVal::Symbol(key), ScVal::Bytes(bytes), ScVal::Symbol(sig), ScVal::Bytes(sig_bytes)) =
            (&map[0].key, &map[0].val, &map[1].key, &map[1].val)
        else {
            return Err("auth_subjects");
        };
        if key.0.as_slice() != b"public_key"
            || sig.0.as_slice() != b"signature"
            || sig_bytes.0.len() != 64
        {
            return Err("auth_subjects");
        }
        let public_key = bytes.0.as_slice().try_into().map_err(|_| "auth_subjects")?;
        signers.push(SignerDescriptor::AccountKey { public_key });
    }
    signers.sort_by_key(SignerDescriptor::encode);
    Ok(signers)
}

/// The payload a signing request presents to its gate.
#[derive(Clone, Debug)]
pub enum SigningPayload<'a> {
    /// A smart account authorization digest.
    AuthDigest([u8; 32]),
    /// A classic account's Soroban authorization payload.
    AddressPayload([u8; 32]),
    /// The envelope whose signature becomes usable.
    Envelope(&'a TransactionEnvelope),
}

/// A payload derived from a plan's immutable facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlannedPayload {
    /// A smart account authorization digest.
    AuthDigest([u8; 32]),
    /// A classic account's Soroban authorization payload.
    AddressPayload([u8; 32]),
    /// The envelope is checked against all plan facts when requested.
    Envelope,
}

/// One permitted signing, with repeated values preserving multiplicity.
#[derive(Clone, Debug)]
pub struct PermittedSigning {
    /// The credential this signature authorizes.
    pub subject: AuthSubject,
    /// The signer that may produce the signature.
    pub signer: SignerDescriptor,
    /// The payload derived from the authorization facts.
    pub payload: PlannedPayload,
}

/// Authenticated operation authority retained with an intent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum IntentPurpose {
    /// An invocation without recognized persistent authority.
    Invoke,
    /// A schedule whose frozen operation requires terminal state evidence.
    TimelockSchedule {
        /// The canonical timelock contract address.
        timelock: String,
        /// The operation identity computed before admission.
        #[serde(with = "hash_hex")]
        operation_id: [u8; 32],
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PlanFacts {
    pub chain_scope: ChainScope,
    pub auth_address: String,
    pub envelope_source: String,
    pub envelope_sequence: i64,
    #[serde(with = "hash_hex")]
    pub host_invocation_sha256: [u8; 32],
    pub subjects: Vec<SubjectFacts>,
    pub greatest_expiration_ledger: Option<u32>,
    pub purpose: Option<IntentPurpose>,
    pub envelope_max_ledger: Option<u32>,
}

impl PlanFacts {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        account_key(&self.envelope_source)?;
        if self.envelope_sequence < 1 {
            return Err("plan");
        }
        for subject in &self.subjects {
            subject.validate(&self.envelope_source)?;
        }
        if !self
            .subjects
            .windows(2)
            .all(|pair| pair[0].encode() <= pair[1].encode())
            || self.greatest_expiration_ledger != self.execution_bound()
        {
            return Err("plan");
        }
        Ok(())
    }

    pub(crate) fn execution_bound(&self) -> Option<u32> {
        if self.subjects.iter().any(|subject| {
            subject.kind != SubjectKind::SourceAccount
                && subject.signature_expiration_ledger.is_none()
        }) || ((self.subjects.is_empty()
            || self
                .subjects
                .iter()
                .any(|s| s.kind == SubjectKind::SourceAccount))
            && self.envelope_max_ledger.is_none())
        {
            return None;
        }
        self.subjects
            .iter()
            .filter_map(|s| s.signature_expiration_ledger)
            .chain(self.envelope_max_ledger)
            .max()
    }

    pub(crate) fn same_authority(&self, other: &Self) -> bool {
        self.chain_scope == other.chain_scope
            && ((self.envelope_source == other.envelope_source
                && self.envelope_sequence == other.envelope_sequence
                && self.host_invocation_sha256 == other.host_invocation_sha256
                && self
                    .subjects
                    .iter()
                    .map(SubjectFacts::encode)
                    .eq(other.subjects.iter().map(SubjectFacts::encode)))
                || self.subjects.iter().any(|prior| {
                    prior.nonce.is_some()
                        && other.subjects.iter().any(|next| {
                            prior.credential == next.credential && prior.nonce == next.nonce
                        })
                }))
    }

    pub(crate) fn intent_id(&self) -> String {
        let mut bytes = b"stellar-agent-signed-intent:v2".to_vec();
        string(&mut bytes, &self.chain_scope.chain().to_string());
        bytes.extend(Sha256::digest(
            self.chain_scope.chain().network_passphrase().as_bytes(),
        ));
        string(&mut bytes, &self.auth_address);
        string(&mut bytes, &self.envelope_source);
        bytes.extend(self.envelope_sequence.to_be_bytes());
        bytes.extend(self.host_invocation_sha256);
        count(&mut bytes, self.subjects.len());
        for subject in &self.subjects {
            bytes.extend(subject.encode());
        }
        option(&mut bytes, self.greatest_expiration_ledger, |out, value| {
            out.extend(value.to_be_bytes())
        });
        match &self.purpose {
            None => bytes.push(0),
            Some(IntentPurpose::Invoke) => bytes.push(1),
            Some(IntentPurpose::TimelockSchedule {
                timelock,
                operation_id,
            }) => {
                bytes.push(2);
                string(&mut bytes, timelock);
                bytes.extend(operation_id);
            }
        }
        option(&mut bytes, self.envelope_max_ledger, |out, value| {
            out.extend(value.to_be_bytes())
        });
        format!(
            "intent-{}",
            crate::submit::bytes_to_hex(&Sha256::digest(bytes))
        )
    }

    pub(crate) fn compare(&self, other: &Self) -> Result<(), &'static str> {
        const STAGES: [(SubjectStage, &str); 6] = [
            (SubjectStage::Credential, "auth_subjects"),
            (SubjectStage::Nonce, "nonce"),
            (SubjectStage::Expiration, "expiration"),
            (SubjectStage::Invocation, "invocation"),
            (SubjectStage::RuleIds, "context_rule_ids"),
            (SubjectStage::Signers, "signers"),
        ];
        if self.purpose != other.purpose {
            return Err("purpose");
        }
        if self.envelope_max_ledger != other.envelope_max_ledger {
            return Err("expiration");
        }
        if self.chain_scope != other.chain_scope {
            return Err("chain");
        }
        if self.host_invocation_sha256 != other.host_invocation_sha256 {
            return Err("host_invocation");
        }
        if self.envelope_source != other.envelope_source {
            return Err("envelope_source");
        }
        if self.envelope_sequence != other.envelope_sequence {
            return Err("envelope_sequence");
        }
        for (stage, field) in STAGES {
            let projection = |subjects: &[SubjectFacts]| {
                let mut values: Vec<_> = subjects
                    .iter()
                    .map(|subject| subject.encode_through(stage))
                    .collect();
                values.sort();
                values
            };
            if projection(&self.subjects) != projection(&other.subjects) {
                return Err(field);
            }
        }
        if self.greatest_expiration_ledger != other.greatest_expiration_ledger {
            return Err("expiration");
        }
        Ok(())
    }
}

/// The complete authority fixed before signing admission.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct SignedIntentPlan {
    pub(crate) facts: PlanFacts,
    subjects: Vec<IntentSubject>,
    permitted: Vec<PermittedSigning>,
    legs: Vec<WindowEntry>,
    capability: Option<crate::signing::LedgerWitnessCapability>,
}

impl SignedIntentPlan {
    /// Validates authority facts and derives every permitted signing.
    ///
    /// # Errors
    /// Refuses malformed plans, unsupported networks, or payload encoding failures.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network_passphrase: &str,
        auth_address: &str,
        envelope_source: &str,
        envelope_sequence: i64,
        host_invocation_sha256: [u8; 32],
        mut subjects: Vec<IntentSubject>,
        greatest_expiration_ledger: Option<u32>,
    ) -> Result<Self, WalletError> {
        let chain_scope = ChainScope::from_passphrase(network_passphrase)?;
        subjects.sort_by_key(|subject| subject.facts.encode());
        if greatest_expiration_ledger != subjects.iter().filter_map(IntentSubject::expiration).max()
        {
            return Err(mismatch("plan"));
        }
        let mut facts = PlanFacts {
            chain_scope,
            auth_address: auth_address.into(),
            envelope_source: envelope_source.into(),
            envelope_sequence,
            host_invocation_sha256,
            subjects: subjects
                .iter()
                .map(|subject| subject.facts.clone())
                .collect(),
            greatest_expiration_ledger,
            purpose: None,
            envelope_max_ledger: None,
        };
        facts.greatest_expiration_ledger = facts.execution_bound();
        facts.validate().map_err(|_| mismatch("plan"))?;
        let mut permitted = Vec::new();
        for subject in &subjects {
            let sf = &subject.facts;
            if let (Some(nonce), Some(signature_expiration_ledger)) =
                (sf.nonce, sf.signature_expiration_ledger)
            {
                let address = match sf.kind {
                    SubjectKind::SmartAccount => ScAddress::Contract(stellar_xdr::ContractId(
                        Hash(contract_key(&sf.credential).map_err(|_| mismatch("plan"))?),
                    )),
                    SubjectKind::AccountKey => ScAddress::Account(stellar_xdr::AccountId(
                        stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(
                            account_key(&sf.credential).map_err(|_| mismatch("plan"))?,
                        )),
                    )),
                    SubjectKind::SourceAccount => return Err(mismatch("plan")),
                };
                let preimage = stellar_agent_soroban_auth::build_auth_preimage(
                    stellar_agent_soroban_auth::AuthCredentialsVersion::V1,
                    Sha256::digest(network_passphrase.as_bytes()).into(),
                    nonce,
                    signature_expiration_ledger,
                    &address,
                    subject.root_invocation.clone(),
                );
                let payload = match sf.kind {
                    SubjectKind::SmartAccount => {
                        let rule_ids: Vec<_> = sf
                            .context_rule_ids
                            .iter()
                            .copied()
                            .map(ContextRuleId::new)
                            .collect();
                        let encoded =
                            encode_context_rule_ids(&rule_ids).map_err(|_| mismatch("plan"))?;
                        PlannedPayload::AuthDigest(
                            *SmartAccountAuthDigest::new(&preimage, &encoded)?.as_bytes(),
                        )
                    }
                    SubjectKind::AccountKey => PlannedPayload::AddressPayload(
                        *SorobanAuthPayload::from_preimage(&preimage)?.as_bytes(),
                    ),
                    SubjectKind::SourceAccount => return Err(mismatch("plan")),
                };
                for signer in &sf.signers {
                    permitted.push(PermittedSigning {
                        subject: sf.auth_subject(),
                        signer: signer.clone(),
                        payload: payload.clone(),
                    });
                }
            }
        }
        permitted.push(PermittedSigning {
            subject: AuthSubject::source(envelope_source).map_err(mismatch)?,
            signer: SignerDescriptor::AccountKey {
                public_key: account_key(envelope_source).map_err(mismatch)?,
            },
            payload: PlannedPayload::Envelope,
        });
        Ok(Self {
            facts,
            subjects,
            permitted,
            legs: Vec::new(),
            capability: None,
        })
    }

    /// Freezes the exact exclusive envelope ledger bound.
    ///
    /// # Errors
    /// Refuses a zero bound.
    pub fn with_envelope_max_ledger(mut self, maximum: u32) -> Result<Self, WalletError> {
        if maximum == 0 {
            return Err(mismatch("expiration"));
        }
        self.facts.envelope_max_ledger = Some(maximum);
        self.facts.greatest_expiration_ledger = self.facts.execution_bound();
        Ok(self)
    }

    /// Classifies the checked host invocation and every authorization function.
    ///
    /// # Errors
    /// Refuses host facts that differ from the frozen invocation hash or schedule contract.
    pub fn classify_purpose(
        mut self,
        host: &stellar_xdr::HostFunction,
        schedule: Option<(&str, [u8; 32])>,
    ) -> Result<Self, WalletError> {
        if xdr_hash(host).map_err(mismatch)? != self.facts.host_invocation_sha256 {
            return Err(mismatch("purpose"));
        }
        self.facts.purpose = classify_purpose(host, &self.subjects, schedule).map_err(mismatch)?;
        Ok(self)
    }

    /// The authenticated operation purpose, when classification is complete.
    #[must_use]
    pub fn purpose(&self) -> Option<&IntentPurpose> {
        self.facts.purpose.as_ref()
    }

    /// Attaches the checked witness that precedes admission.
    #[must_use]
    pub fn with_capability(mut self, capability: crate::signing::LedgerWitnessCapability) -> Self {
        self.capability = Some(capability);
        self
    }
    /// Returns the acquired witness, when the signing path supplies one.
    #[must_use]
    pub fn capability(&self) -> Option<&crate::signing::LedgerWitnessCapability> {
        self.capability.as_ref()
    }
    /// Returns the plan's canonical chain scope.
    #[must_use]
    pub fn chain_scope(&self) -> ChainScope {
        self.facts.chain_scope
    }
    /// Returns the authorization subjects in canonical order.
    #[must_use]
    pub fn subjects(&self) -> &[IntentSubject] {
        &self.subjects
    }
    /// Returns the permitted signings, preserving multiplicity.
    #[must_use]
    pub fn permitted_signings(&self) -> &[PermittedSigning] {
        &self.permitted
    }
    /// Returns the entries frozen by admission.
    #[must_use]
    pub fn legs(&self) -> &[WindowEntry] {
        &self.legs
    }
    pub(crate) fn with_legs(&self, legs: &[WindowEntry]) -> Self {
        Self {
            legs: legs.to_vec(),
            ..self.clone()
        }
    }
    /// Checks an envelope before its signature becomes usable.
    ///
    /// # Errors
    /// Returns the first authorization field that differs from this plan.
    pub fn check_envelope(&self, envelope: &TransactionEnvelope) -> Result<(), &'static str> {
        let facts = BindFacts::from_envelope(
            envelope,
            self.facts.chain_scope.chain().network_passphrase(),
        )?;
        self.compare_bound(&facts)
    }
    pub(crate) fn compare_bound(&self, facts: &BindFacts) -> Result<(), &'static str> {
        facts.compare_to(&self.facts)
    }
}

/// Facts recomputed from a final envelope for durable binding.
#[derive(Clone, Debug)]
pub struct BindFacts {
    pub(crate) host: stellar_xdr::HostFunction,
    pub(crate) subjects: Vec<IntentSubject>,
    pub(crate) facts: PlanFacts,
    pub(crate) envelope_hash: String,
    pub(crate) tx_hash: String,
}

impl BindFacts {
    pub(crate) fn compare_to(&self, expected: &PlanFacts) -> Result<(), &'static str> {
        if matches!(
            expected.purpose,
            Some(IntentPurpose::TimelockSchedule { .. })
        ) && self.facts.host_invocation_sha256 != expected.host_invocation_sha256
        {
            return Err("purpose");
        }
        let mut bound = self.facts.clone();
        let schedule = match &expected.purpose {
            Some(IntentPurpose::TimelockSchedule {
                timelock,
                operation_id,
            }) => Some((timelock.as_str(), *operation_id)),
            _ => None,
        };
        bound.purpose = classify_purpose(&self.host, &self.subjects, schedule)?;
        if expected.purpose.is_none() {
            bound.purpose = None;
        }
        expected.compare(&bound)
    }

    /// Recomputes every authorization fact from the decoded envelope.
    ///
    /// # Errors
    /// Refuses unsupported envelope shapes or malformed authorization payloads.
    pub fn from_envelope(
        envelope: &TransactionEnvelope,
        network_passphrase: &str,
    ) -> Result<Self, &'static str> {
        let chain_scope = ChainScope::from_passphrase(network_passphrase).map_err(|_| "chain")?;
        let TransactionEnvelope::Tx(v1) = envelope else {
            return Err("host_invocation");
        };
        if v1.tx.operations.len() != 1 {
            return Err("host_invocation");
        }
        if v1.tx.operations[0].source_account.is_some() {
            return Err("envelope_source");
        }
        let OperationBody::InvokeHostFunction(op) = &v1.tx.operations[0].body else {
            return Err("host_invocation");
        };
        let (envelope_source, envelope_sequence) =
            crate::submit::replay_identity(envelope).map_err(|_| "envelope_source")?;
        let subjects = op
            .auth
            .iter()
            .map(|entry| IntentSubject::of_entry(entry, &envelope_source))
            .collect::<Result<Vec<_>, _>>()?;
        let mut subject_facts: Vec<_> = subjects
            .iter()
            .map(|subject| subject.facts.clone())
            .collect();
        subject_facts.sort_by_key(SubjectFacts::encode);
        let greatest_expiration_ledger = subject_facts
            .iter()
            .filter_map(|s| s.signature_expiration_ledger)
            .max();
        let envelope_max_ledger = match &v1.tx.cond {
            stellar_xdr::Preconditions::V2(v2) => match &v2.ledger_bounds {
                Some(bounds) if bounds.min_ledger != 0 => return Err("expiration"),
                Some(bounds) => Some(bounds.max_ledger),
                None => None,
            },
            _ => None,
        };
        if envelope_max_ledger == Some(0) {
            return Err("expiration");
        }
        let encoded = envelope
            .to_xdr_base64(Limits::none())
            .map_err(|_| "envelope")?;
        let mut facts = PlanFacts {
            chain_scope,
            auth_address: String::new(),
            envelope_source,
            envelope_sequence,
            host_invocation_sha256: xdr_hash(&op.host_function)?,
            subjects: subject_facts,
            greatest_expiration_ledger,
            purpose: classify_purpose(&op.host_function, &subjects, None)?,
            envelope_max_ledger,
        };
        facts.greatest_expiration_ledger = facts.execution_bound();
        Ok(Self {
            facts,
            host: op.host_function.clone(),
            subjects,
            envelope_hash: crate::submit::envelope_hash_hex(&encoded),
            tx_hash: crate::submit::compute_local_tx_hash_hex(envelope, network_passphrase)
                .map_err(|_| "envelope")?,
        })
    }
}

/// A single-use capability to expose an admitted signing plan.
#[must_use]
pub struct IntentProof {
    pub(crate) intent_id: Option<String>,
    pub(crate) cancel_token: [u8; 32],
    plan: SignedIntentPlan,
}

impl IntentProof {
    pub(crate) fn new(intent_id: Option<String>, plan: SignedIntentPlan) -> Self {
        let mut cancel_token = [0; 32];
        OsRng.fill_bytes(&mut cancel_token);
        Self {
            intent_id,
            cancel_token,
            plan,
        }
    }
    /// Returns the admitted plan and its frozen legs.
    #[must_use]
    pub fn plan(&self) -> &SignedIntentPlan {
        &self.plan
    }
    /// Consumes cancellation authority before a signer can expose bytes.
    #[must_use]
    pub fn expose(self) -> ExposedIntent {
        ExposedIntent {
            intent_id: self.intent_id,
            plan: self.plan,
        }
    }
}

/// An admitted intent whose signatures may be externally usable.
pub struct ExposedIntent {
    intent_id: Option<String>,
    plan: SignedIntentPlan,
}

impl ExposedIntent {
    /// Returns the durable identity, or none when no entries apply.
    #[must_use]
    pub fn intent_id(&self) -> Option<&str> {
        self.intent_id.as_deref()
    }
    /// Returns the immutable plan that admission charges.
    #[must_use]
    pub fn plan(&self) -> &SignedIntentPlan {
        &self.plan
    }
}

/// The exposure and decoded envelope presented for final binding.
pub struct IntentBinding<'a> {
    pub(crate) exposure: &'a ExposedIntent,
    pub(crate) envelope: &'a TransactionEnvelope,
}

impl<'a> IntentBinding<'a> {
    pub(crate) fn new(exposure: &'a ExposedIntent, envelope: &'a TransactionEnvelope) -> Self {
        Self { exposure, envelope }
    }
}

fn classify_purpose(
    host: &stellar_xdr::HostFunction,
    subjects: &[IntentSubject],
    schedule: Option<(&str, [u8; 32])>,
) -> Result<Option<IntentPurpose>, &'static str> {
    use stellar_xdr::{HostFunction, SorobanAuthorizedFunction};
    let HostFunction::InvokeContract(invoke) = host else {
        return Ok(None);
    };
    let allowance = |name: &[u8]| {
        matches!(
            name,
            b"approve" | b"increase_allowance" | b"approve_for_all"
        )
    };
    let schedule_host = schedule.is_some() && invoke.function_name.0.as_slice() == b"schedule";
    if let Some((timelock, _)) = schedule {
        contract_key(timelock).map_err(|_| "purpose")?;
        if !schedule_host
            || scaddress_to_strkey(&invoke.contract_address).map_err(|_| "purpose")? != timelock
        {
            return Err("purpose");
        }
    }
    if allowance(invoke.function_name.0.as_slice())
        || (!schedule_host && invoke.function_name.0.as_slice() == b"schedule")
    {
        return Ok(None);
    }
    let mut stack: Vec<_> = subjects
        .iter()
        .map(|subject| (&subject.root_invocation, true))
        .collect();
    while let Some((node, root)) = stack.pop() {
        let SorobanAuthorizedFunction::ContractFn(function) = &node.function else {
            return Ok(None);
        };
        if allowance(function.function_name.0.as_slice())
            || (function.function_name.0.as_slice() == b"schedule"
                && !(schedule_host && root && function == invoke))
        {
            return Ok(None);
        }
        stack.extend(node.sub_invocations.iter().map(|child| (child, false)));
    }
    Ok(Some(match schedule {
        Some((timelock, operation_id)) => IntentPurpose::TimelockSchedule {
            timelock: timelock.into(),
            operation_id,
        },
        None => IntentPurpose::Invoke,
    }))
}

fn account_key(address: &str) -> Result<[u8; 32], &'static str> {
    let key =
        stellar_strkey::ed25519::PublicKey::from_string(address).map_err(|_| "auth_subjects")?;
    if key.to_string().as_str() != address {
        return Err("auth_subjects");
    }
    Ok(key.0)
}

fn contract_key(address: &str) -> Result<[u8; 32], &'static str> {
    let key = stellar_strkey::Contract::from_string(address).map_err(|_| "auth_subjects")?;
    if key.to_string().as_str() != address {
        return Err("auth_subjects");
    }
    Ok(key.0)
}

/// Computes the SHA-256 of an XDR value for an intent plan.
///
/// # Errors
/// Refuses a value that cannot encode.
pub fn intent_xdr_hash(value: &impl WriteXdr) -> Result<[u8; 32], &'static str> {
    xdr_hash(value)
}

fn xdr_hash(value: &impl WriteXdr) -> Result<[u8; 32], &'static str> {
    Ok(Sha256::digest(value.to_xdr(Limits::none()).map_err(|_| "invocation")?).into())
}

pub(crate) fn mismatch(field: &'static str) -> WalletError {
    SubmissionError::IntentBindingMismatch { field }.into()
}

fn count(out: &mut Vec<u8>, value: usize) {
    out.extend((value as u32).to_be_bytes());
}
fn string(out: &mut Vec<u8>, value: &str) {
    count(out, value.len());
    out.extend(value.as_bytes());
}
fn option<T>(out: &mut Vec<u8>, value: Option<T>, encode: impl FnOnce(&mut Vec<u8>, T)) {
    if let Some(value) = value {
        out.push(1);
        encode(out, value);
    } else {
        out.push(0);
    }
}

pub(crate) mod hash_hex {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&crate::submit::bytes_to_hex(value))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let value = String::deserialize(deserializer)?;
        let decoded =
            stellar_agent_core::hex::decode_hex32(&value).map_err(serde::de::Error::custom)?;
        if crate::submit::bytes_to_hex(&decoded) != value {
            return Err(serde::de::Error::custom("noncanonical hash"));
        }
        Ok(decoded)
    }
}

pub(crate) mod option_hash_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        value: &Option<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => serializer.serialize_some(&crate::submit::bytes_to_hex(value)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<[u8; 32]>, D::Error> {
        #[derive(Deserialize)]
        struct Hash(#[serde(with = "super::hash_hex")] [u8; 32]);
        Ok(Option::<Hash>::deserialize(deserializer)?.map(|hash| hash.0))
    }
}

/// A required capability for signing admission.
pub enum SigningAdmission<'a> {
    /// Records the intent and binds its final submission.
    Recorded(&'a dyn crate::SubmissionRecorder),
    /// Charges count limits for a call with no value leg.
    NoValue(&'a NoValueAdmission),
}

impl<'a> SigningAdmission<'a> {
    /// Admits the complete plan before any signature.
    ///
    /// # Errors
    /// Refuses unverified sizing, unavailable state, or a policy limit.
    pub async fn admit(&self, plan: &SignedIntentPlan) -> Result<IntentProof, WalletError> {
        match self {
            Self::Recorded(recorder) => recorder.admit_signed_intent(plan).await,
            Self::NoValue(admission) => admission.admit(plan).await,
        }
    }
    /// Cancels a proof that no signing request consumes.
    ///
    /// # Errors
    /// Returns a typed intent error when cancellation cannot be recorded.
    pub async fn cancel_unexposed(&self, proof: IntentProof) -> Result<(), WalletError> {
        match self {
            Self::Recorded(recorder) => recorder.cancel_unexposed(proof).await,
            Self::NoValue(admission) => admission.cancel_unexposed(proof).await,
        }
    }
    /// Returns the recorder that binds final submission.
    #[must_use]
    pub fn recorder(&self) -> Option<&'a dyn crate::SubmissionRecorder> {
        match self {
            Self::Recorded(recorder) => Some(*recorder),
            Self::NoValue(_) => None,
        }
    }
}

/// Checked count admission for a signing flow without a value leg.
pub struct NoValueAdmission {
    profile: stellar_agent_core::profile::schema::Profile,
    window: crate::policy_state::PersistedWindowStore,
    sizing: stellar_agent_core::policy::v1::CheckedSizing,
}

impl NoValueAdmission {
    /// Builds admission over the profile's durable window.
    ///
    /// # Errors
    /// Refuses a basis or entry that can charge value.
    pub fn new(
        profile: stellar_agent_core::profile::schema::Profile,
        profile_name: &str,
        sizing: stellar_agent_core::policy::v1::CheckedSizing,
    ) -> Result<Self, WalletError> {
        Self::with_store(
            profile,
            crate::policy_state::PersistedWindowStore::for_profile(profile_name),
            sizing,
        )
    }
    /// Builds admission over an explicit durable window.
    ///
    /// # Errors
    /// Refuses a basis or entry that can charge value.
    pub fn with_store(
        profile: stellar_agent_core::profile::schema::Profile,
        window: crate::policy_state::PersistedWindowStore,
        sizing: stellar_agent_core::policy::v1::CheckedSizing,
    ) -> Result<Self, WalletError> {
        use stellar_agent_core::policy::v1::{SizingBasis, criteria::WindowLimit};
        if !matches!(
            sizing.basis(),
            SizingBasis::NoValue | SizingBasis::NoApplicableLimit
        ) || sizing
            .entries()
            .iter()
            .any(|entry| matches!(entry.limit(), WindowLimit::Amount { .. }))
        {
            return Err(unavailable("value_leg_refused"));
        }
        Ok(Self {
            profile,
            window,
            sizing,
        })
    }
    /// Charges this call before signing and freezes the admitted entries.
    ///
    /// # Errors
    /// Refuses a different network, unavailable state, or a count limit.
    pub async fn admit(&self, plan: &SignedIntentPlan) -> Result<IntentProof, WalletError> {
        admit_checked(&self.profile, &self.window, &self.sizing, plan)
    }
    /// Cancels an admission only while the caller holds its unconsumed proof.
    ///
    /// # Errors
    /// Refuses unavailable state or a bound intent.
    pub async fn cancel_unexposed(&self, proof: IntentProof) -> Result<(), WalletError> {
        if proof.intent_id.is_none() {
            return Ok(());
        }
        self.window
            .cancel_signed_intent(&self.profile, proof)
            .map_err(store_refusal)
    }
}

pub(crate) fn admit_checked(
    profile: &stellar_agent_core::profile::schema::Profile,
    window: &crate::policy_state::PersistedWindowStore,
    sizing: &stellar_agent_core::policy::v1::CheckedSizing,
    plan: &SignedIntentPlan,
) -> Result<IntentProof, WalletError> {
    plan.chain_scope()
        .require_profile(profile)
        .map_err(store_refusal)?;
    let frozen = plan.with_legs(sizing.entries());
    window
        .admit_signed_intent(profile, &frozen)
        .map_err(store_refusal)
}

pub(crate) fn unavailable(class: &'static str) -> WalletError {
    SubmissionError::IntentRecordUnavailable { class }.into()
}

pub(crate) fn store_refusal(error: crate::policy_state::WindowStoreError) -> WalletError {
    use crate::policy_state::WindowStoreError;
    if let Some(error) = error.chain_validation_error() {
        return WalletError::Validation(error);
    }
    match error {
        WindowStoreError::PolicyDenied { reason } => WalletError::PolicyDenied { reason },
        WindowStoreError::IntentBindingMismatch { field } => mismatch(field),
        _ => unavailable("window_unavailable"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test assertions")]
    use super::*;
    use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;

    fn empty_plan(sequence: i64) -> Result<SignedIntentPlan, WalletError> {
        SignedIntentPlan::new(
            TESTNET_PASSPHRASE,
            "fixture",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
            sequence,
            [7; 32],
            Vec::new(),
            None,
        )
    }

    #[test]
    fn intent_identity_known_answer_and_leg_independence() {
        use stellar_agent_core::policy::v1::criteria::{WindowLimit, state_store::StateKey};
        let plan = empty_plan(1).unwrap();
        assert_eq!(
            plan.facts.intent_id(),
            "intent-81fe93946f940554a2cf311403afec303ebd5bfa92c70e1862c2a06ae0646e51"
        );
        let with_legs = plan.with_legs(&[WindowEntry::new(
            StateKey::new("fixture", 1, "rate_limit", 60),
            1000,
            1,
            WindowLimit::Count {
                window: "1m".into(),
                max_calls: 1,
            },
        )]);
        assert_eq!(plan.facts.intent_id(), with_legs.facts.intent_id());
        assert_ne!(
            plan.facts.intent_id(),
            empty_plan(2).unwrap().facts.intent_id()
        );
        assert!(empty_plan(0).is_err());
        assert_eq!(plan.permitted_signings().len(), 1);
    }

    #[test]
    fn intent_identity_known_answer_covers_every_subject_kind() {
        let facts = PlanFacts {
            chain_scope: ChainScope::from_passphrase(TESTNET_PASSPHRASE).unwrap(),
            auth_address: "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ".into(),
            envelope_source: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF".into(),
            envelope_sequence: 4_294_967_297,
            host_invocation_sha256: [7; 32],
            subjects: vec![
                SubjectFacts {
                    kind: SubjectKind::SmartAccount,
                    credential: "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ".into(),
                    nonce: Some(0x0102_0304_0506_0708),
                    signature_expiration_ledger: Some(1_000_000),
                    invocation_sha256: [8; 32],
                    context_rule_ids: vec![3, 1],
                    signers: vec![
                        SignerDescriptor::Delegated { account: [4; 32] },
                        SignerDescriptor::External {
                            verifier: "CACQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQLC2U"
                                .into(),
                            key_data_sha256: [6; 32],
                        },
                    ],
                },
                SubjectFacts {
                    kind: SubjectKind::AccountKey,
                    credential: "GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H".into(),
                    nonce: Some(42),
                    signature_expiration_ledger: Some(999_999),
                    invocation_sha256: [9; 32],
                    context_rule_ids: vec![],
                    signers: vec![SignerDescriptor::AccountKey {
                        public_key: [1; 32],
                    }],
                },
                SubjectFacts {
                    kind: SubjectKind::SourceAccount,
                    credential: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF".into(),
                    nonce: None,
                    signature_expiration_ledger: None,
                    invocation_sha256: [10; 32],
                    context_rule_ids: vec![],
                    signers: vec![],
                },
            ],
            greatest_expiration_ledger: Some(1_000_000),
            purpose: Some(IntentPurpose::Invoke),
            envelope_max_ledger: Some(1_000_000),
        };
        assert!(facts.validate().is_ok());
        assert_eq!(
            facts.intent_id(),
            "intent-25abc1062d314e742df61ac2330ca880f685450608851ce5dee31afb588ec260"
        );
        let mut duplicate = facts.clone();
        duplicate.subjects.insert(1, duplicate.subjects[0].clone());
        assert!(duplicate.validate().is_ok());
        assert_eq!(
            duplicate.intent_id(),
            "intent-7570e32798474ceee2884af73c99467ebe54f0f85482fc82ffee04d6021e867a"
        );
    }

    #[test]
    fn canonical_subject_rejects_another_address_kind() {
        let account = ScAddress::Account(stellar_xdr::AccountId(
            stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256([0; 32])),
        ));
        let contract = ScAddress::Contract(stellar_xdr::ContractId(Hash([1; 32])));
        assert_eq!(AuthSubject::smart_account(&account), Err("auth_subjects"));
        assert_eq!(AuthSubject::account_key(&contract), Err("auth_subjects"));
        assert!(AuthSubject::source("not-an-account").is_err());
    }

    #[test]
    fn proof_exposure_keeps_frozen_plan() {
        let proof = IntentProof::new(None, empty_plan(1).unwrap());
        let exposure = proof.expose();
        assert!(exposure.intent_id().is_none());
        assert_eq!(
            exposure.plan().facts.intent_id(),
            "intent-81fe93946f940554a2cf311403afec303ebd5bfa92c70e1862c2a06ae0646e51"
        );
    }
}

#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers;

#[cfg(test)]
mod closure_tests;
