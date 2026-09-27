//! CAP-85 executable-reference beacon.
//!
//! The beacon owns executable-reference entries: persistent `ContractData`
//! entries keyed by `ScVal::ExecutableTag(tag)` whose value is the 32-byte
//! hash of an uploaded Wasm. A contract deployed with
//! `ContractExecutable::ExternalRef { executable_owner: <beacon>, tag }` runs
//! whichever Wasm the beacon's entry for `tag` names at invocation time, so
//! repointing the entry changes the code of every such contract at once.
//!
//! The wallet's testnet acceptance suites use the beacon to create a
//! reference contract and to repoint it, which exercises the wallet's
//! handling of owner-managed executables end to end.
//!
//! # Authority
//!
//! The admin passed to the constructor authorizes every write: publishing or
//! repointing a tag and deploying a reference contract. Reads are open.

#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, Address, BytesN, ContractExecutable,
    ContractExecutableRef, Env, String,
};

/// Instance-storage keys of the beacon's own state.
#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// The address that authorizes every write.
    Admin,
}

/// The executable-reference beacon contract.
#[contract]
pub struct Cap85Beacon;

#[contractimpl]
impl Cap85Beacon {
    /// Records `admin` as the address that authorizes every write.
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// Points the executable-reference entry for `tag` at `wasm_hash`,
    /// creating the entry when it does not exist.
    ///
    /// Requires the admin's authorization. The host refuses a `wasm_hash`
    /// that is not the hash of an uploaded Wasm. Every contract whose
    /// executable references this beacon and `tag` runs the new Wasm from its
    /// next invocation.
    pub fn publish(env: Env, tag: String, wasm_hash: BytesN<32>) {
        read_admin(&env).require_auth();
        env.executable_refs().set(&tag, &wasm_hash);
    }

    /// Returns the Wasm hash the entry for `tag` names, or `None` when the
    /// beacon has not published `tag`.
    pub fn get_ref(env: Env, tag: String) -> Option<BytesN<32>> {
        env.executable_refs().get(&tag)
    }

    /// Deploys a contract, with no constructor arguments, whose executable is
    /// the external reference `(this beacon, tag)`, and returns its address.
    ///
    /// Requires the admin's authorization. The address derives from the
    /// beacon's address and `salt`. The host refuses a tag the beacon has not
    /// published.
    pub fn deploy_ref(env: Env, tag: String, salt: BytesN<32>) -> Address {
        read_admin(&env).require_auth();
        let executable = ContractExecutable::ExternalRef(ContractExecutableRef {
            owner: env.current_contract_address(),
            tag,
        });
        env.deployer()
            .with_current_contract(salt)
            .deploy_contract(executable, ())
    }
}

/// Reads the admin from instance storage. The constructor runs at creation
/// and always records it, so the entry is present on every deployed beacon.
fn read_admin(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&DataKey::Admin)
        .expect("the constructor records the admin")
}
