//! Executes contract invocations in input order and returns their results.
//!
//! The caller authorizes `exec` with its full arguments, which covers the whole
//! bundle. A failing inner call aborts `exec` and rolls back the bundle. The
//! router directly invokes every inner call, so any caller can satisfy
//! `require_auth` for the router's address through it; that address must hold
//! no assets or roles. The instance TTL extends to 30 days when fewer than 23
//! days remain, at 17,280 ledgers per day. The interface originates in
//! Stellar's smart-wallet-demo-app router, based on Creit Tech's
//! Stellar-Router-Contract.

#![no_std]

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Val, Vec};

const LEDGERS_PER_DAY: u32 = 17_280;
const INSTANCE_TTL_THRESHOLD: u32 = 23 * LEDGERS_PER_DAY;
const INSTANCE_TTL_EXTEND_TO: u32 = 30 * LEDGERS_PER_DAY;

/// Routes a caller-authorized bundle of contract invocations.
#[contract]
pub struct MulticallRouter;

#[contractimpl]
impl MulticallRouter {
    /// Invokes each entry in order under the caller's authorization.
    ///
    /// # Panics
    ///
    /// Aborts when authorization fails or an inner invocation fails. The host
    /// rolls back all changes made by the bundle.
    pub fn exec(
        e: Env,
        caller: Address,
        invocations: Vec<(Address, Symbol, Vec<Val>)>,
    ) -> Vec<Val> {
        e.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
        caller.require_auth();
        let mut results = Vec::new(&e);
        for (contract, function, args) in invocations {
            results.push_back(e.invoke_contract::<Val>(&contract, &function, args));
        }
        results
    }
}

#[cfg(test)]
mod test;
