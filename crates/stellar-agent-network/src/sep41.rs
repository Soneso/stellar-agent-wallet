//! Protocol-neutral SEP-41 invocation construction.
//!
//! This module owns only the typed XDR shape of a SEP-41
//! `transfer(from, to, amount)` call. Protocol crates remain responsible for
//! parsing and validating their wire-format addresses and amounts.

use stellar_xdr::{ContractId, InvokeContractArgs, ScAddress, ScSymbol, ScVal, StringM, VecM};
use thiserror::Error;

/// Failure while constructing a typed SEP-41 transfer invocation.
#[derive(Debug, Error)]
pub enum Sep41BuildError {
    /// The fixed `transfer` function symbol could not be represented as XDR.
    #[error("SEP-41 transfer function symbol construction failed")]
    FunctionSymbol,

    /// The fixed three-element argument list could not be represented as XDR.
    #[error("SEP-41 transfer argument construction failed")]
    Arguments,
}

/// Builds the typed XDR invocation for `transfer(from, to, amount)`.
///
/// Callers must validate the contract, address kinds, and amount according to
/// their own protocol before invoking this function.
///
/// # Errors
///
/// Returns [`Sep41BuildError`] if the fixed function symbol or argument vector
/// cannot be represented by the bounded XDR types.
///
/// # Examples
///
/// ```
/// use stellar_agent_network::sep41::build_sep41_transfer_invoke;
/// use stellar_xdr::{AccountId, ContractId, Hash, PublicKey, ScAddress, Uint256};
///
/// let contract = ContractId(Hash([1; 32]));
/// let account = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(
///     Uint256([2; 32]),
/// )));
/// let invoke = build_sep41_transfer_invoke(contract, account.clone(), account, 10)?;
/// assert_eq!(invoke.args.len(), 3);
/// # Ok::<(), stellar_agent_network::sep41::Sep41BuildError>(())
/// ```
pub fn build_sep41_transfer_invoke(
    contract: ContractId,
    from: ScAddress,
    to: ScAddress,
    amount: i128,
) -> Result<InvokeContractArgs, Sep41BuildError> {
    let args: VecM<ScVal> = vec![
        ScVal::Address(from),
        ScVal::Address(to),
        ScVal::from(amount),
    ]
    .try_into()
    .map_err(|_error| Sep41BuildError::Arguments)?;

    let function_name: StringM<32> = "transfer"
        .try_into()
        .map_err(|_error| Sep41BuildError::FunctionSymbol)?;

    Ok(InvokeContractArgs {
        contract_address: ScAddress::Contract(contract),
        function_name: ScSymbol(function_name),
        args,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test-only assertions use unwrap for concise fixture setup"
    )]

    use super::*;
    use stellar_xdr::{AccountId, Hash, PublicKey, Uint256};

    #[test]
    fn builds_exact_transfer_shape() {
        let contract = ContractId(Hash([1; 32]));
        let from = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([2; 32]))));
        let to = ScAddress::Contract(ContractId(Hash([3; 32])));

        let invoke =
            build_sep41_transfer_invoke(contract.clone(), from.clone(), to.clone(), 42).unwrap();

        assert_eq!(invoke.contract_address, ScAddress::Contract(contract));
        assert_eq!(invoke.function_name.0.as_vec(), b"transfer");
        assert_eq!(invoke.args.len(), 3);
        assert_eq!(invoke.args.first(), Some(&ScVal::Address(from)));
        assert_eq!(invoke.args.get(1), Some(&ScVal::Address(to)));
        assert_eq!(invoke.args.get(2), Some(&ScVal::from(42_i128)));
    }
}
