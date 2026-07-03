//! Oracle-staleness view and criterion types for Blend pools.
//!
//! The protocol-agnostic oracle-staleness substrate lives in
//! [`stellar_agent_defi::oracle_staleness`] so `stellar-agent-defindex` can
//! reuse it without a `defindex → blend` dependency edge.  This module
//! re-exports the items Blend consumers reach via
//! `stellar_agent_blend::oracle`.
//!
//! The Blend-specific oracle reads (Reflector allowlist,
//! `read_pool_oracle_address`, `query_oracle_lastprice_timestamps`) live in
//! [`crate::pins`] and [`crate::oracle_fetch`] because they reference Blend
//! data-key encodings.

pub use stellar_agent_defi::oracle_staleness::{
    DEFAULT_MAX_STALENESS_SECS, OracleStalenessDenialReason, OracleStalenessEvalExt,
    OracleStalenessSnapshot, OracleStalenessView,
};
