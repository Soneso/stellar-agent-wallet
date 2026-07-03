//! Bridge middleware sub-modules.
//!
//! Provides the tower `Layer` implementations that form the bridge's layered
//! defence stack. Each middleware is a separate module so each defence can be
//! reasoned about independently.

pub mod host_header;
pub mod origin_header;
pub mod security_headers;

pub use host_header::HostHeaderAllowlistLayer;
pub use origin_header::OriginHeaderAllowlistLayer;
pub use security_headers::SecurityHeadersLayer;
