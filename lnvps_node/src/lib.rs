//! The LNVPS marketplace node daemon.
//!
//! Runs on hardware LNVPS does not own, so the trust model is inverted
//! throughout: the operator is not assumed hostile, but nothing here depends on
//! them being honest either.
//!
//! - [`credential`] — how the node authenticates *outbound* to LNVPS, as the
//!   operator's own consumer account.
//! - [`control_auth`] — how the node verifies *inbound* commands really came
//!   from LNVPS, against a public key compiled into the binary.
//! - [`tls`] — the node's TLS identity, whose fingerprint LNVPS pins at
//!   registration, so the node's *replies* are authenticated too.
//! - [`inventory`] — what the node reports about the machine.
//! - [`config`] — configuration, including where the control API may listen.

pub mod config;
pub mod control_auth;
pub mod credential;
pub mod inventory;
pub mod tls;
