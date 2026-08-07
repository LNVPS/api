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
//! - [`control`] — the inbound HTTPS control API, authenticated on every request.
//! - [`tls`] — the node's TLS identity, whose fingerprint LNVPS pins at
//!   registration, so the node's *replies* are authenticated too.
//! - [`inventory`] — what the node reports about the machine.
//! - [`api`] — outbound calls to LNVPS, the only direction that works before
//!   there is a tunnel.
//! - [`net`] — applying the data plane LNVPS asked for, over netlink.
//! - [`netns`] — the namespace that data plane lives in, so LNVPS configures
//!   its own network rather than the operator's.
//! - [`wgkey`] — the node's WireGuard key, generated here and never sent.
//! - [`config`] — configuration, including where the control API may listen.

pub mod api;
pub mod config;
pub mod control;
pub mod control_auth;
pub mod credential;
pub mod inventory;
pub mod net;
pub mod netns;
pub mod tls;
pub mod wgkey;
