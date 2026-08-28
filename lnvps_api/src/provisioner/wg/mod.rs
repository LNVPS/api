//! WireGuard interface management, independent of what is carried over it.
//!
//! - [`address`] — the arithmetic of a block: reserved addresses, carving.
//! - [`plan`] — the desired state of one interface.
//! - [`apply`] — reconciling a route server against that state.
//!
//! Nothing here knows about marketplace nodes or VPN devices. Those live with
//! their own consumers and meet this code at `tunnel`, `tunnel_pool` and
//! `tunnel_route`.

pub mod address;
pub mod apply;
pub mod plan;

pub use address::*;
pub use apply::*;
pub use plan::*;
