//! WireGuard interface management, independent of what is carried over it.
//!
//! - [`address`] — the arithmetic of a block: reserved addresses, carving.
//! - [`plan`] — the desired state of one interface.
//! - [`provisioner`] — `TunnelProvisioner`: planning, carving and reconciling.
//!
//! Nothing here knows about marketplace nodes or VPN devices. Those live with
//! their own consumers and meet this code at `tunnel`, `tunnel_pool` and
//! `tunnel_route`.

pub mod address;
pub mod plan;
pub mod provisioner;

pub use address::*;
pub use plan::*;
pub use provisioner::*;
