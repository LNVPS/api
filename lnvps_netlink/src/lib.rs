//! Configuring a WireGuard data plane on Linux, over netlink.
//!
//! Shared by the two daemons LNVPS runs on machines it does not administer by
//! hand: `lnvps-node`, which terminates one tunnel to a route server and puts
//! guests behind it, and `lvd`, which terminates one interface per VPN region
//! and carries a peer per customer device. Both configure interfaces,
//! addresses, routes and WireGuard itself, and neither should have its own
//! answer for how.
//!
//! Interfaces, addresses and routes are managed over **netlink**, not by
//! shelling out to `ip`. Netlink is the interface the kernel actually offers;
//! `ip` is a program that formats netlink messages and then formats the answer
//! back into text for us to parse. Going direct means no dependency on
//! iproute2's presence or version, no output parsing that changes between
//! releases, no arguments to quote, and errors that arrive as kernel error
//! codes instead of a line of English on stderr.
//!
//! What is *not* here is any notion of what the data plane is for. This crate
//! knows how to make the kernel do a thing; deciding which things to do, and
//! reconciling that against what LNVPS asked for, belongs to the daemon.

pub mod kernel;
pub mod netns;
pub mod ops;
pub mod sysctl;

pub use kernel::Kernel;
pub use ops::{NetOps, UnavailableKernel, WgObserved, WgSettings};
pub use sysctl::{PROC_SYS, read_sysctl, write_sysctl};
