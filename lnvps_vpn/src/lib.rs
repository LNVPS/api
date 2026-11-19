//! `lvd` — the LNVPS VPN daemon.
//!
//! Runs on a route server and makes it carry the interfaces LNVPS says it
//! should. One interface per tunnel pool, one peer per customer device.
//!
//! Everything is outbound. The daemon asks what it should be and applies the
//! answer; nothing dials it. A route server runs wherever its region is, which
//! means behind somebody else's NAT, on a residential-grade uplink, or on a
//! provider that filters inbound, and a design that needed to reach it would
//! work everywhere it was tested and fail on the one machine nobody thought
//! about. The way that failure surfaces is a revoked device that keeps
//! working, so it is not a failure anyone would notice quickly.
//!
//! To get the speed of a push out of a pull, the fetch waits: the daemon sends
//! the generation it last applied and LNVPS holds the request until that moves.
//! A revoked key stops being honoured in about one round trip.
//!
//! What this daemon deliberately does not do:
//!
//! - **NAT and egress filtering.** The route server does its own, configured by
//!   whoever built it. LNVPS manages interfaces and peers.
//! - **Logging who connected.** A peer is a key and the addresses it may use.
//!   The daemon never learns whose it is, because it is never told.
//! - **Keeping a customer's address longer than it must.** WireGuard records
//!   where each peer was last heard from, which for a device is somebody's real
//!   address. [`scrub`] removes it once the peer has gone quiet.

pub mod apply;
pub mod client;
pub mod config;
pub mod scrub;
