//! E2E integration tests for LNVPS API endpoints.
//!
//! These tests run against a local server by default and verify that all
//! endpoints return expected HTTP status codes and response shapes.
//! Includes CRUD lifecycle tests for admin resources and RBAC permission tests.
//!
//! # Environment Variables
//!
//! - `LNVPS_API_URL` — Base URL for the user API (default: `http://localhost:8000`)
//! - `LNVPS_ADMIN_API_URL` — Base URL for the admin API (default: `http://localhost:8001`)
//! - `LNVPS_DB_URL` — Database connection string (default: `mysql://root:root@localhost:3376/lnvps`)
//! - `NOSTR_SECRET_KEY` — Hex-encoded Nostr secret key for user API auth (random key generated if unset)
//! - `ADMIN_NOSTR_SECRET_KEY` — Hex-encoded Nostr secret key for admin API auth (random key generated if unset)

mod admin_api;
pub mod client;
pub mod db;
mod lifecycle;
pub mod nip98;
mod rbac;
mod user_api;
