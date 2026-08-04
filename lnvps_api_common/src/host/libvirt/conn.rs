//! Async-safe wrapper around libvirt's synchronous C API.
//!
//! Every `virConnect*` / `virDomain*` call blocks the calling thread — for a
//! remote (`qemu+ssh://`) connection that can mean seconds. Running those
//! directly inside an async task would stall the whole tokio worker, so all
//! libvirt work is dispatched onto the blocking pool via [`LibVirtConn::run`].
//!
//! The connection is also re-opened transparently when libvirt reports it as
//! dead, so a hypervisor restart doesn't permanently break the host client.

use crate::retry::{OpError, OpResult};
use anyhow::{Result, anyhow};
use log::warn;
use std::sync::{Arc, Mutex, Once};
use virt::connect::Connect;

static EVENT_LOOP: Once = Once::new();

/// Start libvirt's default event loop exactly once per process.
///
/// `qemu:///system` goes through libvirtd's remote driver, where **stream data
/// is only delivered while an event loop is running**. Without this,
/// `virDomainOpenConsole` succeeds and then every read returns "would block"
/// forever — a serial console that is silently, permanently empty.
///
/// Must run before any connection is opened, hence the call from
/// [`LibVirtConn::open`].
fn ensure_event_loop() {
    EVENT_LOOP.call_once(|| {
        if let Err(e) = virt::event::event_register_default_impl() {
            warn!(
                "failed to register libvirt event loop ({}); serial console will not work",
                e.message()
            );
            return;
        }
        if let Err(e) = std::thread::Builder::new()
            .name("libvirt-events".to_string())
            .spawn(|| {
                loop {
                    if let Err(e) = virt::event::event_run_default_impl() {
                        // Back off rather than spin if the loop breaks.
                        warn!("libvirt event loop error: {}", e.message());
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                }
            })
        {
            warn!("failed to spawn libvirt event loop thread: {}", e);
        }
    });
}

/// A lazily-reconnecting libvirt connection.
pub struct LibVirtConn {
    uri: String,
    /// `Connect` is `Send + Sync` (libvirt connections are thread-safe), so the
    /// mutex only guards *replacement* of a dead connection, not its use.
    conn: Mutex<Arc<Connect>>,
}

impl std::fmt::Debug for LibVirtConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LibVirtConn")
            .field("uri", &self.uri)
            .finish()
    }
}

impl LibVirtConn {
    pub fn open(uri: &str) -> Result<Self> {
        ensure_event_loop();
        let conn = Connect::open(Some(uri))
            .map_err(|e| anyhow!("failed to connect to libvirt at {}: {}", uri, e.message()))?;
        Ok(Self {
            uri: uri.to_string(),
            conn: Mutex::new(Arc::new(conn)),
        })
    }

    /// Get a live connection handle, re-opening it if libvirt says the previous
    /// one is dead.
    ///
    /// Exposed for long-lived work (the serial console pump) that outlives a
    /// single [`Self::run`] call and must own the connection itself.
    pub fn handle(&self) -> OpResult<Arc<Connect>> {
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| OpError::Fatal(anyhow!("libvirt connection mutex poisoned")))?;

        // `is_alive` is a local state check, not an RPC round-trip.
        if guard.is_alive().unwrap_or(false) {
            return Ok(guard.clone());
        }

        warn!("libvirt connection to {} is dead, reconnecting", self.uri);
        let fresh = Connect::open(Some(&self.uri)).map_err(|e| {
            // A hypervisor that is down may come back — always retryable.
            OpError::Transient(anyhow!(
                "failed to reconnect to libvirt at {}: {}",
                self.uri,
                e.message()
            ))
        })?;
        *guard = Arc::new(fresh);
        Ok(guard.clone())
    }

    /// Run a blocking libvirt operation on the blocking thread pool.
    pub async fn run<T, F>(&self, f: F) -> OpResult<T>
    where
        F: FnOnce(&Connect) -> OpResult<T> + Send + 'static,
        T: Send + 'static,
    {
        let conn = self.handle()?;
        match tokio::task::spawn_blocking(move || f(&conn)).await {
            Ok(res) => res,
            // A panic in the closure is a bug, but the process shouldn't decide
            // that the VM operation is permanently impossible because of it.
            Err(e) => Err(OpError::Transient(anyhow!("libvirt task failed: {}", e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_rejects_bad_uri() {
        assert!(LibVirtConn::open("definitely-not-a-hypervisor:///x").is_err());
    }

    #[tokio::test]
    async fn run_dispatches_to_blocking_pool() -> Result<()> {
        let conn = LibVirtConn::open("test:///default")?;
        let hostname = conn
            .run(|c| {
                c.hostname()
                    .map_err(|e| OpError::Transient(anyhow!("{}", e.message())))
            })
            .await
            .map_err(|e| anyhow!("{:?}", e))?;
        assert!(!hostname.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn run_propagates_fatal_errors() -> Result<()> {
        let conn = LibVirtConn::open("test:///default")?;
        let res: OpResult<()> = conn.run(|_| Err(OpError::Fatal(anyhow!("nope")))).await;
        assert!(matches!(res, Err(OpError::Fatal(_))));
        Ok(())
    }

    #[tokio::test]
    async fn run_converts_panics_to_transient() -> Result<()> {
        let conn = LibVirtConn::open("test:///default")?;
        let res: OpResult<()> = conn.run(|_| panic!("boom")).await;
        assert!(matches!(res, Err(OpError::Transient(_))));
        Ok(())
    }
}
