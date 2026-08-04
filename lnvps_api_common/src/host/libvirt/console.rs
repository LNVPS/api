//! Serial console proxying.
//!
//! Bridges libvirt's console stream to the [`TerminalStream`] channel pair the
//! API's websocket handler expects: `rx` carries bytes **from** the guest, `tx`
//! carries bytes **to** it.
//!
//! libvirt streams are not safe to use concurrently from two threads, so a
//! single blocking pump thread services both directions rather than a reader
//! and a writer task.

use super::error::map_virt_error;
use super::xml::domain_name;
use crate::host::TerminalStream;
use crate::retry::{OpError, OpResult};
use anyhow::anyhow;
use log::{debug, info};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use virt::connect::Connect;
use virt::stream::Stream;
use virt::sys::VIR_STREAM_NONBLOCK;

/// Buffered chunks in each direction before the producer has to wait.
const CHANNEL_DEPTH: usize = 256;
/// Read buffer size; a serial console is low bandwidth.
const READ_BUF: usize = 8192;
/// Idle poll interval. Small enough to feel interactive, large enough not to
/// spin a core per open console.
const IDLE_POLL: Duration = Duration::from_millis(20);

/// Open the serial console for a VM.
pub fn connect(conn: Arc<Connect>, vm_id: u64) -> OpResult<TerminalStream> {
    // Bytes from the guest to the client...
    let (client_tx, client_rx) = channel::<Vec<u8>>(CHANNEL_DEPTH);
    // ...and from the client to the guest.
    let (server_tx, server_rx) = channel::<Vec<u8>>(CHANNEL_DEPTH);

    // Open the console synchronously so a failure (VM not running, console
    // already in use) surfaces as an error here instead of a silently dead
    // terminal.
    let stream = open_console(&conn, vm_id)?;

    std::thread::Builder::new()
        .name(format!("libvirt-console-{vm_id}"))
        .spawn(move || {
            pump(stream, client_tx, server_rx);
            // Keep the connection alive for as long as the console is open.
            drop(conn);
            debug!("console pump for VM {vm_id} finished");
        })
        .map_err(|e| OpError::Transient(anyhow!("cannot spawn console thread: {e}")))?;

    info!("terminal proxy opened for VM {vm_id}");
    Ok(TerminalStream {
        rx: client_rx,
        tx: server_tx,
    })
}

fn open_console(conn: &Connect, vm_id: u64) -> OpResult<Stream> {
    let domain = conn
        .lookup_domain_by_name(&domain_name(vm_id))
        .map_err(|e| map_virt_error("lookup_domain", e))?;

    if !domain
        .is_active()
        .map_err(|e| map_virt_error("domain_is_active", e))?
    {
        // Connecting to a stopped VM would otherwise hand back a terminal that
        // never produces a byte.
        return Err(OpError::Fatal(anyhow!(
            "VM {vm_id} is not running, cannot open its console"
        )));
    }

    // Non-blocking: the pump has to stay responsive to the write side and to
    // client disconnects even when the guest is silent.
    let stream =
        Stream::new(conn, VIR_STREAM_NONBLOCK).map_err(|e| map_virt_error("new_stream", e))?;
    domain
        .open_console(None, &stream, 0)
        .map_err(|e| map_virt_error("open_console", e))?;
    Ok(stream)
}

/// Shuttle bytes in both directions until either side goes away.
fn pump(stream: Stream, client_tx: Sender<Vec<u8>>, mut server_rx: Receiver<Vec<u8>>) {
    let mut buf = [0u8; READ_BUF];
    loop {
        let mut idle = true;

        // Guest -> client.
        match stream.recv(&mut buf) {
            Ok(n) if n > 0 => {
                idle = false;
                if client_tx.blocking_send(buf[..n as usize].to_vec()).is_err() {
                    // Client hung up.
                    break;
                }
            }
            // 0 is EOF (guest closed the console), negative is "would block".
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                debug!("console read ended: {}", e.message());
                break;
            }
        }

        // Client -> guest.
        match server_rx.try_recv() {
            Ok(data) => {
                idle = false;
                if !send_all(&stream, &data) {
                    break;
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => break,
        }

        if idle {
            std::thread::sleep(IDLE_POLL);
        }
    }

    // Best effort: the console is going away either way.
    let _ = stream.finish();
}

/// Write a whole buffer, tolerating short and would-block writes.
fn send_all(stream: &Stream, data: &[u8]) -> bool {
    let mut sent = 0usize;
    while sent < data.len() {
        match stream.send(&data[sent..]) {
            Ok(n) if n > 0 => sent += n as usize,
            // Would block: give the guest a moment to drain.
            Ok(_) => std::thread::sleep(IDLE_POLL),
            Err(e) => {
                debug!("console write ended: {}", e.message());
                return false;
            }
        }
    }
    true
}
