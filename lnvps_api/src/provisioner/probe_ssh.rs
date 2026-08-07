//! Measuring a node from inside a guest running on it.
//!
//! Everything LNVPS can see from outside is what the operator's node chooses to
//! report. This is the only part of the marketplace that finds out what a
//! customer would actually get, by being that customer for a few minutes.
//!
//! What is measured, and why each one:
//!
//! - **Time to first login.** The number a customer experiences, from asking
//!   for a VM to having a shell. It catches the machine that is technically
//!   working and unusably slow.
//! - **Memory allocated *and touched*.** Allocation alone proves nothing where
//!   the host overcommits — the pages have to be written before the machine
//!   admits it does not have them. A node reselling four times its RAM passes
//!   an allocation check and fails this one.
//! - **Disk write and read rates.** An operator can present an NVMe node backed
//!   by a network volume, or a disk that has started failing. Both are visible
//!   as a rate and invisible as a specification.
//!
//! Nothing is installed inside the guest. A probe that waited on a package
//! mirror would be timing the internet, and a node with no outbound access
//! would fail a test about the node.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use lnvps_api_common::ssh_client::SshClient;

use super::ProbeResult;

/// How long to keep trying to log in before calling the node broken.
///
/// Generous on purpose. A slow node is a finding to record, not a test to fail:
/// the point is to measure how long it takes, and a tight limit would turn
/// "this node is slow" into "this node did not answer", which is a different
/// and less useful thing to know.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);

/// Where a probe guest listens. A constant rather than a setting: the image is
/// LNVPS's own and a probe that had to be told this would be a probe that could
/// be pointed somewhere else.
const SSH_PORT: u16 = 22;

/// How much disk to read and write when measuring, in MB.
///
/// Large enough to be past the guest's page cache and any small write buffer,
/// small enough that a probe never fills a template's disk.
const DISK_MB: u64 = 256;

/// An ephemeral keypair, generated per probe and dropped with it.
///
/// A long-lived key that opened a shell on every operator's node would be the
/// most valuable secret LNVPS holds. This one exists for the life of one VM
/// and is authorised by exactly one guest.
pub struct ProbeKey {
    pub private_pem: String,
    pub public_openssh: String,
}

impl ProbeKey {
    pub fn generate() -> Result<Self> {
        let (private_pem, public_openssh) = lnvps_api_common::ssh_client::generate_keypair()
            .context("generating the probe's key")?;
        Ok(Self {
            private_pem,
            public_openssh,
        })
    }
}

impl std::fmt::Debug for ProbeKey {
    /// The private half never reaches a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeKey")
            .field("public_openssh", &self.public_openssh)
            .finish_non_exhaustive()
    }
}

/// Log into a probe VM and measure it.
///
/// `started` is when the VM was asked for, so the login time includes
/// everything a customer waits through: disk clone, boot, and cloud-init.
pub async fn measure(
    address: &str,
    username: &str,
    key: &ProbeKey,
    started: Instant,
) -> Result<ProbeResult> {
    let mut client = wait_for_login(address, SSH_PORT, username, key, started).await?;
    let provision_ms = started.elapsed().as_millis() as u32;

    Ok(ProbeResult {
        provision_ms: Some(provision_ms),
        memory_mb: Some(measure_memory(&mut client).await?),
        disk_write_mb: Some(measure_disk_write(&mut client).await?),
        disk_read_mb: Some(measure_disk_read(&mut client).await?),
        failure: None,
    })
}

/// Keep trying until the guest answers or the node has had long enough.
///
/// A VM that is still booting refuses connections, so a single attempt would
/// measure how fast we asked rather than how fast the node is.
async fn wait_for_login(
    address: &str,
    port: u16,
    username: &str,
    key: &ProbeKey,
    started: Instant,
) -> Result<SshClient> {
    let mut last = String::new();
    while started.elapsed() < LOGIN_TIMEOUT {
        let mut client = SshClient::new();
        match client
            .connect_with_key((address, port), username, &key.private_pem)
            .await
        {
            Ok(()) => return Ok(client),
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    bail!(
        "could not log in within {}s: {last}",
        LOGIN_TIMEOUT.as_secs()
    )
}

/// Memory the guest can allocate *and write to*, in MB.
///
/// Written through `/dev/shm`, which is RAM: every page has to be faulted in and
/// filled, so a host that promised memory it does not have fails here rather
/// than in a customer's VM three weeks later. Bounded to 45% of what the guest
/// reports, because tmpfs defaults to half of RAM and the guest still needs to
/// run while this happens.
async fn measure_memory(client: &mut SshClient) -> Result<u32> {
    let (_, total) = client
        .execute(MEMINFO_COMMAND)
        .await
        .context("reading the guest's memory")?;
    let total_kb = parse_mem_total(&total)?;

    let (code, out) = client
        .execute(&touch_command(touch_mb(total_kb)))
        .await
        .context("touching the guest's memory")?;
    if code != 0 {
        bail!("the guest could not use the memory it was given: {out}");
    }

    Ok((total_kb / 1024) as u32)
}

/// What the guest says it has, in kB.
const MEMINFO_COMMAND: &str = "awk '/MemTotal/ {print $2}' /proc/meminfo";

fn parse_mem_total(out: &str) -> Result<u64> {
    out.trim()
        .parse()
        .with_context(|| format!("the guest reported its memory as {out:?}"))
}

/// How much of it to write, in MB.
///
/// 45%: tmpfs defaults to half of RAM, and the guest still has to run while
/// this happens. Enough to catch a host that promised memory it does not have,
/// which is what this is for.
fn touch_mb(total_kb: u64) -> u64 {
    (total_kb / 1024) * 45 / 100
}

fn touch_command(mb: u64) -> String {
    // Removed in the same command, so a probe that loses its connection here
    // does not leave the guest's RAM full for whatever runs next.
    format!("dd if=/dev/zero of=/dev/shm/probe bs=1M count={mb} 2>&1; rm -f /dev/shm/probe")
}

/// Sequential write, MB/s.
///
/// `conv=fdatasync` so the rate is the disk's rather than the guest's page
/// cache: without it a node with a slow disk and plenty of RAM reports a
/// gigabyte a second.
async fn measure_disk_write(client: &mut SshClient) -> Result<u32> {
    let started = Instant::now();
    let (code, out) = client
        .execute(&write_command(DISK_MB))
        .await
        .context("writing to the guest's disk")?;
    if code != 0 {
        bail!("the guest could not write to its disk: {out}");
    }
    Ok(rate_mb_s(DISK_MB, started.elapsed()))
}

/// Sequential read, MB/s, with the cache dropped first so the number is the
/// disk's and not the memory's.
async fn measure_disk_read(client: &mut SshClient) -> Result<u32> {
    // Best-effort: a guest that will not let us drop caches still gives a
    // useful number, it is just an optimistic one, and refusing to report
    // anything would be worse.
    let _ = client
        .execute("sync; echo 3 > /proc/sys/vm/drop_caches")
        .await;

    let started = Instant::now();
    let (code, out) = client
        .execute(READ_COMMAND)
        .await
        .context("reading the guest's disk")?;
    if code != 0 {
        bail!("the guest could not read back what it wrote: {out}");
    }
    Ok(rate_mb_s(DISK_MB, started.elapsed()))
}

/// `conv=fdatasync` so the rate is the disk's and not the guest's page cache:
/// without it a node with a slow disk and plenty of RAM reports a gigabyte a
/// second.
fn write_command(mb: u64) -> String {
    format!("dd if=/dev/zero of=/var/tmp/probe bs=1M count={mb} conv=fdatasync 2>&1")
}

/// Read back and remove, so a probe cannot leave a quarter of a gigabyte behind
/// on an operator's disk.
const READ_COMMAND: &str = "dd if=/var/tmp/probe of=/dev/null bs=1M 2>&1; rm -f /var/tmp/probe";

/// Timed here rather than parsed from `dd`, whose output format varies with
/// version and locale — a parser that silently returns zero on an unfamiliar
/// line would mark healthy nodes as broken. The SSH round trip is included and
/// is noise beside a multi-second transfer.
fn rate_mb_s(mb: u64, elapsed: Duration) -> u32 {
    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 {
        return 0;
    }
    (mb as f64 / secs).round() as u32
}

#[cfg(test)]
mod tests;

/// Probe a node end to end: build a VM on it, measure it, destroy it, and write
/// down what happened.
///
/// The result is recorded whatever it is. A node that fails is a row, because a
/// node that never completes a probe is indistinguishable from one nobody
/// probed unless the failures are written down — and the first thing anybody
/// will ask about a suspended node is what it did before.
pub async fn run_probe(
    db: &std::sync::Arc<dyn lnvps_db::LNVpsDb>,
    cfg: &lnvps_api_common::host::config::ProvisionerConfig,
    node: &lnvps_db::MarketplaceNode,
) -> Result<ProbeResult> {
    let key = ProbeKey::generate()?;
    let spec = super::ProbeSpec::build(db, node, key.public_openssh.clone()).await?;
    // The image's own default user. A probe that assumed root would fail on
    // every image that disables it, which is most of them, and would look like
    // a broken node.
    let username = spec
        .image
        .default_username
        .clone()
        .unwrap_or_else(|| "root".to_string());

    let started = Instant::now();
    let result = super::with_probe_vm(db, cfg, &spec, || async {
        measure(spec.ip(), &username, &key, started).await
    })
    .await;

    super::record(db, node.id, &spec, result.clone()).await?;
    Ok(result)
}
