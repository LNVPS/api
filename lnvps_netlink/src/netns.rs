//! The network namespace the node's data plane lives in.
//!
//! A marketplace node is somebody else's machine, and often not only an LNVPS
//! node. Configuring the data plane in the machine's own namespace means taking
//! their default route, turning on forwarding machine-wide, and putting guest
//! routes and proxy-ARP settings in the tables their own tooling manages. All
//! of that is rude, and some of it is dangerous.
//!
//! So the data plane gets a namespace of its own:
//!
//! - **Their default route stays theirs.** Ours is inside, where only guest
//!   traffic sees it.
//! - **Guests cannot reach the operator's network at all.** Not because a
//!   firewall rule says so — a rule can be mis-ordered, flushed by their
//!   tooling, or forgotten on one address family — but because the namespace
//!   holds no interface that leads there.
//! - **A tunnel that is down means no path at all.** Without this, a stray
//!   route sends customer traffic out the operator's uplink sourced from LNVPS
//!   addresses, which looks like spoofing to their upstream and can get *their*
//!   connection null-routed.
//! - **Kernel knobs are scoped.** `ip_forward`, `proxy_arp` and `proxy_ndp` are
//!   per-namespace, so LNVPS stops editing settings on their machine.
//!
//! The one thing that must stay outside is the tunnel's own UDP socket: a
//! WireGuard interface keeps its socket in the namespace it was *created* in,
//! so the tunnel interface is created in the machine's namespace and then moved
//! into this one.
//! The encrypted outer traffic still leaves through the operator's uplink,
//! while the inner interface — and everything routed over it — is isolated.

use std::fs;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::sched::{CloneFlags, setns, unshare};

/// The namespace the data plane lives in.
pub const NAMESPACE: &str = "lnvps";

/// Where namespaces are pinned, matching iproute2 so `ip netns exec lnvps …`
/// works for an operator debugging their machine.
pub const NETNS_DIR: &str = "/run/netns";

/// The pinned path for a namespace.
pub fn path(root: &Path, name: &str) -> PathBuf {
    root.join(name)
}

/// Create the namespace if it does not exist, and return a handle to it.
///
/// Pinned as a bind mount, exactly as `ip netns add` does it, so the namespace
/// outlives the daemon: a node restarting must not take its customers' network
/// with it, and an operator must be able to look inside with the tools they
/// already have.
pub fn ensure(root: &Path, name: &str) -> Result<Handle> {
    let pinned = path(root, name);
    if pinned.exists() {
        return Handle::open(&pinned);
    }

    fs::create_dir_all(root)
        .with_context(|| format!("Cannot create the namespace directory {}", root.display()))?;
    fs::File::create(&pinned).with_context(|| {
        format!(
            "Cannot create the namespace mount point {}",
            pinned.display()
        )
    })?;

    // Done on a thread: unsharing changes the *calling thread's* namespace, and
    // the daemon's other threads must keep the machine's own network — that is
    // how it goes on reaching LNVPS while the tunnel is being built.
    let pinned_for_thread = pinned.clone();
    std::thread::spawn(move || -> Result<()> {
        unshare(CloneFlags::CLONE_NEWNET).context("Cannot create a network namespace")?;
        // `/proc/thread-self`, not `/proc/self`: in a process with more than
        // one thread, `/proc/self/ns/net` is the *process's* namespace, which
        // is the one this thread just stopped being in. Pinning that would
        // produce a "namespace" that is the machine's own network, and every
        // isolation this module exists for would silently not happen.
        mount(
            Some(Path::new("/proc/thread-self/ns/net")),
            &pinned_for_thread,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .with_context(|| {
            format!(
                "Cannot pin the namespace at {}",
                pinned_for_thread.display()
            )
        })?;
        Ok(())
    })
    .join()
    .map_err(|_| anyhow::anyhow!("The thread creating the namespace panicked"))??;

    Handle::open(&pinned)
}

/// Remove a pinned namespace. Used by tests and teardown, not in normal running.
pub fn remove(root: &Path, name: &str) -> Result<()> {
    let pinned = path(root, name);
    if !pinned.exists() {
        return Ok(());
    }
    // Unmounting drops the namespace once nothing else holds it; the file is
    // then just a file.
    let _ = umount2(&pinned, MntFlags::MNT_DETACH);
    fs::remove_file(&pinned)
        .with_context(|| format!("Cannot remove the namespace file {}", pinned.display()))
}

/// The default pinned location, used outside tests.
pub fn ensure_default() -> Result<Handle> {
    ensure(Path::new(NETNS_DIR), NAMESPACE)
}

/// An open network namespace.
#[derive(Debug)]
pub struct Handle {
    fd: OwnedFd,
    path: PathBuf,
}

impl Handle {
    /// Open an already-pinned namespace.
    pub fn open(pinned: &Path) -> Result<Self> {
        let file = fs::File::open(pinned)
            .with_context(|| format!("Cannot open the namespace at {}", pinned.display()))?;
        Ok(Self {
            fd: OwnedFd::from(file),
            path: pinned.to_path_buf(),
        })
    }

    /// Where this namespace is pinned.
    pub fn pinned_at(&self) -> &Path {
        &self.path
    }

    /// The descriptor, for the netlink call that moves an interface in here.
    pub fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_fd().as_raw_fd()
    }

    /// Run `f` with this namespace as the current one.
    ///
    /// On a thread of its own, because namespace membership is per-thread: the
    /// daemon's other threads keep the machine's own network, which is what
    /// lets it go on reaching LNVPS while the tunnel is down or being built.
    /// The thread is scoped and joined here, so it ends inside the namespace
    /// rather than being returned to a pool carrying it.
    pub fn enter<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce() -> Result<T> + Send,
        T: Send,
    {
        let target = self.fd.as_fd().as_raw_fd();
        std::thread::scope(|scope| {
            scope
                .spawn(move || -> Result<T> {
                    setns_fd(target).context("Cannot enter the data plane namespace")?;
                    f()
                })
                .join()
                .map_err(|_| anyhow::anyhow!("A thread entering the namespace panicked"))?
        })
    }
}

/// `setns` on a raw fd, restricted to the network namespace.
fn setns_fd(fd: std::os::fd::RawFd) -> Result<()> {
    // SAFETY: the fd is owned by the caller for the duration of the call.
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    setns(borrowed, CloneFlags::CLONE_NEWNET)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of the module: a thread inside the namespace must see a
    /// different network from the machine's, and the namespace must outlive the
    /// thread that made it so a daemon restart does not take the data plane
    /// with it.
    #[test]
    #[ignore = "requires root; run with scripts/tunnel-e2e.sh"]
    fn a_namespace_isolates_and_persists() {
        let root = tempfile::tempdir().unwrap();
        let handle = ensure(root.path(), "lnvps-test").unwrap();

        let outside = std::fs::read_link("/proc/thread-self/ns/net").unwrap();
        let inside = handle
            .enter(|| Ok(std::fs::read_link("/proc/thread-self/ns/net")?))
            .unwrap();
        assert_ne!(
            outside, inside,
            "the thread stayed in the machine's network"
        );

        // The daemon's own threads keep the machine's network, which is what
        // lets it go on reaching LNVPS while the tunnel is down.
        assert_eq!(
            std::fs::read_link("/proc/thread-self/ns/net").unwrap(),
            outside
        );

        // Pinned, so it survives this process.
        assert!(path(root.path(), "lnvps-test").exists());
        remove(root.path(), "lnvps-test").unwrap();
        assert!(!path(root.path(), "lnvps-test").exists());
    }
}
