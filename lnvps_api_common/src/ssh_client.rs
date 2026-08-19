use anyhow::{Result, anyhow, bail};
use log::info;
use russh::client::{self, Handle, Msg};
use russh::keys::{PrivateKeyWithHashAlg, decode_secret_key, load_secret_key};
use russh::{Channel, ChannelMsg};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::FileAttributes;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::ToSocketAddrs;

/// How long a connect/auth attempt may take before it is abandoned.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a single command may run before the channel is abandoned.
///
/// Every caller in this workspace runs a short administrative command —
/// `pvesm path`, `mkdir`, `ssh-keyscan -T 5`, a bounded `dd` — so ten minutes
/// bounds a hang without changing what any of them do. It has to be a bound
/// rather than a tight limit: the peer may be a marketplace node, which is
/// third-party hardware that controls the guest, and one that accepts a channel
/// and never closes it would otherwise hold this future forever. The worker
/// runs jobs serially, so "forever" means every other job in the deployment
/// stops too.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(600);

/// How much output one command may produce before it is abandoned.
///
/// The output of every command here is a path, a status line or a few lines of
/// JSON. 8 MiB is far past all of them and still bounded, which matters because
/// the peer chooses how much to send: without a cap a hostile or broken host
/// can grow this `Vec` until the API process is killed by the OOM killer, and
/// on a marketplace node the peer is somebody else's machine.
const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

/// Session event handler.
///
/// Host keys are accepted unconditionally: hosts are addressed by IP from the
/// database and there is no key store to pin them against, so verifying here
/// would reject every connection rather than add security.
struct Handler;

impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[derive(Default)]
pub struct SshClient {
    session: Option<Handle<Handler>>,
}

/// Generate an ed25519 keypair, returned as OpenSSH text.
///
/// Here rather than in the caller because this crate is the one that owns the
/// SSH dependency: a second place generating keys would be a second place to
/// pick an algorithm, and the pair has to match what [`SshClient`] can load.
///
/// Returns `(private OpenSSH PEM, public authorized_keys line)`.
pub fn generate_keypair() -> Result<(String, String)> {
    // `rand::rng()` from rand 0.10, the only generator in this dependency graph
    // that satisfies ssh-key's bound: the graph carries three versions of
    // rand_core, ssh-key resolves to 0.10's trait, and 0.10 removed `OsRng` in
    // favour of this. A mismatch is a compile error rather than a silent
    // downgrade, which is what to want on the one call in this codebase that
    // generates a key granting shell access to somebody else's machine.
    let key = russh::keys::PrivateKey::random(&mut rand_10::rng(), russh::keys::Algorithm::Ed25519)
        .map_err(|e| anyhow::anyhow!("Key generation failed: {e}"))?;

    Ok((
        key.to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .map_err(|e| anyhow::anyhow!("Private key could not be encoded: {e}"))?
            .to_string(),
        key.public_key()
            .to_openssh()
            .map_err(|e| anyhow::anyhow!("Public key could not be encoded: {e}"))?,
    ))
}

impl SshClient {
    pub fn new() -> SshClient {
        SshClient { session: None }
    }

    pub async fn connect(
        &mut self,
        host: impl ToSocketAddrs,
        username: &str,
        key: &PathBuf,
    ) -> Result<()> {
        let key = load_secret_key(key, None)?;
        self.authenticate(host, username, key).await
    }

    /// Connect using a private key from memory (PEM format)
    pub async fn connect_with_key(
        &mut self,
        host: impl ToSocketAddrs,
        username: &str,
        private_key_pem: &str,
    ) -> Result<()> {
        let key = decode_secret_key(private_key_pem, None)?;
        self.authenticate(host, username, key).await
    }

    async fn authenticate(
        &mut self,
        host: impl ToSocketAddrs,
        username: &str,
        key: russh::keys::PrivateKey,
    ) -> Result<()> {
        let config = Arc::new(client::Config {
            inactivity_timeout: None,
            ..Default::default()
        });
        // A host can finish key exchange and then stall in auth, so the timeout
        // has to cover the whole handshake and not just the connect.
        let session = tokio::time::timeout(CONNECT_TIMEOUT, async move {
            let mut session = client::connect(config, host, Handler).await?;
            let hash_alg = session.best_supported_rsa_hash().await?.flatten();
            let res = session
                .authenticate_publickey(
                    username,
                    PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg),
                )
                .await?;
            if !res.success() {
                bail!("SSH public key authentication failed for user {username}");
            }
            Ok::<_, anyhow::Error>(session)
        })
        .await??;

        self.session = Some(session);
        Ok(())
    }

    fn session(&self) -> Result<&Handle<Handler>> {
        self.session
            .as_ref()
            .ok_or_else(|| anyhow!("SSH session is not connected"))
    }

    pub async fn open_channel(&mut self) -> Result<Channel<Msg>> {
        Ok(self.session()?.channel_open_session().await?)
    }

    /// Open a direct-streamlocal channel to a unix socket on the remote host.
    ///
    /// The returned channel borrows nothing from this client, but the session it
    /// belongs to lives on the client: keep the [`SshClient`] alive for as long
    /// as the channel is in use.
    pub async fn tunnel_unix_socket(&mut self, remote_path: &Path) -> Result<Channel<Msg>> {
        let path = remote_path
            .to_str()
            .ok_or_else(|| anyhow!("Remote socket path is not valid UTF-8"))?;
        Ok(self
            .session()?
            .channel_open_direct_streamlocal(path)
            .await?)
    }

    /// Connect and run a single command.
    pub async fn run_command(
        host: String,
        port: u16,
        username: String,
        key: PathBuf,
        command: String,
    ) -> Result<(i32, String)> {
        let mut client = SshClient::new();
        client.connect((host, port), &username, &key).await?;
        client.execute(&command).await
    }

    pub async fn execute(&mut self, command: &str) -> Result<(i32, String)> {
        // Bounded in both time and size: see COMMAND_TIMEOUT and
        // MAX_OUTPUT_BYTES. Both are properties of talking to a machine that
        // may not be ours, so they belong here rather than at each call site.
        tokio::time::timeout(COMMAND_TIMEOUT, self.execute_unbounded(command))
            .await
            .map_err(|_| {
                anyhow!(
                    "Command did not finish within {}s: {command}",
                    COMMAND_TIMEOUT.as_secs()
                )
            })?
    }

    async fn execute_unbounded(&mut self, command: &str) -> Result<(i32, String)> {
        info!("Executing command: {}", command);
        let mut channel = self.session()?.channel_open_session().await?;
        channel.exec(true, command).await?;

        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut code = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { ref data } => out.extend_from_slice(data),
                // Also collect stderr. Tools like `qm`/`qemu-img` print the
                // actual failure reason there (stdout only carries the terse
                // "update VM ..." echo and syslog only logs "creating disks
                // failed"), so without this the real cause of a non-zero exit is
                // invisible.
                ChannelMsg::ExtendedData { ref data, ext: 1 } => err.extend_from_slice(data),
                ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status as i32),
                _ => {}
            }
            // Checked as it arrives rather than at the end, because the point
            // is to stop accumulating rather than to report afterwards that too
            // much was accumulated.
            if out.len() + err.len() > MAX_OUTPUT_BYTES {
                bail!("Command produced more than {MAX_OUTPUT_BYTES} bytes of output: {command}");
            }
        }

        let mut s = String::from_utf8_lossy(&out).into_owned();
        let err = String::from_utf8_lossy(&err).into_owned();
        // A server that closes the channel without an exit-status is treated as
        // a failure so callers cannot mistake it for a clean run.
        let code = code.ok_or_else(|| anyhow!("Command did not report an exit status"))?;
        // Fold stderr into the returned output on failure so callers that log
        // the string surface it; on success it is left out to avoid disturbing
        // output parsers.
        if code != 0 && !err.trim().is_empty() {
            if !s.is_empty() && !s.ends_with('\n') {
                s.push('\n');
            }
            s.push_str("stderr: ");
            s.push_str(err.trim_end());
        }
        Ok((code, s))
    }

    /// Upload a file to the remote host via SFTP
    pub async fn scp_upload(
        &mut self,
        local_data: &[u8],
        remote_path: &Path,
        mode: i32,
    ) -> Result<()> {
        let path = remote_path
            .to_str()
            .ok_or_else(|| anyhow!("Remote path is not valid UTF-8"))?
            .to_string();

        info!(
            "SFTP upload to {:?} ({} bytes, mode {:o})",
            remote_path,
            local_data.len(),
            mode
        );

        let channel = self.session()?.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream()).await?;

        let mut file = sftp.create(path.clone()).await?;
        file.write_all(local_data).await?;
        file.shutdown().await?;

        // Only the permission bits are sent. `FileAttributes::default()` is not
        // an empty attribute set — it carries `size: Some(0)`, which the server
        // applies and truncates the file we just wrote.
        sftp.set_metadata(
            path,
            FileAttributes {
                permissions: Some(mode as u32),
                ..FileAttributes::empty()
            },
        )
        .await?;
        sftp.close().await?;

        info!("SFTP upload complete");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both bounds exist, and are generous enough not to change what any
    /// existing caller does.
    ///
    /// Every command run through this client is a short administrative one — a
    /// path lookup, a `mkdir`, an `ssh-keyscan -T 5`, a bounded `dd` — so these
    /// limits are only ever reached by a peer that has stopped behaving. That
    /// matters because the peer is not always ours: a marketplace node is
    /// third-party hardware, and one that accepts a channel and never closes it
    /// would otherwise hang the caller forever and, on the worker, stop every
    /// other job in the deployment behind it.
    #[test]
    fn a_command_is_bounded_in_time_and_size() {
        // `const` blocks, so a change that breaks one of these fails the build
        // rather than waiting for the test to be run.
        const {
            assert!(
                COMMAND_TIMEOUT.as_secs() >= 300,
                "a legitimate slow command must not be cut off"
            );
            assert!(
                COMMAND_TIMEOUT.as_secs() <= 3600,
                "a bound nobody reaches is not a bound"
            );
            assert!(
                MAX_OUTPUT_BYTES >= 1024 * 1024,
                "real command output must fit comfortably"
            );
            assert!(
                MAX_OUTPUT_BYTES <= 64 * 1024 * 1024,
                "a peer must not be able to grow this until the process is killed"
            );
        }
    }

    /// A command on a client that was never connected fails rather than
    /// waiting out the whole timeout.
    ///
    /// The timeout wraps `session()`, so a bug that made this path hang would
    /// be invisible for ten minutes rather than immediate.
    #[tokio::test]
    async fn a_disconnected_client_fails_immediately() {
        let mut client = SshClient::new();
        let began = std::time::Instant::now();

        let err = client
            .execute("true")
            .await
            .expect_err("a client with no session cannot run anything");

        assert!(err.to_string().contains("not connected"), "{err}");
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "the error waited on the command timeout instead of being reported"
        );
    }

    /// A peer that accepts the connection and then says nothing does not hang
    /// the caller.
    ///
    /// This is the shape of the problem on a marketplace node, which is
    /// hardware LNVPS does not own: the TCP connect succeeds, so nothing fails
    /// fast, and without a bound the caller waits forever.
    ///
    /// The assertion is that it *finishes* well inside a bound of its own, not
    /// that it takes the full `CONNECT_TIMEOUT`: waiting out 30s of real time
    /// would make this the slowest test in the crate to prove a constant that
    /// is read directly above.
    #[tokio::test]
    async fn a_silent_peer_does_not_hang_the_caller() {
        // Accepts and never speaks, so the SSH handshake cannot complete.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            // Held open deliberately: dropping the socket would close the
            // connection and make this a connection error rather than a stall.
            std::future::pending::<()>().await;
        });

        // A real key, so the failure is the stalled handshake rather than a
        // key that could not be parsed.
        let (private_pem, _) = generate_keypair().unwrap();
        let mut client = SshClient::new();

        // Bounded by more than CONNECT_TIMEOUT: if the connect is unbounded,
        // this outer timeout is what fires, and the assertion below fails.
        let outcome = tokio::time::timeout(
            CONNECT_TIMEOUT + Duration::from_secs(15),
            client.connect_with_key(addr, "probe", &private_pem),
        )
        .await;

        assert!(
            outcome.is_ok(),
            "a stalled handshake was never abandoned; the caller would wait forever"
        );
        assert!(
            outcome.unwrap().is_err(),
            "a handshake that never completed must not be reported as connected"
        );
    }
}
