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
