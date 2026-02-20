use anyhow::{Result, anyhow};
use log::info;
use ssh2::Channel;
use std::io::Read;
use std::path::{Path, PathBuf};
use tokio::net::{TcpStream, ToSocketAddrs};

pub struct SshClient {
    session: ssh2::Session,
}

impl SshClient {
    pub fn new() -> Result<SshClient> {
        let session = ssh2::Session::new()?;
        Ok(SshClient { session })
    }

    pub async fn connect(
        &mut self,
        host: impl ToSocketAddrs,
        username: &str,
        key: &PathBuf,
    ) -> Result<()> {
        let tcp = TcpStream::connect(host).await?;
        self.session.set_tcp_stream(tcp);
        self.session.handshake()?;
        self.session
            .userauth_pubkey_file(username, None, key, None)?;
        Ok(())
    }

    /// Connect using a private key from memory (PEM format)
    pub async fn connect_with_key(
        &mut self,
        host: impl ToSocketAddrs,
        username: &str,
        private_key_pem: &str,
    ) -> Result<()> {
        let tcp = TcpStream::connect(host).await?;
        self.session.set_tcp_stream(tcp);
        self.session.handshake()?;
        self.session
            .userauth_pubkey_memory(username, None, private_key_pem, None)?;
        Ok(())
    }

    pub async fn open_channel(&mut self) -> Result<Channel> {
        let channel = self.session.channel_session()?;
        Ok(channel)
    }

    pub fn tunnel_unix_socket(&mut self, remote_path: &Path) -> Result<Channel> {
        self.session
            .channel_direct_streamlocal(remote_path.to_str().unwrap(), None)
            .map_err(|e| anyhow!(e))
    }

    /// Toggle blocking mode on the underlying SSH session.
    ///
    /// Set to `false` before calling [`tunnel_unix_socket`] when you need
    /// non-blocking I/O (e.g. for the terminal proxy bridge thread).
    pub fn set_blocking(&self, blocking: bool) {
        self.session.set_blocking(blocking);
    }

    pub async fn execute(&mut self, command: &str) -> Result<(i32, String)> {
        info!("Executing command: {}", command);
        let mut channel = self.session.channel_session()?;
        channel.exec(command)?;
        let mut s = String::new();
        channel.read_to_string(&mut s)?;
        channel.wait_close()?;
        Ok((channel.exit_status()?, s))
    }

    /// Upload a file to the remote host via SFTP
    pub fn scp_upload(&self, local_data: &[u8], remote_path: &Path, mode: i32) -> Result<()> {
        use std::io::Write;

        info!(
            "SFTP upload to {:?} ({} bytes, mode {:o})",
            remote_path,
            local_data.len(),
            mode
        );

        let sftp = self.session.sftp()?;
        let mut file = sftp.create(remote_path)?;
        file.write_all(local_data)?;

        // Set file permissions
        let mut stat = sftp.stat(remote_path)?;
        stat.perm = Some(mode as u32);
        sftp.setstat(remote_path, stat)?;

        info!("SFTP upload complete");
        Ok(())
    }
}
