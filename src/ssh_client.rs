use anyhow::Result;
use log::info;
use std::io::Read;
use std::path::PathBuf;
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

    pub async fn execute(&mut self, command: &str) -> Result<(i32, String)> {
        info!("Executing command: {}", command);
        let mut channel = self.session.channel_session()?;
        channel.exec(command)?;
        let mut s = String::new();
        channel.read_to_string(&mut s)?;
        channel.wait_close()?;
        Ok((channel.exit_status()?, s))
    }
}
