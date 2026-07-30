//! Integration tests for [`SshClient`] against a real sshd.
//!
//! The server is the `sshd` service in `docker-compose.e2e.yaml`; the address
//! and client key come from the environment, so these tests are skipped when the
//! e2e infrastructure is not running.
//!
//! - `LNVPS_TEST_SSH_ADDR` — `host:port` of the test sshd (e.g. `localhost:2222`)
//! - `LNVPS_TEST_SSH_KEY`  — path to the client private key
#![cfg(any(feature = "proxmox", feature = "linux-ssh"))]

use anyhow::Result;
use lnvps_api::ssh_client::SshClient;
use std::path::{Path, PathBuf};

/// Socket the test sshd's echo server listens on.
const ECHO_SOCKET: &str = "/tmp/e2e-echo.sock";

struct Target {
    addr: String,
    key: PathBuf,
}

fn target() -> Option<Target> {
    let addr = std::env::var("LNVPS_TEST_SSH_ADDR").ok()?;
    let key = std::env::var("LNVPS_TEST_SSH_KEY").ok()?;
    Some(Target {
        addr,
        key: PathBuf::from(key),
    })
}

/// Skip rather than fail when the e2e stack is not up: `cargo test --workspace`
/// runs these on developer machines too.
macro_rules! target_or_skip {
    () => {
        match target() {
            Some(t) => t,
            None => {
                eprintln!("skipping: LNVPS_TEST_SSH_ADDR / LNVPS_TEST_SSH_KEY not set");
                return Ok(());
            }
        }
    };
}

async fn connected(t: &Target) -> Result<SshClient> {
    let mut client = SshClient::new()?;
    client.connect(t.addr.as_str(), "root", &t.key).await?;
    Ok(client)
}

#[tokio::test]
async fn exec_captures_stdout_and_exit_code() -> Result<()> {
    let t = target_or_skip!();
    let mut client = connected(&t).await?;

    let (code, out) = client.execute("echo hello").await?;
    assert_eq!(0, code);
    assert_eq!("hello\n", out);
    Ok(())
}

#[tokio::test]
async fn exec_folds_stderr_into_output_on_failure() -> Result<()> {
    let t = target_or_skip!();
    let mut client = connected(&t).await?;

    let (code, out) = client.execute("echo oops >&2; exit 3").await?;
    assert_eq!(3, code);
    assert!(out.contains("stderr: oops"), "unexpected output: {out}");

    // Stderr is deliberately left out when the command succeeds so output
    // parsers are undisturbed.
    let (code, out) = client.execute("echo noise >&2; echo fine").await?;
    assert_eq!(0, code);
    assert_eq!("fine\n", out);
    Ok(())
}

#[tokio::test]
async fn run_command_connects_and_executes() -> Result<()> {
    let t = target_or_skip!();
    let (host, port) = t.addr.rsplit_once(':').expect("addr must be host:port");

    let (code, out) = SshClient::run_command(
        host.to_string(),
        port.parse()?,
        "root".to_string(),
        t.key.clone(),
        "echo remote".to_string(),
    )
    .await?;
    assert_eq!(0, code);
    assert_eq!("remote\n", out);
    Ok(())
}

#[tokio::test]
async fn sftp_upload_writes_content_and_mode() -> Result<()> {
    let t = target_or_skip!();
    let mut client = connected(&t).await?;
    let remote = format!("/tmp/upload-{}", std::process::id());

    client
        .scp_upload(b"payload\n", Path::new(&remote), 0o755)
        .await?;

    let (code, out) = client.execute(&format!("cat '{remote}'")).await?;
    assert_eq!(0, code);
    assert_eq!("payload\n", out);

    let (code, out) = client.execute(&format!("stat -c %a '{remote}'")).await?;
    assert_eq!(0, code);
    assert_eq!("755", out.trim());

    // Overwriting a longer file must not leave a tail of the previous content.
    client
        .scp_upload(b"short\n", Path::new(&remote), 0o644)
        .await?;
    let (_, out) = client.execute(&format!("cat '{remote}'")).await?;
    assert_eq!("short\n", out);

    client.execute(&format!("rm -f '{remote}'")).await?;
    Ok(())
}

#[tokio::test]
async fn tunnel_unix_socket_round_trips() -> Result<()> {
    let t = target_or_skip!();
    let mut client = connected(&t).await?;

    let mut channel = client.tunnel_unix_socket(Path::new(ECHO_SOCKET)).await?;
    channel.data(&b"ping\n"[..]).await?;

    let mut got = Vec::new();
    while let Some(msg) = channel.wait().await {
        if let russh::ChannelMsg::Data { data } = msg {
            got.extend_from_slice(&data);
            if got.ends_with(b"\n") {
                break;
            }
        }
    }
    assert_eq!(b"ping\n".to_vec(), got);
    Ok(())
}

#[tokio::test]
async fn connect_rejects_unauthorised_user() -> Result<()> {
    let t = target_or_skip!();

    let mut client = SshClient::new()?;
    let err = client
        .connect(t.addr.as_str(), "nobody", &t.key)
        .await
        .expect_err("authentication as an unauthorised user must fail");
    assert!(
        err.to_string().contains("authentication failed"),
        "unexpected error: {err}"
    );

    // A failed connect must not leave a session behind that later calls could
    // use as if authenticated.
    assert!(client.execute("echo nope").await.is_err());
    Ok(())
}
