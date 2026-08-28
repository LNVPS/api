//! `lvd` — the LNVPS VPN daemon.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use lnvps_netlink::{Kernel, NetOps};
use lnvps_vpn::client::Client;
use lnvps_vpn::config::VpnConfig;
use lnvps_vpn::{apply, scrub};

#[derive(Parser)]
#[command(name = "lvd", version, about = "LNVPS VPN route server daemon")]
struct Cli {
    /// Path to the configuration file.
    #[arg(short, long, default_value = "/etc/lvd/config.yaml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon: fetch what this route server should be and keep it that
    /// way.
    Run,
    /// Check the configuration without contacting LNVPS or touching the
    /// machine.
    Check,
    /// Fetch what LNVPS wants and print it, changing nothing.
    Show,
    /// Fetch it and apply it once, then exit.
    Apply,
    /// Print what this machine currently has, read from the machine itself.
    Observe,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    let config = VpnConfig::load(&cli.config)?;

    match cli.command {
        Command::Check => {
            // `load` already validated. Saying so is the point of the command:
            // an operator wants to know the file is good before starting.
            println!("{} looks good", cli.config.display());
            Ok(())
        }
        Command::Show => {
            let doc = Client::new(&config)?.dataplane(0, 0).await?;
            println!("{}", serde_json::to_string_pretty(&doc)?);
            Ok(())
        }
        Command::Apply => {
            let kernel = Kernel::host()?;
            let doc = Client::new(&config)?.dataplane(0, 0).await?;
            report(apply::apply(&kernel, &doc).await?);
            Ok(())
        }
        Command::Observe => {
            let kernel = Kernel::host()?;
            let doc = Client::new(&config)?.dataplane(0, 0).await?;
            for interface in &doc.interfaces {
                let name = interface.interface();
                match kernel.wireguard_state(&name).await? {
                    Some(state) => println!(
                        "{name}: port {}, {} peers, {} of them handshaken",
                        state.listen_port,
                        state.peers.len(),
                        state
                            .peers
                            .iter()
                            .filter(|p| p.last_handshake_secs.is_some())
                            .count()
                    ),
                    None => println!("{name}: not configured"),
                }
            }
            Ok(())
        }
        Command::Run => run(config).await,
    }
}

/// Fetch, apply, repeat.
///
/// The fetch waits: LNVPS holds it open until the generation moves, so a
/// revoked key stops being honoured in about one round trip rather than on the
/// next poll. When the wait expires the document comes back unchanged and the
/// apply is silent, which is the ordinary case and costs nothing.
async fn run(config: VpnConfig) -> Result<()> {
    let client = Client::new(&config)?;
    let kernel = Kernel::host().context("Cannot talk to the kernel; lvd needs to run as root")?;

    // Zero, not the last generation applied: this daemon has just started and
    // has no idea what the machine is carrying, so the first fetch must return
    // the document rather than wait for it to change.
    let mut generation = 0;

    loop {
        let doc = match client.dataplane(generation, config.wait_secs).await {
            Ok(doc) => doc,
            Err(e) => {
                // Logged and retried rather than fatal. A route server that
                // exits because LNVPS was briefly unreachable is one that stops
                // carrying traffic it is already carrying perfectly well: the
                // kernel keeps forwarding without this process.
                log::warn!("Could not fetch the data plane: {e:#}");
                tokio::time::sleep(config.retry()).await;
                continue;
            }
        };

        match apply::apply(&kernel, &doc).await {
            Ok(applied) => {
                for change in &applied.changes {
                    log::info!("{change}");
                }
                // Only on success. Recording a generation that was not applied
                // would mean the next fetch waits for a *further* change before
                // retrying, so one failed apply would strand the machine until
                // somebody else's device moved.
                generation = doc.generation;
            }
            Err(e) => {
                log::error!("Could not apply generation {}: {e:#}", doc.generation);
                tokio::time::sleep(config.retry()).await;
                continue;
            }
        }

        match scrub::scrub_quiet_peers(&kernel, &doc, config.scrub_after_secs).await {
            Ok(scrubbed) => {
                for key in scrubbed {
                    log::info!("scrubbed the recorded address of {key}");
                }
            }
            // Not fatal, and not a reason to retry the fetch: the peers are
            // configured correctly, this only failed to forget something.
            Err(e) => log::warn!("Could not scrub quiet peers: {e:#}"),
        }

        // A floor under the loop. With a wait the fetch already blocks, but a
        // server that answers immediately every time -- because the generation
        // keeps moving, or because `wait` is zero -- must not turn this into a
        // spin.
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn report(applied: apply::Applied) {
    if applied.is_empty() {
        println!("already correct");
        return;
    }
    for change in applied.changes {
        println!("{change}");
    }
}
