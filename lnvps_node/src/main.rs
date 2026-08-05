//! `lnvps-node` — the LNVPS marketplace node daemon.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use lnvps_node::config::NodeConfig;
use lnvps_node::control::ControlState;
use lnvps_node::credential::Credential;
use lnvps_node::inventory::Inventory;
use lnvps_node::{config, control, control_auth, tls};

#[derive(Parser)]
#[command(name = "lnvps-node", version, about = "LNVPS marketplace node daemon")]
struct Cli {
    /// Path to the configuration file.
    #[arg(short, long, default_value = "/etc/lnvps-node/config.yaml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon: serve the control API over the tunnel.
    Run,
    /// Print what this node would report about its hardware.
    Inventory,
    /// Check the configuration and credential without contacting LNVPS.
    Check,
    /// Print the node's TLS fingerprint, the value LNVPS pins at registration.
    Fingerprint {
        /// State directory holding the identity (defaults to the configured one).
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Command::Run => run(&cli.config).await?,
        // Deliberately usable before there is any config: an operator
        // evaluating whether their hardware qualifies should not have to
        // configure a daemon first.
        Command::Inventory => {
            println!("{}", serde_json::to_string_pretty(&Inventory::collect())?);
        }
        Command::Check => {
            let config = NodeConfig::load(&cli.config)?;
            let credential = Credential::load_checked(&config.credential)?;
            println!("config:     {}", cli.config.display());
            println!("api url:    {}", config.api_url);
            match credential.public_key() {
                Some(pubkey) => println!("identity:   {pubkey}"),
                None => println!("identity:   session token (no public key)"),
            }
            match &config.control {
                Some(control) => println!(
                    "control:    {}:{} on {}",
                    control.listen, control.port, control.tunnel_interface
                ),
                None => println!("control:    not configured (node not yet paired)"),
            }
        }
        Command::Fingerprint { state_dir } => {
            let state_dir = match state_dir {
                Some(dir) => dir,
                None => NodeConfig::load(&cli.config)?.state_dir,
            };
            let tls = tls::load_or_generate(&state_dir, None)?;
            println!("{}", tls.fingerprint);
            if tls.generated {
                eprintln!(
                    "note: a new certificate was generated; register this fingerprint with \
                     LNVPS or control requests will not reach this node"
                );
            }
        }
    }
    Ok(())
}

/// Start the control API.
///
/// The order here is deliberate: everything that can be known to be wrong is
/// checked before a socket is opened, so a misconfigured node fails at startup
/// with a specific message instead of serving something it should not.
async fn run(config_path: &Path) -> Result<()> {
    let config = NodeConfig::load(config_path)?;

    let control = config.control.as_ref().context(
        "No control section in the configuration: this node is not paired yet, so there is \
         nothing for LNVPS to command. Register the node first.",
    )?;

    // Refuses immediately if the binary was built without a control key, rather
    // than starting a listener that can never authorise anything (decision 12).
    let control_pubkey = control_auth::control_pubkey()?;

    // Decision 13: the address must belong to the tunnel interface, checked
    // against the interface itself.
    let addrs = config::interface_addresses(&control.tunnel_interface)?;
    config::validate_listen_address(control.listen, &addrs)?;

    let tls = tls::load_or_generate(&config.state_dir, Some(control.listen))?;
    if tls.generated {
        log::warn!(
            "Generated a new TLS certificate (fingerprint {}). LNVPS pins this value at \
             registration, so until the new fingerprint is registered, control requests will \
             not reach this node.",
            tls.fingerprint
        );
    }

    let addr = SocketAddr::new(control.listen, control.port);
    control::serve(Arc::new(ControlState::new(control_pubkey, addr)), addr, tls).await
}
