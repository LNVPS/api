//! `lnvps-node` — the LNVPS marketplace node daemon.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use lnvps_node::config::NodeConfig;
use lnvps_node::credential::Credential;
use lnvps_node::inventory::Inventory;

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
    /// Print what this node would report about its hardware.
    Inventory,
    /// Check the configuration and credential without contacting LNVPS.
    Check,
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
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
    }
    Ok(())
}
