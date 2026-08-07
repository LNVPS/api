//! `lnvps-node` — the LNVPS marketplace node daemon.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

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
    /// Show or apply the data plane LNVPS has asked this node to run.
    Dataplane {
        #[command(subcommand)]
        action: DataplaneAction,
    },
    /// Print the node's TLS fingerprint, the value LNVPS pins at registration.
    Fingerprint {
        /// State directory holding the identity (defaults to the configured one).
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum DataplaneAction {
    /// Fetch what LNVPS wants and print it, changing nothing.
    Show,
    /// Fetch it and apply it.
    Apply,
    /// Print what this machine currently has, read from the machine itself.
    Observe,
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
            // The token is a secret, so only its presence is reported. The
            // node's identity as LNVPS sees it comes from `lnvps-node self`
            // once the control API is reachable.
            let _ = &credential;
            println!(
                "credential: loaded from {}",
                config.credential.file.display()
            );
            match &config.control {
                Some(control) => println!(
                    "control:    {}:{} on {}",
                    control.listen, control.port, control.tunnel_interface
                ),
                None => println!("control:    not configured (node not yet paired)"),
            }
        }
        Command::Dataplane { action } => dataplane(&cli.config, action).await?,
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

/// Show, apply or observe the data plane.
///
/// Exposed as a command of its own so an operator can see exactly what LNVPS
/// asked for, and re-drive it, without running the daemon or reading its logs.
async fn dataplane(config_path: &Path, action: DataplaneAction) -> Result<()> {
    let config = NodeConfig::load(config_path)?;

    // Deliberately before the credential is loaded: "what does this machine
    // have?" is the question an operator asks when something is wrong, and it
    // must not fail because the token is missing or LNVPS is unreachable.
    if let DataplaneAction::Observe = action {
        let state = lnvps_node::net::observe(
            &lnvps_node::net::Kernel::new()?,
            &lnvps_node::fw::SystemFirewall::new(lnvps_node::netns::ensure_default()?),
        )
        .await?;
        println!("{}", serde_json::to_string_pretty(&state)?);
        return Ok(());
    }

    let credential = Credential::load_checked(&config.credential)?;
    let api = lnvps_node::api::LnvpsApi::new(&config.api_url, &credential)?;

    // Presented before fetching: the document describes a tunnel that does not
    // exist until LNVPS has this node's public key, so asking for it first
    // would report "no tunnel allocated" on every first run.
    let key = lnvps_node::wgkey::load_or_generate(&config.state_dir)?;
    if key.generated {
        log::info!("Generated this node's tunnel key; presenting it to LNVPS");
    }
    api.request_tunnel(&key.public_bytes()).await?;
    let desired = api.dataplane().await?;

    match action {
        DataplaneAction::Show => println!("{}", serde_json::to_string_pretty(&desired)?),
        DataplaneAction::Apply => {
            let kernel = lnvps_node::net::Kernel::new()?;
            let fw = lnvps_node::fw::SystemFirewall::new(lnvps_node::netns::ensure_default()?);
            let applied = lnvps_node::net::apply(&kernel, &fw, &desired, &key).await?;
            for line in applied {
                println!("{line}");
            }
        }
        DataplaneAction::Observe => unreachable!("handled above, before loading a credential"),
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

    // The data plane is applied *before* the listen address is checked, because
    // the address being checked for is one this brings into existence: the
    // control API binds the tunnel interface, and on a fresh machine the tunnel
    // does not exist until now.
    let kernel = Arc::new(lnvps_node::net::Kernel::new()?);
    let fw = Arc::new(lnvps_node::fw::SystemFirewall::new(
        lnvps_node::netns::ensure_default()?,
    ));
    if let Err(e) = apply_dataplane(&config, kernel.as_ref(), fw.as_ref()).await {
        // Not fatal. A node whose tunnel is already up from a previous run must
        // keep serving through an LNVPS outage — refusing to start would turn
        // an API blip into every node on the platform going dark.
        log::warn!(
            "Could not apply the data plane ({e}); continuing with whatever this machine \
             already has configured"
        );
    }

    // Decision 13: the address must belong to the tunnel interface, checked
    // against the interface itself — inside the data plane namespace, which is
    // the only place that interface exists.
    let interface = control.tunnel_interface.clone();
    let addrs = kernel
        .namespace()
        .enter(move || config::interface_addresses(&interface))?;
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

    // Re-applied on a timer for the same reason the route server reconciles its
    // end: guests come and go, and a node that only configured itself at
    // startup would route a departed customer's address until it was restarted.
    let refresh = config.clone();
    let refresh_kernel = kernel.clone();
    let refresh_fw = fw.clone();
    tokio::spawn(async move {
        let interval = Duration::from_secs(refresh.heartbeat_secs.max(10));
        loop {
            tokio::time::sleep(interval).await;
            if let Err(e) =
                apply_dataplane(&refresh, refresh_kernel.as_ref(), refresh_fw.as_ref()).await
            {
                log::warn!("Data plane refresh failed: {e}");
            }
        }
    });

    // Bound inside the namespace, because that is where the tunnel address
    // lives. The socket keeps that namespace while the rest of the daemon stays
    // in the machine's own, which is what lets it go on reaching LNVPS.
    let listener = kernel.namespace().enter(move || {
        std::net::TcpListener::bind(addr)
            .with_context(|| format!("Cannot bind the control API to {addr}"))
    })?;

    control::serve_on(
        Arc::new(ControlState::new(control_pubkey, addr, kernel, fw)),
        listener,
        tls,
    )
    .await
}

/// Fetch the data plane and apply it.
async fn apply_dataplane(
    config: &NodeConfig,
    kernel: &dyn lnvps_node::net::NetOps,
    fw: &dyn lnvps_node::fw::FirewallOps,
) -> Result<()> {
    let credential = Credential::load_checked(&config.credential)?;
    let api = lnvps_node::api::LnvpsApi::new(&config.api_url, &credential)?;

    let key = lnvps_node::wgkey::load_or_generate(&config.state_dir)?;
    if key.generated {
        log::warn!(
            "Generated a new tunnel key. LNVPS re-pins a node that presents one, but the \
             tunnel stays down until it has been presented."
        );
    }
    api.request_tunnel(&key.public_bytes()).await?;
    let desired = api.dataplane().await?;

    let applied = lnvps_node::net::apply(kernel, fw, &desired, &key).await?;
    if !applied.is_empty() {
        log::debug!("Applied data plane: {}", applied.join("; "));
    }
    Ok(())
}
