use anyhow::{Result, anyhow};
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use aya::util::KernelVersion;
use aya::{Ebpf, Pod};
use aya_log::EbpfLogger;
use log::info;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Simple token bucket
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct Bucket {
    /// Tokens available
    pub tokens: u64,
    /// Timestamp in nanoseconds
    pub timestamp: u64,
}

unsafe impl Pod for Bucket {}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::init();

    sudo::escalate_if_needed().map_err(|e| anyhow!("failed to escalate: {}", e))?;

    let kernel = KernelVersion::current()?;
    info!("Running on kernel {}", kernel);

    let program = concat!(
        env!("OUT_DIR"),
        "/lnvps_ebpf/bpfel-unknown-none/release/lnvps_ebpf",
    );
    info!("Loading program: {}", program);

    let mut bpf = Ebpf::load_file(program)?;
    EbpfLogger::init(&mut bpf)?;

    {
        let program: &mut Xdp = bpf.program_mut("xdp_lnvps").unwrap().try_into()?;
        program.load()?;
        program.attach("eno2", XdpFlags::default())?;
    };

    let syn_rates: HashMap<_, [u8; 4], Bucket> =
        HashMap::try_from(bpf.map_mut("V4_SYN_RATE").unwrap())?;

    let b = Arc::new(AtomicBool::new(false));
    let bh = b.clone();
    ctrlc::set_handler(move || {
        bh.store(true, Ordering::Relaxed);
    })?;
    while !b.load(Ordering::Relaxed) {
        for l in syn_rates.iter() {
            if let Ok(limits) = l {
                let tk = limits.1.tokens;
                info!("{}->{}", Ipv4Addr::from(limits.0), tk);
            }
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    info!("Shutdown complete.");
    Ok(())
}
