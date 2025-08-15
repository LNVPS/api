use aya::Ebpf;
use aya::programs::{Xdp, XdpFlags};
use aya_log::EbpfLogger;
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/lnvps_ebpf/bpfel-unknown-none/release/lnvps_ebpf",
    )))?;

    EbpfLogger::init(&mut bpf)?;

    let program: &mut Xdp = bpf.program_mut("xdp_lnvps").unwrap().try_into()?;
    program.load()?;
    program.attach("eno2", XdpFlags::default())?;

    signal::ctrl_c().await?;
    Ok(())
}
