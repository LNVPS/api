use aya_build::{Package, Toolchain};

/// Environment variable selecting the toolchain the eBPF crate is built with.
///
/// The datapath needs a nightly (`-Z build-std` for `bpfel-unknown-none`), and
/// `bpf-linker` binds to one LLVM major, so the toolchain and the linker have
/// to agree. Locally that is whatever `nightly` points at; release builds pin
/// an exact date (see `.github/workflows/lnvps_fw-deb.yml`) and set this so the
/// shipped object comes from the toolchain the harness verified against —
/// verifier acceptance is codegen-sensitive.
const TOOLCHAIN_ENV: &str = "LNVPS_FW_EBPF_TOOLCHAIN";

fn main() -> aya_build::Result<()> {
    let ebpf_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../lnvps_ebpf");
    println!("cargo:rerun-if-changed={ebpf_dir}/src");
    println!("cargo:rerun-if-changed={ebpf_dir}/Cargo.toml");
    println!("cargo:rerun-if-env-changed={TOOLCHAIN_ENV}");
    // `Toolchain::Custom` borrows, so the name has to outlive the call.
    let pinned = std::env::var(TOOLCHAIN_ENV).ok().filter(|s| !s.is_empty());
    let toolchain = match &pinned {
        Some(name) => Toolchain::Custom(name),
        None => Toolchain::default(),
    };
    aya_build::build_ebpf(
        [Package {
            name: "lnvps_ebpf",
            root_dir: ebpf_dir,
            no_default_features: false,
            features: &[],
        }],
        toolchain,
    )
}
