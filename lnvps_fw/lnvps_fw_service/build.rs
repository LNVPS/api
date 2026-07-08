use aya_build::{Package, Toolchain};

fn main() -> aya_build::Result<()> {
    let ebpf_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../lnvps_ebpf");
    println!("cargo:rerun-if-changed={ebpf_dir}/src");
    println!("cargo:rerun-if-changed={ebpf_dir}/Cargo.toml");
    aya_build::build_ebpf(
        [Package {
            name: "lnvps_ebpf",
            root_dir: ebpf_dir,
            no_default_features: false,
            features: &[],
        }],
        Toolchain::default(),
    )
}
