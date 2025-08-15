use aya_build::cargo_metadata;

fn main() {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .unwrap();
    let ebpf_packages: Vec<cargo_metadata::Package> = packages
        .into_iter()
        .filter(|p| p.name.ends_with("_ebpf"))
        .collect();
    eprintln!("building eBPF packages {:?}", ebpf_packages);
    if ebpf_packages.is_empty() {
        panic!("no eBPF packages found");
    }
    aya_build::build_ebpf(ebpf_packages).ok();
}
