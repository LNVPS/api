fn main() {
    let bpf_linker = which::which("bpf-linker");
    match bpf_linker {
        Err(_) => {
            eprintln!("bpf-linker not found");
        }
        Ok(p) => println!("cargo:rerun-if-changed={}", p.display()),
    }
}
