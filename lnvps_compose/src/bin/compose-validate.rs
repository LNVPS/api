//! `compose-validate` — parse, validate and report the resource footprint of
//! one or more managed-app `compose` documents (the same checks the admin
//! catalog API and the operator apply).
//!
//! ```text
//! compose-validate app.yaml other.yaml   # validate the given files
//! cat app.yaml | compose-validate         # or read one doc from stdin
//! ```
//!
//! Exits non-zero if any document fails to parse or validate.

use lnvps_compose::Compose;
use std::io::Read;
use std::process::ExitCode;

/// Human-readable byte size (binary units) for footprint reporting.
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.2} {}", UNITS[u])
    }
}

/// Parse + validate a single document and format a one-line summary.
///
/// Returns `Ok(summary)` when the document is valid, or `Err(message)`
/// describing the first failure.
fn check(source: &str) -> Result<String, String> {
    let compose = Compose::parse(source).map_err(|e| format!("parse error: {e}"))?;
    compose
        .validate()
        .map_err(|e| format!("validation error: {e}"))?;
    // This CLI is an authoring tool, so it applies the admission-only rule that
    // every `${...}` is declared — the same check the admin API performs.
    compose
        .validate_declarations()
        .map_err(|e| format!("validation error: {e}"))?;
    let f = compose
        .footprint()
        .map_err(|e| format!("footprint error: {e}"))?;
    let vars = compose.referenced_vars();
    let vars_note = if vars.is_empty() {
        String::new()
    } else {
        format!("; vars: {}", vars.join(", "))
    };
    Ok(format!(
        "{} service(s), cpu={}m memory={} storage={}{}",
        compose.services.len(),
        f.cpu_milli,
        human_bytes(f.memory_bytes),
        human_bytes(f.storage_bytes),
        vars_note
    ))
}

/// Read a whole file (or stdin for `-`).
fn read_source(path: &str) -> std::io::Result<String> {
    if path == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path)
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // No arguments → read a single document from stdin.
    let paths: Vec<String> = if args.is_empty() {
        vec!["-".to_string()]
    } else {
        args
    };

    let mut ok = true;
    for path in &paths {
        let label = if path == "-" { "<stdin>" } else { path };
        match read_source(path) {
            Ok(src) => match check(&src) {
                Ok(summary) => println!("OK   {label}: {summary}"),
                Err(e) => {
                    eprintln!("FAIL {label}: {e}");
                    ok = false;
                }
            },
            Err(e) => {
                eprintln!("FAIL {label}: cannot read: {e}");
                ok = false;
            }
        }
    }

    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_bytes_scales() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.00 KiB");
        assert_eq!(human_bytes(256 * 1024 * 1024), "256.00 MiB");
        assert_eq!(human_bytes(10 * 1024 * 1024 * 1024), "10.00 GiB");
    }

    #[test]
    fn check_ok_reports_footprint_and_vars() {
        let yaml = "services:\n  a:\n    image: x\n    resources: { cpu: 250m, memory: 256Mi }\n    env:\n      URL: \"${host}\"\nconfig:\n  - { name: host, type: string }\n";
        let summary = check(yaml).expect("valid");
        assert!(summary.contains("1 service(s)"));
        assert!(summary.contains("cpu=250m"));
        assert!(summary.contains("memory=256.00 MiB"));
        assert!(summary.contains("vars: host"));
    }

    #[test]
    fn check_rejects_invalid() {
        // Bogus YAML.
        assert!(check(": : :").is_err());
        // Parses but fails validation: ingress on a non-http port.
        let bad = "services:\n  a:\n    image: x\n    ports:\n      - { name: p, container: 5432, protocol: tcp, expose: ingress }\n";
        assert!(check(bad).is_err());
    }
}
