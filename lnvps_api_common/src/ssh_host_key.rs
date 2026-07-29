use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// One SSH host key of a VM, as a client needs it to verify the host on first
/// connect: the algorithm, the base64 key blob (`known_hosts` third field) and
/// the fingerprint `ssh` prints.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ApiVmHostKey {
    /// Key algorithm, e.g. `ssh-ed25519`.
    pub key_type: String,
    /// Base64 key blob, without the algorithm prefix or any comment.
    pub public_key: String,
    /// `SHA256:…` fingerprint over the decoded key blob, matching
    /// `ssh-keygen -lf` and the banner OpenSSH prints on an unknown host.
    pub fingerprint_sha256: String,
}

/// Algorithms worth storing. Anything else (including `ssh-dss`, which no
/// current OpenSSH offers) is dropped rather than surfaced as a key a client
/// might pin.
const ACCEPTED_KEY_TYPES: [&str; 5] = [
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
];

/// Key families a capture asks the guest for. A guest normally offers one key
/// per family; anything missing means the scan did not get everything.
pub const SCANNED_KEY_FAMILIES: [&str; 3] = ["ed25519", "rsa", "ecdsa"];

/// The family a key algorithm belongs to, collapsing the ECDSA curves.
pub fn key_family(key_type: &str) -> &str {
    if key_type.starts_with("ecdsa-") {
        "ecdsa"
    } else {
        key_type.strip_prefix("ssh-").unwrap_or(key_type)
    }
}

/// Whether a capture holds a key from every family a scan asks for.
///
/// A scan opens one connection per family and can time out on some of them, so
/// a capture short of this is treated as unfinished and scanned again rather
/// than pinning the VM to whichever subset answered first.
pub fn capture_is_complete(keys: &[ApiVmHostKey]) -> bool {
    SCANNED_KEY_FAMILIES
        .iter()
        .all(|f| keys.iter().any(|k| key_family(&k.key_type) == *f))
}

/// Merge a fresh scan into what was already captured, newest key winning per
/// algorithm, and render it back as `known_hosts` lines for `host`.
///
/// Merged rather than replaced so a scan that times out on one family does not
/// drop a key an earlier scan already got.
pub fn merge_ssh_host_keys(host: &str, stored: Option<&str>, scan: &str) -> String {
    let mut merged: Vec<ApiVmHostKey> = stored.map(parse_ssh_host_keys).unwrap_or_default();
    for key in parse_ssh_host_keys(scan) {
        match merged.iter_mut().find(|k| k.key_type == key.key_type) {
            Some(existing) => *existing = key,
            None => merged.push(key),
        }
    }
    merged.sort_by(|a, b| a.key_type.cmp(&b.key_type));
    merged
        .iter()
        .map(|k| format!("{host} {} {}\n", k.key_type, k.public_key))
        .collect()
}

/// Parse `ssh-keyscan` output (or any `known_hosts` fragment) into host keys.
///
/// Lines are `host keytype base64 [comment]`; `ssh-keyscan` also emits `#`
/// comment lines on stderr and, depending on version, on stdout. Anything that
/// is not a well-formed line of an accepted algorithm is dropped: this parses
/// output from a host that could be anything from a stale OpenSSH to a timeout
/// message, and a half-understood line is not a key to pin.
pub fn parse_ssh_host_keys(scan: &str) -> Vec<ApiVmHostKey> {
    let mut keys = Vec::new();
    for line in scan.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(_host), Some(key_type), Some(public_key)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if !ACCEPTED_KEY_TYPES.contains(&key_type) {
            continue;
        }
        let Ok(blob) = BASE64_STANDARD.decode(public_key) else {
            continue;
        };
        let digest = Sha256::digest(&blob);
        keys.push(ApiVmHostKey {
            key_type: key_type.to_string(),
            public_key: public_key.to_string(),
            fingerprint_sha256: format!(
                "SHA256:{}",
                base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
            ),
        });
    }
    keys.sort_by(|a, b| a.key_type.cmp(&b.key_type));
    keys.dedup();
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real `ssh-keyscan` capture: comment lines, two algorithms, and a
    /// trailing comment field on one line.
    const SCAN: &str = "\
# 10.0.0.5:22 SSH-2.0-OpenSSH_9.2p1
10.0.0.5 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIxcwoVKDYPNmQud4AV/iPBbNVYPSr4X0E31b3FQxS/B
# 10.0.0.5:22 SSH-2.0-OpenSSH_9.2p1
10.0.0.5 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLzjP6wKPgJb/zLHyqRA0WZyGbOXVjkB1x/mD8vGw2v88q6+0opgrCYFTsZ3iAMztSDmaJzAf8DipD5cgPVdqfk= root@vm
";

    #[test]
    fn parses_accepted_algorithms_and_fingerprints_them() {
        let keys = parse_ssh_host_keys(SCAN);
        assert_eq!(keys.len(), 2, "{keys:?}");
        let ed = keys.iter().find(|k| k.key_type == "ssh-ed25519").unwrap();
        assert_eq!(
            ed.public_key,
            "AAAAC3NzaC1lZDI1NTE5AAAAIIxcwoVKDYPNmQud4AV/iPBbNVYPSr4X0E31b3FQxS/B"
        );
        // Pinned against `ssh-keygen -lf` for the same key, so a change in
        // digest or encoding fails here rather than shipping a fingerprint that
        // does not match what ssh shows the customer.
        assert_eq!(
            ed.fingerprint_sha256,
            "SHA256:XXJM8fNyKu1oxISUmJkU3eTS4F4FcyW69THWriTri6M"
        );
        assert!(!ed.fingerprint_sha256.ends_with('='), "no base64 padding");
    }

    /// Everything that is not a key line a client could pin is dropped rather
    /// than surfaced: unknown algorithms, malformed base64 and truncated lines.
    #[test]
    fn drops_anything_not_a_well_formed_key() {
        let scan = "\
# comment only
10.0.0.5 ssh-dss AAAAB3NzaC1kc3MAAACBAKQ1
10.0.0.5 ssh-ed25519 not-base64!!
10.0.0.5 ssh-ed25519

";
        assert!(parse_ssh_host_keys(scan).is_empty());
    }

    /// A scan that timed out on one family adds to what is already stored
    /// rather than replacing it, and the result is only complete once every
    /// family answered.
    #[test]
    fn a_later_scan_fills_in_what_an_earlier_one_missed() {
        let ed = "10.0.0.5 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIxcwoVKDYPNmQud4AV/iPBbNVYPSr4X0E31b3FQxS/B\n";
        let ecdsa = "10.0.0.5 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLzjP6wKPgJb/zLHyqRA0WZyGbOXVjkB1x/mD8vGw2v88q6+0opgrCYFTsZ3iAMztSDmaJzAf8DipD5cgPVdqfk=\n";

        assert!(
            !capture_is_complete(&parse_ssh_host_keys(ed)),
            "rsa missing"
        );

        let merged = merge_ssh_host_keys("10.0.0.5", Some(ed), ecdsa);
        let keys = parse_ssh_host_keys(&merged);
        assert_eq!(keys.len(), 2, "the earlier key survives the second scan");
        assert!(!capture_is_complete(&keys), "still no rsa");

        // Re-scanning what is already stored changes nothing.
        assert_eq!(
            merge_ssh_host_keys("10.0.0.5", Some(&merged), ecdsa),
            merged
        );
    }

    /// Every ECDSA curve is one family, so a guest offering nistp384 is not
    /// re-scanned forever waiting for nistp256.
    #[test]
    fn ecdsa_curves_are_one_family() {
        assert_eq!(key_family("ecdsa-sha2-nistp384"), "ecdsa");
        assert_eq!(key_family("ssh-ed25519"), "ed25519");
        assert_eq!(key_family("ssh-rsa"), "rsa");
    }

    /// `ssh-keyscan` reports every listening address, so the same key can
    /// appear once per IP; a client wants the key once.
    #[test]
    fn repeated_keys_collapse() {
        let repeated = format!("{SCAN}{SCAN}");
        assert_eq!(parse_ssh_host_keys(&repeated).len(), 2);
    }
}
