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
        // The blob names its own algorithm first; a mismatch means the line was
        // assembled wrong and the fingerprint would not be the host's.
        if !blob_declares_type(&blob, key_type) {
            continue;
        }
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

/// Whether an SSH public key blob starts with the given algorithm name, which
/// every key format encodes as its first length-prefixed string.
fn blob_declares_type(blob: &[u8], key_type: &str) -> bool {
    let Some(len_bytes) = blob.get(..4) else {
        return false;
    };
    let len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    blob.get(4..4 + len) == Some(key_type.as_bytes())
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
    /// than surfaced: unknown algorithms, malformed base64, truncated lines,
    /// and a line whose blob does not agree with its stated algorithm.
    #[test]
    fn drops_anything_not_a_well_formed_key() {
        let scan = "\
# comment only
10.0.0.5 ssh-dss AAAAB3NzaC1kc3MAAACBAKQ1
10.0.0.5 ssh-ed25519 not-base64!!
10.0.0.5 ssh-ed25519
10.0.0.5 ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIIxcwoVKDYPNmQud4AV/iPBbNVYPSr4X0E31b3FQxS/B

";
        assert!(parse_ssh_host_keys(scan).is_empty());
    }

    /// `ssh-keyscan` reports every listening address, so the same key can
    /// appear once per IP; a client wants the key once.
    #[test]
    fn repeated_keys_collapse() {
        let repeated = format!("{SCAN}{SCAN}");
        assert_eq!(parse_ssh_host_keys(&repeated).len(), 2);
    }
}
