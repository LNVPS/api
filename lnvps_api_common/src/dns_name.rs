//! Validation for hostnames a customer asks us to serve.
//!
//! Two separate questions, deliberately kept apart: whether a name is a
//! syntactically valid public hostname, and whether it is one this deployment
//! will accept. The second needs the operator's own hostnames, which the first
//! knows nothing about.

use anyhow::{Result, bail};

/// Longest name the DNS carries, and the width of the `nostr_domain.name`
/// column.
const MAX_DOMAIN_LEN: usize = 200;

/// Suffixes that resolve to something other than the public DNS, or to nothing
/// at all. A customer cannot prove control of any of them and no certificate
/// authority will issue for them, so a row naming one is an Ingress that can
/// never serve traffic.
///
/// RFC 6761 and RFC 8375 special-use names, RFC 2606 examples, the names ICANN
/// reserved after the .corp/.home/.mail collision review, and `.onion`, which
/// is real but not reachable over the ingress.
const RESERVED_TLDS: &[&str] = &[
    "alt",
    "corp",
    "example",
    "home",
    "internal",
    "invalid",
    "lan",
    "local",
    "localdomain",
    "localhost",
    "mail",
    "onion",
    "test",
];

/// RFC 2606 example domains: valid syntax, owned by IANA, never a customer's.
const RESERVED_DOMAINS: &[&str] = &["example.com", "example.net", "example.org"];

/// Normalise and check a public hostname.
///
/// Returns the canonical form to store: trimmed, lowercased, with any trailing
/// root dot removed, so `Blog.Example.COM.` and `blog.example.com` cannot both
/// be registered as if they were different names.
pub fn validate_public_domain(input: &str) -> Result<String> {
    let name = input.trim().trim_end_matches('.').to_ascii_lowercase();

    if name.is_empty() {
        bail!("domain is required");
    }
    if name.len() > MAX_DOMAIN_LEN {
        bail!("domain must be at most {MAX_DOMAIN_LEN} characters");
    }
    // Named before the label check, because these are what people actually
    // paste: a URL, a host:port, or an email address. "invalid character" is
    // true but tells them nothing about which part to delete.
    if name.contains("://") || name.contains('/') {
        bail!("enter the domain only, without a scheme or path (e.g. nostr.example.com)");
    }
    if name.contains(':') {
        bail!("enter the domain only, without a port");
    }
    if name.contains('@') {
        bail!("enter the domain only, without an email local part");
    }
    if name.contains('_') {
        bail!("domain labels may not contain underscores");
    }
    if !name.is_ascii() {
        bail!(
            "international domains must be entered in their punycode form (e.g. xn--pbt981c.com)"
        );
    }

    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() < 2 {
        bail!("domain must include a top-level domain (e.g. nostr.example.com)");
    }
    for label in &labels {
        let ok = !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !ok {
            bail!("'{label}' is not a valid DNS label");
        }
    }

    // The last label is what makes this a name rather than an address: a
    // numeric one means an IP was pasted, which has no NIP-05 document and
    // cannot be pointed at us with a CNAME.
    let tld = labels[labels.len() - 1];
    let punycode = tld.starts_with("xn--");
    if !punycode && !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        bail!("'{tld}' is not a top-level domain — enter a domain name, not an IP address");
    }
    if tld.len() < 2 {
        bail!("'{tld}' is not a top-level domain");
    }
    if RESERVED_TLDS.contains(&tld) {
        bail!("'.{tld}' is a reserved name that cannot be reached from the public internet");
    }
    if RESERVED_DOMAINS.contains(&labels[labels.len() - 2..].join(".").as_str()) {
        bail!("'{name}' is a reserved example domain");
    }

    Ok(name)
}

/// Whether `name` is `suffix` or sits underneath it.
///
/// Both are expected in the canonical form [`validate_public_domain`] returns.
/// Compared label-wise, so `notlnvps.net` is not treated as a subdomain of
/// `lnvps.net`.
pub fn is_under(name: &str, suffix: &str) -> bool {
    name == suffix || name.ends_with(&format!(".{suffix}"))
}

/// The suffixes a deployment refuses to let a customer register, derived from
/// its own hostnames plus anything the operator listed explicitly.
///
/// Each configured host contributes itself **and its parent**, so an API on
/// `api.lnvps.net` reserves the whole of `lnvps.net`: the hostnames LNVPS
/// serves from are not all in the config, and a customer who registers one gets
/// an Ingress in the same cluster claiming that host. The parent is only taken
/// when it is itself a domain (`lnvps.net`, not `net`), so a deployment whose
/// public URL is a bare registrable domain reserves that domain and no more.
pub fn reserved_suffixes<'a>(hosts: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for host in hosts {
        let Ok(host) = validate_public_domain(host) else {
            continue;
        };
        let parent = host.split_once('.').map(|(_, rest)| rest.to_string());
        for candidate in [Some(host), parent].into_iter().flatten() {
            if candidate.matches('.').count() >= 1 && !out.contains(&candidate) {
                out.push(candidate);
            }
        }
    }
    out
}

/// The hostname part of a configured URL, for [`reserved_suffixes`].
///
/// Deliberately tolerant: config carries `https://api.lnvps.net`,
/// `api.lnvps.net` and occasionally a trailing path, and a value this cannot
/// parse must not become an empty reservation that blocks nothing silently.
pub fn host_of(url: &str) -> Option<String> {
    let rest = url
        .trim()
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url.trim());
    let host = rest
        .split(['/', '?', '#'])
        .next()?
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or_else(|| rest.split(['/', '?', '#']).next().unwrap_or(""));
    let host = host.split(':').next()?.trim();
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_valid_domain_is_normalised() {
        assert_eq!(
            validate_public_domain(" Nostr.MyRelay.COM. ").unwrap(),
            "nostr.myrelay.com"
        );
        assert_eq!(validate_public_domain("a-b.co.uk").unwrap(), "a-b.co.uk");
        assert_eq!(
            validate_public_domain("xn--pbt981c.com").unwrap(),
            "xn--pbt981c.com"
        );
    }

    /// What people actually paste. Each of these used to be stored verbatim and
    /// became an Ingress rule that could never serve anything.
    #[test]
    fn a_domain_that_is_not_a_domain_is_refused() {
        for bad in [
            "",
            "   ",
            "localhost",
            "example",
            "https://nostr.myrelay.com",
            "nostr.myrelay.com/nip05",
            "nostr.myrelay.com:8080",
            "user@myrelay.com",
            "my_domain.com",
            "nostr.myrelay.local",
            "box.internal",
            "thing.test",
            "example.com",
            "nostr.example.com",
            "-bad.myrelay.com",
            "bad-.myrelay.com",
            "192.168.1.1",
            "1.2.3.4",
            "ünicode.com",
        ] {
            assert!(validate_public_domain(bad).is_err(), "'{bad}' was accepted");
        }
    }

    #[test]
    fn a_domain_that_is_too_long_is_refused() {
        let long = format!("{}.com", "a".repeat(MAX_DOMAIN_LEN));
        assert!(validate_public_domain(&long).is_err());
    }

    /// The operator's own names, and everything under the domain they sit in:
    /// an API on `api.lnvps.net` is not the only thing LNVPS serves from
    /// `lnvps.net`, and the rest are not in the config to be listed.
    #[test]
    fn a_deployment_reserves_its_own_domain_and_its_parent() {
        let reserved = reserved_suffixes(["api.lnvps.net", "nostr.lnvps.net"]);
        assert_eq!(
            reserved,
            vec!["api.lnvps.net", "lnvps.net", "nostr.lnvps.net"]
        );

        assert!(reserved.iter().any(|s| is_under("api.lnvps.net", s)));
        assert!(reserved.iter().any(|s| is_under("anything.lnvps.net", s)));
        assert!(reserved.iter().any(|s| is_under("lnvps.net", s)));
        assert!(!reserved.iter().any(|s| is_under("notlnvps.net", s)));
        assert!(!reserved.iter().any(|s| is_under("lnvps.com", s)));
    }

    /// A bare registrable domain reserves itself, not its TLD.
    #[test]
    fn a_bare_domain_does_not_reserve_a_tld() {
        assert_eq!(reserved_suffixes(["lnvps.net"]), vec!["lnvps.net"]);
        assert!(!is_under("someone-else.net", "lnvps.net"));
    }

    #[test]
    fn a_host_is_taken_from_whatever_the_config_holds() {
        assert_eq!(
            host_of("https://api.lnvps.net").as_deref(),
            Some("api.lnvps.net")
        );
        assert_eq!(
            host_of("http://api.lnvps.net:8000/").as_deref(),
            Some("api.lnvps.net")
        );
        assert_eq!(host_of("API.lnvps.net").as_deref(), Some("api.lnvps.net"));
        assert_eq!(host_of("").as_deref(), None);
    }
}
