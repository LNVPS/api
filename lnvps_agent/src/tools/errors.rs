pub const NOT_FOUND: &str = "Nothing matches that id or name on this account.";
pub const BACKEND_UNAVAILABLE: &str = "An LNVPS internal service did not answer. This is a platform fault the customer cannot fix. Do not retry in a loop: say so plainly and send them to support@lnvps.net with the VM id.";

pub fn customer_safe(message: &str) -> String {
    if message.contains("no rows returned") {
        return NOT_FOUND.to_string();
    }
    if leaks_internals(message) {
        return BACKEND_UNAVAILABLE.to_string();
    }
    message.to_string()
}

fn leaks_internals(message: &str) -> bool {
    message.contains("http://")
        || message.contains("https://")
        || message.contains("/api2/")
        || message.contains("sqlx")
        || message.contains("10.")
            && message
                .split(|c: char| !(c.is_ascii_digit() || c == '.'))
                .any(is_private_ip)
}

fn is_private_ip(token: &str) -> bool {
    token
        .parse::<std::net::Ipv4Addr>()
        .map(|ip| ip.is_private())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_not_found_becomes_a_plain_not_found() {
        let out = customer_safe(
            "sqlx: no rows returned by a query that expected to return at least one row",
        );
        assert_eq!(out, NOT_FOUND);
    }

    #[test]
    fn hypervisor_urls_and_private_addresses_never_reach_the_model() {
        let raw = "transient error: Request failed: error sending request for url (https://10.97.0.6:8006/api2/json/nodes/pve2/qemu/1506/status/reset)";
        assert_eq!(customer_safe(raw), BACKEND_UNAVAILABLE);
        assert_eq!(
            customer_safe("connect to 10.97.0.6 failed"),
            BACKEND_UNAVAILABLE
        );
    }

    #[test]
    fn ordinary_errors_pass_through() {
        assert_eq!(
            customer_safe("VM 5 does not belong to you"),
            "VM 5 does not belong to you"
        );
        assert_eq!(
            customer_safe("port must be between 1 and 65535"),
            "port must be between 1 and 65535"
        );
    }

    #[test]
    fn a_public_address_in_an_error_is_not_treated_as_internal() {
        assert_eq!(
            customer_safe("no usable IP 185.18.221.5"),
            "no usable IP 185.18.221.5"
        );
    }
}
