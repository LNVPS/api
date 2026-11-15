use chrono::{DateTime, Duration, Utc};

use crate::ABUSE_LOG_TARGET;

const NEW_ACCOUNT_DAYS: i64 = 7;
const LARGE_CPU: u16 = 16;
const LARGE_MEMORY_BYTES: u64 = 16 * 1024 * 1024 * 1024;

const THROWAWAY_DOMAINS: &[&str] = &[
    "sfmail.cc",
    "xdander.com",
    "fldubai.com",
    "mail.tm",
    "mailinator.com",
    "guerrillamail.com",
    "10minutemail.com",
    "tempmail.com",
    "temp-mail.org",
    "yopmail.com",
    "sharklasers.com",
    "trashmail.com",
    "dispostable.com",
    "getnada.com",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderSignal {
    NewAccount,
    LargeTemplate,
    ThrowawayEmail,
}

impl OrderSignal {
    pub fn name(self) -> &'static str {
        match self {
            Self::NewAccount => "new_account",
            Self::LargeTemplate => "large_template",
            Self::ThrowawayEmail => "throwaway_email",
        }
    }
}

pub fn is_throwaway_domain(email: &str) -> bool {
    let Some(domain) = email.rsplit_once('@').map(|(_, d)| d.trim().to_lowercase()) else {
        return false;
    };
    THROWAWAY_DOMAINS
        .iter()
        .any(|d| domain == *d || domain.ends_with(&format!(".{d}")))
}

pub fn order_signals(
    account_created: DateTime<Utc>,
    now: DateTime<Utc>,
    cpu: u16,
    memory_bytes: u64,
    email: &str,
) -> Vec<OrderSignal> {
    let mut out = Vec::new();
    if now - account_created < Duration::days(NEW_ACCOUNT_DAYS) {
        out.push(OrderSignal::NewAccount);
    }
    if cpu >= LARGE_CPU || memory_bytes >= LARGE_MEMORY_BYTES {
        out.push(OrderSignal::LargeTemplate);
    }
    if is_throwaway_domain(email) {
        out.push(OrderSignal::ThrowawayEmail);
    }
    out
}

pub fn should_alert(signals: &[OrderSignal]) -> bool {
    signals.len() >= 3
}

pub fn alert_message(user_id: u64, vm_id: u64, signals: &[OrderSignal]) -> String {
    let names: Vec<_> = signals.iter().map(|s| s.name()).collect();
    format!(
        "Suspicious order: user {user_id} ordered VM {vm_id} ({})",
        names.join(", ")
    )
}

pub fn log_suspicious_order(user_id: u64, vm_id: u64, signals: &[OrderSignal]) {
    log::error!(target: ABUSE_LOG_TARGET, "{}", alert_message(user_id, vm_id, signals));
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    #[test]
    fn a_new_account_with_a_big_template_and_a_throwaway_domain_alerts() {
        let now = Utc::now();
        let s = order_signals(now - Duration::hours(2), now, 32, 32 * GIB, "x@fldubai.com");
        assert!(should_alert(&s));
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn two_signals_do_not_alert() {
        let now = Utc::now();
        let s = order_signals(now - Duration::hours(2), now, 32, 32 * GIB, "me@example.org");
        assert!(!should_alert(&s));
        let s = order_signals(now - Duration::days(400), now, 32, 32 * GIB, "a@mail.tm");
        assert!(!should_alert(&s));
    }

    #[test]
    fn subdomains_of_throwaway_providers_match_but_lookalikes_do_not() {
        assert!(is_throwaway_domain("a@inbox.mail.tm"));
        assert!(is_throwaway_domain("A@Mailinator.com"));
        assert!(!is_throwaway_domain("a@notmail.tm"));
        assert!(!is_throwaway_domain("no-at-sign"));
    }

    #[test]
    fn a_small_template_is_not_large() {
        let now = Utc::now();
        let s = order_signals(now, now, 2, 4 * GIB, "a@b.c");
        assert_eq!(s, vec![OrderSignal::NewAccount]);
    }
}
