use axum::http::Method;

pub const API_TOKEN_PREFIX: &str = "lnvps_";
pub const MAX_API_TOKEN_TTL_DAYS: u64 = 365;
pub const DEFAULT_API_TOKEN_TTL_DAYS: u64 = 90;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenScope {
    Read,
    Vm,
}

impl TokenScope {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "vm" => Some(Self::Vm),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Vm => "vm",
        }
    }

    pub fn allows(self, method: &Method, path: &str) -> bool {
        if !path.starts_with("/api/v1/") || path.starts_with("/api/v1/account/tokens") {
            return false;
        }
        let read_only = matches!(*method, Method::GET | Method::HEAD);
        let creates_payment = path.contains("/renew") || path.contains("/upgrade");
        match self {
            Self::Read => read_only && !creates_payment,
            Self::Vm => {
                if read_only {
                    return path.starts_with("/api/v1/vm") && !creates_payment;
                }
                *method == Method::PATCH
                    && path.strip_prefix("/api/v1/vm/").is_some_and(|rest| {
                        matches!(
                            rest.split_once('/'),
                            Some((id, "start" | "stop" | "restart"))
                                if id.chars().all(|c| c.is_ascii_digit())
                        )
                    })
            }
        }
    }
}

pub fn new_api_token() -> String {
    format!("{API_TOKEN_PREFIX}{}", hex::encode(rand::random::<[u8; 32]>()))
}

pub fn is_api_token(bearer: &str) -> bool {
    bearer.starts_with(API_TOKEN_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_read_token_never_writes() {
        assert!(TokenScope::Read.allows(&Method::GET, "/api/v1/vm"));
        assert!(!TokenScope::Read.allows(&Method::PATCH, "/api/v1/vm/1/stop"));
        assert!(!TokenScope::Read.allows(&Method::POST, "/api/v1/vm"));
    }

    #[test]
    fn a_vm_token_controls_vms_but_cannot_spend_or_destroy() {
        let s = TokenScope::Vm;
        assert!(s.allows(&Method::GET, "/api/v1/vm"));
        assert!(s.allows(&Method::PATCH, "/api/v1/vm/1/start"));
        assert!(s.allows(&Method::PATCH, "/api/v1/vm/1/restart"));
        assert!(!s.allows(&Method::PATCH, "/api/v1/vm/1/re-install"));
        assert!(!s.allows(&Method::POST, "/api/v1/vm"));
        assert!(!s.allows(&Method::GET, "/api/v1/vm/1/renew"));
        assert!(!s.allows(&Method::POST, "/api/v1/vm/1/upgrade"));
        assert!(!s.allows(&Method::DELETE, "/api/v1/vm/1"));
        assert!(!s.allows(&Method::GET, "/api/v1/account"));
    }

    #[test]
    fn tokens_never_reach_the_admin_api() {
        assert!(!TokenScope::Read.allows(&Method::GET, "/api/admin/v1/users"));
        assert!(!TokenScope::Vm.allows(&Method::GET, "/api/admin/v1/vms"));
    }

    #[test]
    fn tokens_cannot_manage_tokens() {
        assert!(!TokenScope::Read.allows(&Method::GET, "/api/v1/account/tokens"));
        assert!(!TokenScope::Vm.allows(&Method::POST, "/api/v1/account/tokens"));
    }

    #[test]
    fn parse_round_trips() {
        for s in [TokenScope::Read, TokenScope::Vm] {
            assert_eq!(TokenScope::parse(s.as_str()), Some(s));
        }
        assert_eq!(TokenScope::parse("admin"), None);
    }
}
