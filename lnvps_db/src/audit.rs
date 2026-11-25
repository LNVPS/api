use sha2::{Digest, Sha256};

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NewAuditEntry {
    pub actor_type: String,
    pub actor_id: Option<u64>,
    pub auth_method: Option<String>,
    pub credential_id: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub before_summary: Option<String>,
    pub after_summary: Option<String>,
    pub request_id: Option<String>,
}

impl NewAuditEntry {
    pub fn new(actor_type: &str, actor_id: Option<u64>, action: &str) -> Self {
        Self {
            actor_type: actor_type.to_string(),
            actor_id,
            action: action.to_string(),
            ..Default::default()
        }
    }

    pub fn target(mut self, target_type: &str, target_id: impl ToString) -> Self {
        self.target_type = Some(target_type.to_string());
        self.target_id = Some(target_id.to_string());
        self
    }

    pub fn auth(mut self, method: &str, credential_id: Option<String>) -> Self {
        self.auth_method = Some(method.to_string());
        self.credential_id = credential_id;
        self
    }

    pub fn origin(mut self, ip: Option<String>, user_agent: Option<String>) -> Self {
        self.ip = ip;
        self.user_agent = user_agent;
        self
    }

    pub fn change(mut self, before: Option<String>, after: Option<String>) -> Self {
        self.before_summary = before;
        self.after_summary = after;
        self
    }

    pub fn request(mut self, request_id: Option<String>) -> Self {
        self.request_id = request_id;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct AuditEntry {
    pub id: u64,
    pub created: i64,
    pub actor_type: String,
    pub actor_id: Option<u64>,
    pub auth_method: Option<String>,
    pub credential_id: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub before_summary: Option<String>,
    pub after_summary: Option<String>,
    pub request_id: Option<String>,
    pub prev_hash: String,
    pub hash: String,
}

#[derive(Clone, Debug, Default)]
pub struct AuditFilter {
    pub actor_type: Option<String>,
    pub actor_id: Option<u64>,
    pub action: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub since: Option<i64>,
    pub until: Option<i64>,
}

impl AuditFilter {
    pub fn matches(&self, e: &AuditEntry) -> bool {
        self.actor_type.as_ref().is_none_or(|v| *v == e.actor_type)
            && self.actor_id.is_none_or(|v| Some(v) == e.actor_id)
            && self.action.as_ref().is_none_or(|v| *v == e.action)
            && self
                .target_type
                .as_ref()
                .is_none_or(|v| Some(v) == e.target_type.as_ref())
            && self
                .target_id
                .as_ref()
                .is_none_or(|v| Some(v) == e.target_id.as_ref())
            && self.since.is_none_or(|v| e.created >= v)
            && self.until.is_none_or(|v| e.created <= v)
    }
}

fn field(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(v) => {
            hasher.update([1u8]);
            hasher.update((v.len() as u64).to_be_bytes());
            hasher.update(v.as_bytes());
        }
        None => hasher.update([0u8]),
    }
}

pub fn truncate_ip(ip: &str) -> String {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let o = v4.octets();
            format!("{}.{}.{}.0", o[0], o[1], o[2])
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            let s = v6.segments();
            std::net::Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0).to_string()
        }
        Err(_) => String::new(),
    }
}

pub const IP_RETENTION_DAYS: u32 = 90;

pub fn compute_hash(prev_hash: &str, created: i64, e: &NewAuditEntry) -> String {
    let mut h = Sha256::new();
    field(&mut h, Some(prev_hash));
    field(&mut h, Some(&created.to_string()));
    field(&mut h, Some(&e.actor_type));
    field(&mut h, e.actor_id.map(|v| v.to_string()).as_deref());
    field(&mut h, e.auth_method.as_deref());
    field(&mut h, e.credential_id.as_deref());
    let masked = e.ip.as_deref().map(truncate_ip);
    field(&mut h, masked.as_deref());
    field(&mut h, e.user_agent.as_deref());
    field(&mut h, Some(&e.action));
    field(&mut h, e.target_type.as_deref());
    field(&mut h, e.target_id.as_deref());
    field(&mut h, e.before_summary.as_deref());
    field(&mut h, e.after_summary.as_deref());
    field(&mut h, e.request_id.as_deref());
    hex::encode(h.finalize())
}

impl AuditEntry {
    pub fn seal(id: u64, created: i64, prev_hash: &str, e: NewAuditEntry) -> Self {
        let hash = compute_hash(prev_hash, created, &e);
        Self {
            id,
            created,
            actor_type: e.actor_type,
            actor_id: e.actor_id,
            auth_method: e.auth_method,
            credential_id: e.credential_id,
            ip: e.ip,
            user_agent: e.user_agent,
            action: e.action,
            target_type: e.target_type,
            target_id: e.target_id,
            before_summary: e.before_summary,
            after_summary: e.after_summary,
            request_id: e.request_id,
            prev_hash: prev_hash.to_string(),
            hash,
        }
    }

    fn as_new(&self) -> NewAuditEntry {
        NewAuditEntry {
            actor_type: self.actor_type.clone(),
            actor_id: self.actor_id,
            auth_method: self.auth_method.clone(),
            credential_id: self.credential_id.clone(),
            ip: self.ip.clone(),
            user_agent: self.user_agent.clone(),
            action: self.action.clone(),
            target_type: self.target_type.clone(),
            target_id: self.target_id.clone(),
            before_summary: self.before_summary.clone(),
            after_summary: self.after_summary.clone(),
            request_id: self.request_id.clone(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChainError {
    BrokenLink { id: u64 },
    BadHash { id: u64 },
    Gap { after: u64, found: u64 },
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::BrokenLink { id } => {
                write!(f, "entry {id} does not link to the previous entry")
            }
            ChainError::BadHash { id } => write!(f, "entry {id} content does not match its hash"),
            ChainError::Gap { after, found } => {
                write!(f, "entries missing between {after} and {found}")
            }
        }
    }
}

impl std::error::Error for ChainError {}

#[derive(Debug, PartialEq, Eq)]
pub struct ChainHead {
    pub last_id: u64,
    pub last_hash: String,
}

pub fn verify_chain(
    entries: &[AuditEntry],
    start: Option<&ChainHead>,
) -> Result<ChainHead, ChainError> {
    let mut last_id = start.map(|s| s.last_id).unwrap_or(0);
    let mut last_hash = start
        .map(|s| s.last_hash.clone())
        .unwrap_or_else(|| GENESIS_HASH.to_string());
    for e in entries {
        if e.id != last_id + 1 {
            return Err(ChainError::Gap {
                after: last_id,
                found: e.id,
            });
        }
        if e.prev_hash != last_hash {
            return Err(ChainError::BrokenLink { id: e.id });
        }
        if compute_hash(&e.prev_hash, e.created, &e.as_new()) != e.hash {
            return Err(ChainError::BadHash { id: e.id });
        }
        last_id = e.id;
        last_hash = e.hash.clone();
    }
    Ok(ChainHead { last_id, last_hash })
}

pub const HIGH_RISK_ACTIONS: &[&str] = &[
    "admin.role.assign",
    "admin.role.revoke",
    "admin.refund",
    "admin.vm.delete",
    "admin.vm.purge",
    "auth.token.create",
    "auth.passkey.add",
    "user.email.change",
];

pub fn is_high_risk(action: &str) -> bool {
    HIGH_RISK_ACTIONS.contains(&action)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(n: u64) -> Vec<AuditEntry> {
        let mut out: Vec<AuditEntry> = Vec::new();
        for i in 1..=n {
            let prev = out
                .last()
                .map(|e| e.hash.clone())
                .unwrap_or_else(|| GENESIS_HASH.to_string());
            out.push(AuditEntry::seal(
                i,
                1000 + i as i64,
                &prev,
                NewAuditEntry::new("admin", Some(7), "admin.refund").target("vm", i),
            ));
        }
        out
    }

    #[test]
    fn an_intact_chain_verifies_and_reports_its_head() {
        let c = chain(5);
        let head = verify_chain(&c, None).unwrap();
        assert_eq!(head.last_id, 5);
        assert_eq!(head.last_hash, c[4].hash);
    }

    #[test]
    fn editing_a_row_is_detected() {
        let mut c = chain(5);
        c[2].actor_id = Some(8);
        assert_eq!(verify_chain(&c, None), Err(ChainError::BadHash { id: 3 }));
    }

    #[test]
    fn editing_a_row_and_its_hash_breaks_the_next_link() {
        let mut c = chain(5);
        c[2].after_summary = Some("x".into());
        c[2].hash = compute_hash(&c[2].prev_hash, c[2].created, &c[2].as_new());
        assert_eq!(
            verify_chain(&c, None),
            Err(ChainError::BrokenLink { id: 4 })
        );
    }

    #[test]
    fn deleting_a_row_is_detected() {
        let mut c = chain(5);
        c.remove(1);
        assert_eq!(
            verify_chain(&c, None),
            Err(ChainError::Gap { after: 1, found: 3 })
        );
    }

    #[test]
    fn truncating_the_start_is_caught_without_a_head() {
        let c = chain(5);
        assert_eq!(
            verify_chain(&c[1..], None),
            Err(ChainError::Gap { after: 0, found: 2 })
        );
    }

    #[test]
    fn verification_can_resume_from_a_known_head() {
        let c = chain(5);
        let head = verify_chain(&c[..3], None).unwrap();
        assert_eq!(verify_chain(&c[3..], Some(&head)).unwrap().last_id, 5);
    }

    #[test]
    fn field_boundaries_cannot_be_shifted_between_columns() {
        let a = compute_hash(GENESIS_HASH, 1, &NewAuditEntry::new("ab", None, "c"));
        let b = compute_hash(GENESIS_HASH, 1, &NewAuditEntry::new("a", None, "bc"));
        assert_ne!(a, b);
    }

    #[test]
    fn filter_matches_on_every_set_field() {
        let e = chain(1).remove(0);
        let f = AuditFilter {
            action: Some("admin.refund".into()),
            actor_id: Some(7),
            ..Default::default()
        };
        assert!(f.matches(&e));
        let f = AuditFilter {
            action: Some("other".into()),
            ..Default::default()
        };
        assert!(!f.matches(&e));
    }

    #[test]
    fn truncation_keeps_a_v4_24_and_a_v6_48() {
        assert_eq!(truncate_ip("203.0.113.77"), "203.0.113.0");
        assert_eq!(truncate_ip("2001:db8:abcd:1234::5"), "2001:db8:abcd::");
        assert_eq!(truncate_ip("junk"), "");
    }

    #[test]
    fn truncating_a_stored_ip_keeps_the_chain_valid() {
        let mut c = chain(3);
        let mut e = NewAuditEntry::new("user", Some(1), "auth.login");
        e.ip = Some("203.0.113.77".into());
        let prev = c[2].hash.clone();
        let mut sealed = AuditEntry::seal(4, 2000, &prev, e);
        assert!(
            verify_chain(
                &{
                    let mut all = c.clone();
                    all.push(sealed.clone());
                    all
                },
                None
            )
            .is_ok()
        );
        sealed.ip = Some(truncate_ip(sealed.ip.as_deref().unwrap()));
        c.push(sealed);
        assert_eq!(verify_chain(&c, None).unwrap().last_id, 4);
    }

    #[test]
    fn high_risk_actions_are_flagged() {
        assert!(is_high_risk("admin.role.assign"));
        assert!(!is_high_risk("vm.start"));
    }
}
