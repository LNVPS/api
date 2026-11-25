mod fetch;
pub mod fixtures;
mod lists;
mod screener;

pub use fetch::*;
pub use lists::*;
pub use screener::*;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use lnvps_db::{LNVpsDb, SanctionsField, SanctionsListInfo};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;

pub const NEAR_MATCH_THRESHOLD: f64 = 0.90;
const MIN_TOKEN_LEN: usize = 3;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ListRef {
    pub id: Option<u64>,
    pub source: String,
    pub version: String,
    pub fetched: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchStrength {
    Exact,
    Near,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Hit {
    pub field: SanctionsField,
    pub value: String,
    pub list: ListRef,
    pub entry_id: String,
    pub entry_name: String,
    pub score: f32,
    pub strength: MatchStrength,
}

#[derive(Clone, Debug, Default)]
pub struct Party {
    pub name: Option<String>,
    pub email: Option<String>,
}

#[async_trait]
pub trait SanctionsProvider: Send + Sync {
    fn name(&self) -> &str;

    async fn is_ready(&self) -> Result<bool>;

    async fn screen_party(&self, party: &Party) -> Result<Vec<Hit>>;

    async fn screen_addresses(&self, addresses: &[String]) -> Result<Vec<Hit>>;
}

pub fn normalize_name(name: &str) -> String {
    let folded: String = name
        .nfkd()
        .filter(|c| !is_combining_mark(*c))
        .collect::<String>()
        .to_lowercase();
    let mut tokens: Vec<&str> = folded
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .collect();
    tokens.sort_unstable();
    tokens.join(" ")
}

struct IndexedList {
    list: ListRef,
    entries: Vec<ListEntry>,
    addresses: HashMap<String, Vec<usize>>,
    emails: HashMap<String, Vec<usize>>,
    names: Vec<(usize, String, String)>,
    exact: HashMap<String, Vec<usize>>,
    tokens: HashMap<String, Vec<usize>>,
}

impl IndexedList {
    fn new(list: ListRef, entries: Vec<ListEntry>) -> Self {
        let mut ix = Self {
            list,
            addresses: HashMap::new(),
            emails: HashMap::new(),
            names: Vec::new(),
            exact: HashMap::new(),
            tokens: HashMap::new(),
            entries: Vec::new(),
        };
        for (e, entry) in entries.iter().enumerate() {
            for a in &entry.addresses {
                ix.addresses
                    .entry(normalize_address(&a.address))
                    .or_default()
                    .push(e);
            }
            for m in &entry.emails {
                ix.emails.entry(normalize_email(m)).or_default().push(e);
            }
            for n in &entry.names {
                let norm = normalize_name(n);
                if norm.is_empty() {
                    continue;
                }
                let at = ix.names.len();
                for t in norm
                    .split(' ')
                    .filter(|t| t.chars().count() >= MIN_TOKEN_LEN)
                {
                    ix.tokens.entry(t.to_string()).or_default().push(at);
                }
                ix.exact.entry(norm.clone()).or_default().push(at);
                ix.names.push((e, n.clone(), norm));
            }
        }
        ix.entries = entries;
        ix
    }

    fn hit(&self, field: SanctionsField, value: &str, e: usize, name: &str, score: f64) -> Hit {
        let entry_name = if name.is_empty() {
            self.entries[e].names.first().cloned().unwrap_or_default()
        } else {
            name.to_string()
        };
        Hit {
            field,
            value: value.to_string(),
            list: self.list.clone(),
            entry_id: self.entries[e].id.clone(),
            entry_name,
            score: score as f32,
            strength: if score >= 1.0 {
                MatchStrength::Exact
            } else {
                MatchStrength::Near
            },
        }
    }

    fn by_name(&self, name: &str) -> Vec<Hit> {
        let norm = normalize_name(name);
        if norm.is_empty() {
            return vec![];
        }
        let single_token = !norm.contains(' ');
        let mut best: HashMap<usize, (f64, usize)> = HashMap::new();
        for &at in self.exact.get(&norm).into_iter().flatten() {
            best.insert(self.names[at].0, (1.0, at));
        }
        if !single_token {
            let mut candidates: HashSet<usize> = HashSet::new();
            for t in norm
                .split(' ')
                .filter(|t| t.chars().count() >= MIN_TOKEN_LEN)
            {
                candidates.extend(self.tokens.get(t).into_iter().flatten().copied());
            }
            for at in candidates {
                let (e, _, listed) = &self.names[at];
                if !listed.contains(' ') || best.get(e).is_some_and(|(s, _)| *s >= 1.0) {
                    continue;
                }
                let score = strsim::jaro_winkler(&norm, listed);
                if score >= NEAR_MATCH_THRESHOLD && best.get(e).is_none_or(|(s, _)| *s < score) {
                    best.insert(*e, (score.min(0.999), at));
                }
            }
        }
        best.into_iter()
            .map(|(e, (score, at))| {
                let mut hit = self.hit(SanctionsField::Name, name, e, &self.names[at].1, score);
                if single_token {
                    hit.strength = MatchStrength::Near;
                }
                hit
            })
            .collect()
    }

    fn by_key(
        &self,
        map: &HashMap<String, Vec<usize>>,
        field: SanctionsField,
        key: &str,
        value: &str,
    ) -> Vec<Hit> {
        let mut seen = HashSet::new();
        map.get(key)
            .into_iter()
            .flatten()
            .filter(|e| seen.insert(**e))
            .map(|&e| self.hit(field, value, e, "", 1.0))
            .collect()
    }
}

#[derive(Default)]
pub struct SanctionsIndex {
    lists: Vec<IndexedList>,
}

impl SanctionsIndex {
    pub fn new(lists: Vec<(ListRef, Vec<ListEntry>)>) -> Self {
        Self {
            lists: lists
                .into_iter()
                .map(|(l, e)| IndexedList::new(l, e))
                .collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.lists.is_empty()
    }

    pub fn screen_party(&self, party: &Party) -> Vec<Hit> {
        let mut out = Vec::new();
        for l in &self.lists {
            if let Some(name) = party.name.as_deref().filter(|n| !n.trim().is_empty()) {
                out.extend(l.by_name(name));
            }
            if let Some(email) = party.email.as_deref().filter(|e| !e.trim().is_empty()) {
                out.extend(l.by_key(
                    &l.emails,
                    SanctionsField::Email,
                    &normalize_email(email),
                    email,
                ));
            }
        }
        out
    }

    pub fn screen_addresses(&self, addresses: &[String]) -> Vec<Hit> {
        let mut out = Vec::new();
        for l in &self.lists {
            for a in addresses {
                out.extend(l.by_key(
                    &l.addresses,
                    SanctionsField::Address,
                    &normalize_address(a),
                    a,
                ));
            }
        }
        out
    }
}

pub struct ListSanctionsProvider {
    db: Arc<dyn LNVpsDb>,
    cache: RwLock<(Vec<u64>, Arc<SanctionsIndex>)>,
}

impl ListSanctionsProvider {
    pub fn new(db: Arc<dyn LNVpsDb>) -> Self {
        Self {
            db,
            cache: RwLock::new((vec![], Arc::new(SanctionsIndex::default()))),
        }
    }

    pub async fn index(&self) -> Result<Arc<SanctionsIndex>> {
        let infos = self.db.list_sanctions_lists().await?;
        let ids: Vec<u64> = infos.iter().map(|l| l.id).collect();
        {
            let cache = self.cache.read().await;
            if cache.0 == ids {
                return Ok(cache.1.clone());
            }
        }
        let mut lists = Vec::with_capacity(infos.len());
        for info in &infos {
            let stored = self.db.get_sanctions_list(info.id).await?;
            lists.push((list_ref(info), decode_entries(&stored.entries)?));
        }
        let index = Arc::new(SanctionsIndex::new(lists));
        *self.cache.write().await = (ids, index.clone());
        Ok(index)
    }
}

pub fn list_ref(info: &SanctionsListInfo) -> ListRef {
    ListRef {
        id: Some(info.id),
        source: info.source.clone(),
        version: info.version.clone(),
        fetched: Some(info.fetched),
    }
}

#[async_trait]
impl SanctionsProvider for ListSanctionsProvider {
    fn name(&self) -> &str {
        "official_lists"
    }

    async fn is_ready(&self) -> Result<bool> {
        Ok(!self.index().await?.is_empty())
    }

    async fn screen_party(&self, party: &Party) -> Result<Vec<Hit>> {
        Ok(self.index().await?.screen_party(party))
    }

    async fn screen_addresses(&self, addresses: &[String]) -> Result<Vec<Hit>> {
        Ok(self.index().await?.screen_addresses(addresses))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index() -> SanctionsIndex {
        let ofac = fixtures::ofac().unwrap();
        let eu = fixtures::eu().unwrap();
        SanctionsIndex::new(vec![
            (fixtures::list_ref(&ofac), ofac.entries),
            (fixtures::list_ref(&eu), eu.entries),
        ])
    }

    fn party(name: &str) -> Party {
        Party {
            name: Some(name.to_string()),
            email: None,
        }
    }

    #[test]
    fn names_normalise_case_order_punctuation_and_accents() {
        assert_eq!(
            normalize_name("TESTOV, Ivan Petrovich"),
            "ivan petrovich testov"
        );
        assert_eq!(
            normalize_name("Ívan  petrovich-TESTOV"),
            "ivan petrovich testov"
        );
        assert_eq!(normalize_name(" ,; "), "");
    }

    #[test]
    fn a_listed_address_is_found_and_an_unlisted_one_is_not() {
        let ix = index();
        let hits = ix.screen_addresses(&[fixtures::OFAC_LISTED_ADDRESS.to_uppercase()]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].entry_id, "90001");
        assert_eq!(hits[0].strength, MatchStrength::Exact);
        let hits = ix.screen_addresses(&[fixtures::EU_LISTED_ADDRESS.to_string()]);
        assert_eq!(hits[0].entry_id, "7001");
        assert_eq!(hits[0].list.source, SOURCE_EU_FSF);
        assert!(
            ix.screen_addresses(&[fixtures::UNLISTED_ADDRESS.to_string()])
                .is_empty()
        );
    }

    #[test]
    fn a_normalised_exact_name_is_an_exact_hit() {
        let hits = index().screen_party(&party("ivan petrovich TESTOV"));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].strength, MatchStrength::Exact);
        assert_eq!(hits[0].score, 1.0);
    }

    #[test]
    fn a_near_match_name_is_near_with_a_score() {
        let hits = index().screen_party(&party("Ivan Petrovitch Testov"));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].strength, MatchStrength::Near);
        assert!(hits[0].score >= NEAR_MATCH_THRESHOLD as f32 && hits[0].score < 1.0);
    }

    #[test]
    fn unrelated_and_single_token_names_do_not_hold() {
        let ix = index();
        assert!(ix.screen_party(&party("Maria Fixture Example")).is_empty());
        assert!(ix.screen_party(&party("Ivan Smith")).is_empty());
        let hits = ix.screen_party(&party("Testov"));
        assert!(hits.iter().all(|h| h.strength == MatchStrength::Near));
    }

    #[test]
    fn a_listed_email_is_an_exact_hit() {
        let hits = index().screen_party(&Party {
            name: None,
            email: Some("EU.Listed@example.org".into()),
        });
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].field, SanctionsField::Email);
        assert_eq!(hits[0].entry_id, "7002");
    }
}
