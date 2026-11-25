use super::{ParsedList, SOURCE_EU_FSF, SOURCE_OFAC_SDN, encode_entries, parse_eu, parse_ofac};
use anyhow::{Context, Result};
use chrono::Utc;
use lnvps_db::{LNVpsDb, SanctionsList};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

const KEEP_VERSIONS: u64 = 3;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct SanctionsConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_ofac_url")]
    pub ofac_url: String,
    #[serde(default = "default_eu_url")]
    pub eu_url: String,
}

impl Default for SanctionsConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            ofac_url: default_ofac_url(),
            eu_url: default_eu_url(),
        }
    }
}

fn default_enabled() -> bool {
    true
}

fn default_ofac_url() -> String {
    "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports".to_string()
}

fn default_eu_url() -> String {
    "https://webgate.ec.europa.eu/fsd/fsf/public/files/csvFullSanctionsList_1_1/content?token=dG9rZW4tMjAxNw".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshOutcome {
    Stored { id: u64, entries: u32 },
    Unchanged { id: u64 },
}

pub struct SanctionsListFetcher {
    db: std::sync::Arc<dyn LNVpsDb>,
    client: reqwest::Client,
    config: SanctionsConfig,
}

impl SanctionsListFetcher {
    pub fn new(db: std::sync::Arc<dyn LNVpsDb>, config: SanctionsConfig) -> Result<Self> {
        Ok(Self {
            db,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(300))
                .build()?,
            config,
        })
    }

    async fn get(&self, url: &str) -> Result<Vec<u8>> {
        Ok(self
            .client
            .get(url)
            .send()
            .await
            .with_context(|| format!("fetching {url}"))?
            .error_for_status()?
            .bytes()
            .await?
            .to_vec())
    }

    async fn fetch_ofac(&self) -> Result<(Vec<u8>, ParsedList)> {
        let base = self.config.ofac_url.trim_end_matches('/');
        let sdn = self.get(&format!("{base}/SDN.CSV")).await?;
        let alt = self.get(&format!("{base}/ALT.CSV")).await?;
        let comments = self.get(&format!("{base}/SDN_COMMENTS.CSV")).await?;
        let list = parse_ofac(&sdn, &alt, &comments)?;
        Ok(([sdn, alt, comments].concat(), list))
    }

    async fn fetch_eu(&self) -> Result<(Vec<u8>, ParsedList)> {
        let raw = self.get(&self.config.eu_url).await?;
        let list = parse_eu(&raw)?;
        Ok((raw, list))
    }

    async fn store(&self, raw: Vec<u8>, list: ParsedList) -> Result<RefreshOutcome> {
        let sha = hex::encode(Sha256::digest(&raw));
        let current = self
            .db
            .list_sanctions_lists()
            .await?
            .into_iter()
            .find(|l| l.source == list.source);
        if let Some(c) = current.filter(|c| c.sha256 == sha) {
            self.db.touch_sanctions_list(c.id).await?;
            return Ok(RefreshOutcome::Unchanged { id: c.id });
        }
        let now = Utc::now();
        let version = match &list.published {
            Some(p) => format!("{p} sha256:{}", &sha[..12]),
            None => format!("{} sha256:{}", now.format("%Y-%m-%d"), &sha[..12]),
        };
        let entries = list.entries.len() as u32;
        let id = self
            .db
            .insert_sanctions_list(&SanctionsList {
                source: list.source.clone(),
                version,
                sha256: sha,
                entry_count: entries,
                entries: encode_entries(&list.entries)?,
                fetched: now,
                checked: now,
                ..Default::default()
            })
            .await?;
        self.db
            .prune_sanctions_lists(&list.source, KEEP_VERSIONS)
            .await?;
        Ok(RefreshOutcome::Stored { id, entries })
    }

    pub async fn refresh(&self) -> Vec<(&'static str, Result<RefreshOutcome>)> {
        let ofac = match self.fetch_ofac().await {
            Ok((raw, list)) => self.store(raw, list).await,
            Err(e) => Err(e),
        };
        let eu = match self.fetch_eu().await {
            Ok((raw, list)) => self.store(raw, list).await,
            Err(e) => Err(e),
        };
        let out = vec![(SOURCE_OFAC_SDN, ofac), (SOURCE_EU_FSF, eu)];
        for (source, r) in &out {
            match r {
                Ok(o) => info!("Sanctions list {source}: {o:?}"),
                Err(e) => warn!("Sanctions list {source} refresh failed: {e:#}"),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockDb;
    use crate::sanctions::{ListSanctionsProvider, SanctionsProvider, fixtures};
    use lnvps_db::LNVpsDbBase;
    use std::sync::Arc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn serve(server: &MockServer, p: &str, body: &[u8]) {
        Mock::given(method("GET"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
            .mount(server)
            .await;
    }

    fn config(server: &MockServer) -> SanctionsConfig {
        SanctionsConfig {
            enabled: true,
            ofac_url: format!("{}/ofac", server.uri()),
            eu_url: format!("{}/eu.csv", server.uri()),
        }
    }

    #[tokio::test]
    async fn refresh_stores_each_list_once_and_feeds_the_provider() {
        let server = MockServer::start().await;
        serve(&server, "/ofac/SDN.CSV", fixtures::OFAC_SDN).await;
        serve(&server, "/ofac/ALT.CSV", fixtures::OFAC_ALT).await;
        serve(&server, "/ofac/SDN_COMMENTS.CSV", fixtures::OFAC_COMMENTS).await;
        serve(&server, "/eu.csv", fixtures::EU_CSV).await;
        let db = Arc::new(MockDb::default());
        let fetcher = SanctionsListFetcher::new(db.clone(), config(&server)).unwrap();
        let provider = ListSanctionsProvider::new(db.clone());
        assert!(!provider.is_ready().await.unwrap());

        let first = fetcher.refresh().await;
        assert!(matches!(
            first[0].1,
            Ok(RefreshOutcome::Stored { entries: 4, .. })
        ));
        assert!(matches!(
            first[1].1,
            Ok(RefreshOutcome::Stored { entries: 3, .. })
        ));
        let lists = db.list_sanctions_lists().await.unwrap();
        assert_eq!(lists.len(), 2);
        let eu = lists.iter().find(|l| l.source == SOURCE_EU_FSF).unwrap();
        assert!(eu.version.starts_with("20/11/2026 sha256:"));

        let second = fetcher.refresh().await;
        assert!(matches!(second[0].1, Ok(RefreshOutcome::Unchanged { .. })));
        assert_eq!(db.sanctions_lists.lock().await.len(), 2);

        assert!(provider.is_ready().await.unwrap());
        let hits = provider
            .screen_addresses(&[fixtures::OFAC_LISTED_ADDRESS.to_string()])
            .await
            .unwrap();
        assert_eq!(hits.len(), 1);
        let ofac = lists.iter().find(|l| l.source == SOURCE_OFAC_SDN).unwrap();
        assert_eq!(hits[0].list.id, Some(ofac.id));
        assert_eq!(hits[0].list.version, ofac.version);
        assert!(hits[0].list.fetched.is_some());
    }

    #[tokio::test]
    async fn a_failing_source_does_not_stop_the_other() {
        let server = MockServer::start().await;
        serve(&server, "/eu.csv", fixtures::EU_CSV).await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let db = Arc::new(MockDb::default());
        let out = SanctionsListFetcher::new(db.clone(), config(&server))
            .unwrap()
            .refresh()
            .await;
        assert!(out[0].1.is_err());
        assert!(out[1].1.is_ok());
        assert_eq!(db.list_sanctions_lists().await.unwrap().len(), 1);
    }

    #[test]
    fn config_defaults_to_the_official_lists() {
        let cfg: SanctionsConfig = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(cfg, SanctionsConfig::default());
        assert!(cfg.enabled);
        assert!(
            cfg.ofac_url
                .starts_with("https://sanctionslistservice.ofac.treas.gov/")
        );
        assert!(cfg.eu_url.starts_with("https://webgate.ec.europa.eu/"));
        let off: SanctionsConfig =
            serde_json::from_value(serde_json::json!({"enabled": false})).unwrap();
        assert!(!off.enabled);
    }

    #[tokio::test]
    async fn old_versions_are_pruned() {
        let db = Arc::new(MockDb::default());
        let fetcher = SanctionsListFetcher::new(db.clone(), SanctionsConfig::default()).unwrap();
        for i in 0..5u8 {
            let mut list = fixtures::eu().unwrap();
            list.entries.truncate(1 + (i as usize % 3));
            fetcher.store(vec![i], list).await.unwrap();
        }
        assert_eq!(
            db.sanctions_lists.lock().await.len(),
            KEEP_VERSIONS as usize
        );
        assert_eq!(db.list_sanctions_lists().await.unwrap()[0].id, 5);
    }
}
