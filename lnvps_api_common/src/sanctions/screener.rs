use super::{Hit, ListRef, MatchStrength, Party, SanctionsProvider};
use crate::{WorkCommander, WorkJob};
use anyhow::Result;
use lnvps_db::{
    LNVpsDb, PaymentMethod, PaymentScreening, SanctionsField, SanctionsMatch, SanctionsMatchFilter,
    SanctionsMatchStatus, SanctionsSubject, ScreeningMode, User,
};
use log::{info, warn};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::Arc;

pub const SOURCE_ENTITY_RULE: &str = "eu_reg_833_2014_art_5b";
const ENTITY_RULE_COUNTRIES: [&str; 2] = ["RUS", "BLR"];
const ENTITY_RULE_VAT_PREFIXES: [&str; 2] = ["RU", "BY"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SanctionsHoldError;

impl fmt::Display for SanctionsHoldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "New orders on this account are on hold pending a compliance review. Please contact support."
        )
    }
}

impl std::error::Error for SanctionsHoldError {}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CustomerScreening {
    pub held: bool,
    pub review: bool,
    pub new_matches: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositDecision {
    Credit,
    Hold,
}

#[derive(Debug, Clone, Default)]
pub struct DepositScreen {
    pub payment_ref: String,
    pub payment_id: Option<Vec<u8>>,
    pub user_id: Option<u64>,
    pub method: PaymentMethod,
    pub address: String,
    pub amount_msat: u64,
}

pub fn is_legal_entity(user: &User) -> bool {
    user.billing_tax_id
        .as_ref()
        .is_some_and(|t| !t.as_str().trim().is_empty())
}

fn entity_country(user: &User) -> Option<String> {
    if let Some(c) = user
        .country_code
        .as_deref()
        .filter(|c| ENTITY_RULE_COUNTRIES.contains(c))
    {
        return Some(c.to_string());
    }
    let tax = user.billing_tax_id.as_ref()?.as_str().trim().to_uppercase();
    ENTITY_RULE_VAT_PREFIXES
        .iter()
        .zip(ENTITY_RULE_COUNTRIES)
        .find(|(p, _)| tax.starts_with(*p))
        .map(|(_, c)| c.to_string())
}

pub fn entity_rule(user: &User) -> Option<Hit> {
    if !is_legal_entity(user) {
        return None;
    }
    let country = entity_country(user)?;
    Some(Hit {
        field: SanctionsField::Entity,
        value: format!(
            "legal entity in {country}: {}",
            user.billing_name
                .as_ref()
                .map(|n| n.as_str())
                .unwrap_or_default()
        ),
        list: ListRef {
            id: None,
            source: SOURCE_ENTITY_RULE.to_string(),
            version: "2022/1904".to_string(),
            fetched: None,
        },
        entry_id: format!("entity:{country}"),
        entry_name: format!("Legal person, entity or body established in {country}"),
        score: 1.0,
        strength: MatchStrength::Exact,
    })
}

fn subject_hash(
    subject: SanctionsSubject,
    key: &str,
    field: SanctionsField,
    value: &str,
) -> Vec<u8> {
    Sha256::digest(
        format!(
            "{subject:?}|{key}|{field:?}|{}",
            value.trim().to_lowercase()
        )
        .as_bytes(),
    )
    .to_vec()
}

pub async fn user_orders_held(db: &dyn LNVpsDb, user_id: u64) -> Result<bool> {
    for status in [SanctionsMatchStatus::Held, SanctionsMatchStatus::Confirmed] {
        let (_, n) = db
            .list_sanctions_matches(
                &SanctionsMatchFilter {
                    subject: Some(SanctionsSubject::User),
                    status: Some(status),
                    user_id: Some(user_id),
                    ..Default::default()
                },
                1,
                0,
            )
            .await?;
        if n > 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

pub async fn ensure_orders_allowed(db: &dyn LNVpsDb, user_id: u64) -> Result<()> {
    if user_orders_held(db, user_id).await? {
        return Err(SanctionsHoldError.into());
    }
    Ok(())
}

pub async fn payment_blocked(db: &dyn LNVpsDb, payment_ref: &str) -> Result<bool> {
    let (rows, _) = db
        .list_sanctions_matches(
            &SanctionsMatchFilter {
                subject: Some(SanctionsSubject::Payment),
                payment_ref: Some(payment_ref.to_string()),
                ..Default::default()
            },
            1000,
            0,
        )
        .await?;
    Ok(rows.iter().any(|m| m.status.blocks()))
}

#[derive(Clone)]
pub struct Screener {
    db: Arc<dyn LNVpsDb>,
    provider: Arc<dyn SanctionsProvider>,
    work: Option<Arc<dyn WorkCommander>>,
}

impl Screener {
    pub fn new(db: Arc<dyn LNVpsDb>, provider: Arc<dyn SanctionsProvider>) -> Self {
        Self {
            db,
            provider,
            work: None,
        }
    }

    pub fn with_notifier(mut self, work: Arc<dyn WorkCommander>) -> Self {
        self.work = Some(work);
        self
    }

    pub fn provider(&self) -> &Arc<dyn SanctionsProvider> {
        &self.provider
    }

    pub async fn record_delegated(
        &self,
        payment_ref: &str,
        payment_id: Option<&[u8]>,
        user_id: Option<u64>,
        method: PaymentMethod,
    ) -> Result<()> {
        record_delegated_screening(
            self.db.as_ref(),
            payment_ref,
            payment_id,
            user_id,
            method,
            None,
        )
        .await
    }

    async fn notify(&self, title: String, message: String) {
        let Some(work) = &self.work else {
            return;
        };
        if let Err(e) = work
            .send(WorkJob::SendAdminNotification {
                title: Some(title),
                message,
            })
            .await
        {
            warn!("Failed to queue sanctions notification: {}", e);
        }
    }

    async fn record(
        &self,
        subject: SanctionsSubject,
        user_id: Option<u64>,
        payment_ref: Option<&str>,
        hit: &Hit,
        status: SanctionsMatchStatus,
    ) -> Result<Option<u64>> {
        let key = match (subject, payment_ref, user_id) {
            (SanctionsSubject::Payment, Some(p), _) => p.to_string(),
            (_, _, Some(u)) => u.to_string(),
            _ => String::new(),
        };
        Ok(self
            .db
            .insert_sanctions_match(&SanctionsMatch {
                subject,
                user_id,
                payment_ref: payment_ref.map(str::to_string),
                field: hit.field,
                subject_value: hit.value.clone().into(),
                subject_hash: subject_hash(subject, &key, hit.field, &hit.value),
                list_id: hit.list.id,
                list_source: hit.list.source.clone(),
                list_version: hit.list.version.clone(),
                list_fetched: hit.list.fetched,
                entry_id: hit.entry_id.clone(),
                entry_name: hit.entry_name.clone(),
                score: hit.score,
                status,
                ..Default::default()
            })
            .await?)
    }

    pub async fn screen_user(&self, user: &User) -> Result<CustomerScreening> {
        let party = Party {
            name: user
                .billing_name
                .as_ref()
                .map(|n| n.as_str().to_string())
                .filter(|n| !n.trim().is_empty()),
            email: Some(user.email.as_str().to_string()).filter(|e| !e.trim().is_empty()),
        };
        let mut hits = Vec::new();
        if party.name.is_some() || party.email.is_some() {
            if self.provider.is_ready().await? {
                hits = self.provider.screen_party(&party).await?;
            } else {
                warn!(
                    "Sanctions lists not loaded, user {} screened by entity rule only",
                    user.id
                );
            }
        }
        hits.extend(entity_rule(user));
        let mut out = CustomerScreening::default();
        let mut lines = Vec::new();
        for hit in &hits {
            let status = match hit.strength {
                MatchStrength::Exact => SanctionsMatchStatus::Held,
                MatchStrength::Near => SanctionsMatchStatus::Review,
            };
            if let Some(id) = self
                .record(SanctionsSubject::User, Some(user.id), None, hit, status)
                .await?
            {
                out.new_matches.push(id);
                lines.push(format!(
                    "#{id} {:?} {:?} -> {} {} \"{}\" score {:.2}",
                    status, hit.field, hit.list.source, hit.entry_id, hit.entry_name, hit.score
                ));
            }
        }
        let (open, _) = self
            .db
            .list_sanctions_matches(
                &SanctionsMatchFilter {
                    subject: Some(SanctionsSubject::User),
                    user_id: Some(user.id),
                    ..Default::default()
                },
                1000,
                0,
            )
            .await?;
        out.held = open.iter().any(|m| m.status.blocks());
        out.review = open
            .iter()
            .any(|m| m.status == SanctionsMatchStatus::Review);
        if !lines.is_empty() {
            info!(
                "Sanctions screening of user {}: {} new match(es)",
                user.id,
                lines.len()
            );
            self.notify(
                format!("Sanctions screening: user {}", user.id),
                format!(
                    "Customer {} matched during sanctions screening. New orders are {}.\n{}\nReview it under /api/admin/v1/sanctions/matches?user_id={}.",
                    user.id,
                    if out.held { "on hold" } else { "allowed until reviewed" },
                    lines.join("\n"),
                    user.id
                ),
            )
            .await;
        }
        Ok(out)
    }

    pub async fn screen_deposit(
        &self,
        d: &DepositScreen,
        sources: Option<Vec<String>>,
    ) -> Result<DepositDecision> {
        if let Some(existing) = self.db.get_payment_screening(&d.payment_ref).await? {
            return Ok(if existing.is_held() {
                DepositDecision::Hold
            } else {
                DepositDecision::Credit
            });
        }
        let mut row = PaymentScreening {
            payment_ref: d.payment_ref.clone(),
            payment_id: d.payment_id.clone(),
            user_id: d.user_id,
            payment_method: d.method,
            provider: self.provider.name().to_string(),
            address: Some(d.address.clone().into()),
            amount_msat: Some(d.amount_msat),
            ..Default::default()
        };
        let ready = self.provider.is_ready().await?;
        let (Some(sources), true) = (sources, ready) else {
            row.mode = ScreeningMode::Unscreened;
            row.held = true;
            row.result = Some(
                if ready {
                    "source addresses unavailable"
                } else {
                    "sanctions lists not loaded"
                }
                .to_string(),
            );
            if self.db.insert_payment_screening(&row).await? {
                warn!(
                    "Deposit {} held until it can be screened: {}",
                    d.payment_ref,
                    row.result.as_deref().unwrap_or_default()
                );
            }
            return Ok(DepositDecision::Hold);
        };
        let hits = self.provider.screen_addresses(&sources).await?;
        row.mode = ScreeningMode::Screened;
        row.sources = Some(sources.join(","));
        row.held = !hits.is_empty();
        row.result = Some(serde_json::to_string(&hits_json(&hits))?);
        if !self.db.insert_payment_screening(&row).await? {
            return Ok(match self.db.get_payment_screening(&d.payment_ref).await? {
                Some(r) if r.is_held() => DepositDecision::Hold,
                _ => DepositDecision::Credit,
            });
        }
        if hits.is_empty() {
            return Ok(DepositDecision::Credit);
        }
        self.record_deposit_hits(d, &hits).await?;
        Ok(DepositDecision::Hold)
    }

    pub async fn rescreen_deposit(
        &self,
        row: &PaymentScreening,
        sources: Vec<String>,
    ) -> Result<DepositDecision> {
        if !self.provider.is_ready().await? {
            return Ok(DepositDecision::Hold);
        }
        let hits = self.provider.screen_addresses(&sources).await?;
        let mut updated = row.clone();
        updated.mode = ScreeningMode::Screened;
        updated.provider = self.provider.name().to_string();
        updated.sources = Some(sources.join(","));
        updated.result = Some(serde_json::to_string(&hits_json(&hits))?);
        self.db.update_payment_screening(&updated).await?;
        if hits.is_empty() {
            return Ok(DepositDecision::Credit);
        }
        let d = DepositScreen {
            payment_ref: row.payment_ref.clone(),
            payment_id: row.payment_id.clone(),
            user_id: row.user_id,
            method: row.payment_method,
            address: row
                .address
                .as_ref()
                .map(|a| a.as_str().to_string())
                .unwrap_or_default(),
            amount_msat: row.amount_msat.unwrap_or_default(),
        };
        self.record_deposit_hits(&d, &hits).await?;
        Ok(DepositDecision::Hold)
    }

    async fn record_deposit_hits(&self, d: &DepositScreen, hits: &[Hit]) -> Result<()> {
        let mut lines = Vec::new();
        for hit in hits {
            if let Some(id) = self
                .record(
                    SanctionsSubject::Payment,
                    d.user_id,
                    Some(&d.payment_ref),
                    hit,
                    SanctionsMatchStatus::Held,
                )
                .await?
            {
                lines.push(format!(
                    "#{id} source {} -> {} {} \"{}\"",
                    hit.value, hit.list.source, hit.entry_id, hit.entry_name
                ));
            }
        }
        warn!(
            "Deposit {} held: source address matched a sanctions list",
            d.payment_ref
        );
        self.notify(
            format!("Sanctions hold: on-chain deposit {}", d.payment_ref),
            format!(
                "An on-chain deposit of {} sats (outpoint {}, user {}) was held because a source address is on a sanctions list. It has not been credited or refunded.\n{}\nReview it under /api/admin/v1/sanctions/matches?payment_ref={}.",
                d.amount_msat / 1000,
                d.payment_ref,
                d.user_id.map(|u| u.to_string()).unwrap_or_else(|| "unknown".into()),
                lines.join("\n"),
                d.payment_ref
            ),
        )
        .await;
        Ok(())
    }
}

fn hits_json(hits: &[Hit]) -> serde_json::Value {
    serde_json::Value::Array(
        hits.iter()
            .map(|h| {
                serde_json::json!({
                    "value": h.value,
                    "source": h.list.source,
                    "version": h.list.version,
                    "entry_id": h.entry_id,
                    "entry_name": h.entry_name,
                    "score": h.score,
                })
            })
            .collect(),
    )
}

pub async fn record_delegated_screening(
    db: &dyn LNVpsDb,
    payment_ref: &str,
    payment_id: Option<&[u8]>,
    user_id: Option<u64>,
    method: PaymentMethod,
    result: Option<serde_json::Value>,
) -> Result<()> {
    let Some(provider) = delegated_provider(method) else {
        return Ok(());
    };
    db.insert_payment_screening(&PaymentScreening {
        payment_ref: payment_ref.to_string(),
        payment_id: payment_id.map(<[u8]>::to_vec),
        user_id,
        payment_method: method,
        mode: ScreeningMode::Delegated,
        provider: provider.to_string(),
        result: result.map(|r| r.to_string()),
        ..Default::default()
    })
    .await?;
    Ok(())
}

pub async fn record_delegated_payment(
    db: &dyn LNVpsDb,
    payment: &lnvps_db::SubscriptionPayment,
    result: Option<serde_json::Value>,
) {
    if let Err(e) = record_delegated_screening(
        db,
        &hex::encode(&payment.id),
        Some(&payment.id),
        Some(payment.user_id),
        payment.payment_method,
        result,
    )
    .await
    {
        warn!(
            "Failed to record delegated screening for payment {}: {}",
            hex::encode(&payment.id),
            e
        );
    }
}

pub fn delegated_provider(method: PaymentMethod) -> Option<&'static str> {
    match method {
        PaymentMethod::Lightning => Some("lightning"),
        PaymentMethod::Revolut => Some("revolut"),
        PaymentMethod::Stripe => Some("stripe"),
        PaymentMethod::Paypal => Some("paypal"),
        PaymentMethod::Gateway => Some("payment_gateway"),
        PaymentMethod::FixedFloat => Some("fixedfloat"),
        PaymentMethod::OnChain => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockDb;
    use crate::sanctions::{SanctionsIndex, fixtures};
    use async_trait::async_trait;
    use lnvps_db::LNVpsDbBase;

    struct FixtureProvider(SanctionsIndex);

    #[async_trait]
    impl SanctionsProvider for FixtureProvider {
        fn name(&self) -> &str {
            "fixture"
        }
        async fn is_ready(&self) -> Result<bool> {
            Ok(!self.0.is_empty())
        }
        async fn screen_party(&self, party: &Party) -> Result<Vec<Hit>> {
            Ok(self.0.screen_party(party))
        }
        async fn screen_addresses(&self, addresses: &[String]) -> Result<Vec<Hit>> {
            Ok(self.0.screen_addresses(addresses))
        }
    }

    fn screener(db: Arc<MockDb>) -> Screener {
        let ofac = fixtures::ofac().unwrap();
        let eu = fixtures::eu().unwrap();
        Screener::new(
            db,
            Arc::new(FixtureProvider(SanctionsIndex::new(vec![
                (fixtures::list_ref(&ofac), ofac.entries),
                (fixtures::list_ref(&eu), eu.entries),
            ]))),
        )
    }

    fn user(id: u64, name: &str, country: &str, tax_id: Option<&str>) -> User {
        User {
            id,
            email: format!("customer{id}@example.net").into(),
            billing_name: Some(name.into()),
            country_code: Some(country.to_string()),
            billing_tax_id: tax_id.map(Into::into),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_russian_individual_is_allowed() {
        let db = Arc::new(MockDb::default());
        let s = screener(db.clone());
        let out = s
            .screen_user(&user(1, "Olga Fixture Example", "RUS", None))
            .await
            .unwrap();
        assert_eq!(out, CustomerScreening::default());
        assert!(!user_orders_held(db.as_ref(), 1).await.unwrap());
        ensure_orders_allowed(db.as_ref(), 1).await.unwrap();
    }

    #[tokio::test]
    async fn a_russian_company_is_held() {
        let db = Arc::new(MockDb::default());
        let s = screener(db.clone());
        let out = s
            .screen_user(&user(2, "Fixture Widgets OOO", "RUS", Some("7700000000")))
            .await
            .unwrap();
        assert!(out.held);
        let err = ensure_orders_allowed(db.as_ref(), 2).await.unwrap_err();
        assert!(err.downcast_ref::<SanctionsHoldError>().is_some());
        let m = db.get_sanctions_match(out.new_matches[0]).await.unwrap();
        assert_eq!(m.field, SanctionsField::Entity);
        assert_eq!(m.list_source, SOURCE_ENTITY_RULE);
        assert_eq!(m.status, SanctionsMatchStatus::Held);
    }

    #[tokio::test]
    async fn a_belarus_vat_number_marks_an_entity_without_a_country() {
        let mut u = user(3, "Fixture Belarus Ltd", "IRL", Some("BY100000000"));
        assert!(entity_rule(&u).is_some());
        u.billing_tax_id = Some("IE1234567X".into());
        assert!(entity_rule(&u).is_none());
        u.billing_tax_id = Some("  ".into());
        u.country_code = Some("RUS".into());
        assert!(entity_rule(&u).is_none());
    }

    #[tokio::test]
    async fn a_near_match_name_goes_to_review_not_to_a_block() {
        let db = Arc::new(MockDb::default());
        let s = screener(db.clone());
        let out = s
            .screen_user(&user(4, "Ivan Petrovitch Testov", "DEU", None))
            .await
            .unwrap();
        assert!(out.review);
        assert!(!out.held);
        assert!(!user_orders_held(db.as_ref(), 4).await.unwrap());
        let m = db.get_sanctions_match(out.new_matches[0]).await.unwrap();
        assert_eq!(m.status, SanctionsMatchStatus::Review);
        assert!(m.score < 1.0);
        assert_eq!(m.list_version, "fixture");
        assert!(m.list_fetched.is_some());
    }

    #[tokio::test]
    async fn an_exact_name_holds_and_is_logged_once() {
        let db = Arc::new(MockDb::default());
        let s = screener(db.clone());
        let u = user(5, "Ivan Petrovich TESTOV", "DEU", None);
        let out = s.screen_user(&u).await.unwrap();
        assert!(out.held);
        assert_eq!(out.new_matches.len(), 1);
        let again = s.screen_user(&u).await.unwrap();
        assert!(again.held);
        assert!(again.new_matches.is_empty());
    }

    #[tokio::test]
    async fn a_cleared_match_stops_holding_orders() {
        let db = Arc::new(MockDb::default());
        let s = screener(db.clone());
        let u = user(6, "Ivan Petrovich Testov", "DEU", None);
        let id = s.screen_user(&u).await.unwrap().new_matches[0];
        assert!(
            db.resolve_sanctions_match(id, SanctionsMatchStatus::Cleared, 9, "different person")
                .await
                .unwrap()
        );
        assert!(!user_orders_held(db.as_ref(), 6).await.unwrap());
        assert!(!s.screen_user(&u).await.unwrap().held);
    }

    #[tokio::test]
    async fn a_listed_source_address_is_held_and_an_unlisted_one_passes() {
        let db = Arc::new(MockDb::default());
        let s = screener(db.clone());
        let held = DepositScreen {
            payment_ref: "aa:0".into(),
            user_id: Some(7),
            method: PaymentMethod::OnChain,
            address: "bcrt1qours".into(),
            amount_msat: 5_000_000,
            ..Default::default()
        };
        assert_eq!(
            s.screen_deposit(&held, Some(vec![fixtures::OFAC_LISTED_ADDRESS.to_string()]))
                .await
                .unwrap(),
            DepositDecision::Hold
        );
        assert!(payment_blocked(db.as_ref(), "aa:0").await.unwrap());
        assert_eq!(
            s.screen_deposit(&held, None).await.unwrap(),
            DepositDecision::Hold
        );
        let clean = DepositScreen {
            payment_ref: "bb:1".into(),
            ..held.clone()
        };
        assert_eq!(
            s.screen_deposit(&clean, Some(vec![fixtures::UNLISTED_ADDRESS.to_string()]))
                .await
                .unwrap(),
            DepositDecision::Credit
        );
        let row = db.get_payment_screening("bb:1").await.unwrap().unwrap();
        assert_eq!(row.mode, ScreeningMode::Screened);
        assert!(!row.held);
    }

    #[tokio::test]
    async fn an_unscreenable_deposit_is_held_then_rescreened() {
        let db = Arc::new(MockDb::default());
        let s = screener(db.clone());
        let d = DepositScreen {
            payment_ref: "cc:0".into(),
            method: PaymentMethod::OnChain,
            ..Default::default()
        };
        assert_eq!(
            s.screen_deposit(&d, None).await.unwrap(),
            DepositDecision::Hold
        );
        let row = db.get_payment_screening("cc:0").await.unwrap().unwrap();
        assert_eq!(row.mode, ScreeningMode::Unscreened);
        assert_eq!(
            s.rescreen_deposit(&row, vec![fixtures::UNLISTED_ADDRESS.into()])
                .await
                .unwrap(),
            DepositDecision::Credit
        );
        assert_eq!(
            db.get_payment_screening("cc:0")
                .await
                .unwrap()
                .unwrap()
                .mode,
            ScreeningMode::Screened
        );
    }

    #[tokio::test]
    async fn delegated_checks_are_recorded_once() {
        let db = Arc::new(MockDb::default());
        let r = hex::encode([1u8; 32]);
        record_delegated_screening(
            db.as_ref(),
            &r,
            Some(&[1u8; 32]),
            Some(1),
            PaymentMethod::Revolut,
            Some(serde_json::json!({"risk_level": "low"})),
        )
        .await
        .unwrap();
        record_delegated_screening(db.as_ref(), &r, None, Some(1), PaymentMethod::Revolut, None)
            .await
            .unwrap();
        let row = db.get_payment_screening(&r).await.unwrap().unwrap();
        assert_eq!(row.mode, ScreeningMode::Delegated);
        assert_eq!(row.provider, "revolut");
        assert_eq!(row.result.as_deref(), Some(r#"{"risk_level":"low"}"#));
        record_delegated_screening(db.as_ref(), "x:0", None, None, PaymentMethod::OnChain, None)
            .await
            .unwrap();
        assert!(db.get_payment_screening("x:0").await.unwrap().is_none());
        assert_eq!(delegated_provider(PaymentMethod::Stripe), Some("stripe"));
    }
}
