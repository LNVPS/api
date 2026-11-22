use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use lnvps_db::{LNVpsDb, OnChainAddressType, PaymentMethod, PaymentMethodConfig, ProviderConfig};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::sync::Arc;

pub const CONFIRM_ENV: &str = "GATEWAY_IMPORT_CONFIRM";

pub fn confirm_apply(apply: bool, env: Option<&str>) -> Result<()> {
    if apply && env != Some("yes") {
        bail!("--apply refused: set {CONFIRM_ENV}=yes to confirm creating providers");
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct NewProvider {
    pub method: String,
    pub provider_type: String,
    pub name: String,
    pub config: Value,
    pub fee_rate: Option<f64>,
    pub fee_base: Option<u64>,
    pub fee_currency: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ExistingProvider {
    pub id: u64,
    pub method: String,
    pub provider_type: String,
    pub name: String,
}

#[async_trait]
pub trait GatewayAdmin: Send + Sync {
    async fn list_providers(&self, tenant: u64) -> Result<Vec<ExistingProvider>>;
    async fn create_provider(&self, tenant: u64, provider: &NewProvider) -> Result<u64>;
    async fn set_enabled(&self, tenant: u64, provider_id: u64, enabled: bool) -> Result<()>;
}

pub struct HttpGatewayAdmin {
    http: reqwest::Client,
    base: String,
    token: String,
}

impl HttpGatewayAdmin {
    pub fn new(base: &str, admin_token: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            base: base.trim_end_matches('/').to_string(),
            token: admin_token.to_string(),
        }
    }

    fn url(&self, tenant: u64, rest: &str) -> String {
        format!("{}/admin/tenants/{tenant}/providers{rest}", self.base)
    }
}

#[async_trait]
impl GatewayAdmin for HttpGatewayAdmin {
    async fn list_providers(&self, tenant: u64) -> Result<Vec<ExistingProvider>> {
        let res = self
            .http
            .get(self.url(tenant, ""))
            .bearer_auth(&self.token)
            .send()
            .await?;
        let status = res.status();
        if !status.is_success() {
            bail!("listing providers failed with {status}");
        }
        Ok(res.json().await?)
    }

    async fn create_provider(&self, tenant: u64, provider: &NewProvider) -> Result<u64> {
        let res = self
            .http
            .post(self.url(tenant, ""))
            .bearer_auth(&self.token)
            .json(provider)
            .send()
            .await?;
        let status = res.status();
        if !status.is_success() {
            let body = res.text().await.unwrap_or_default();
            bail!(
                "creating provider '{}' failed with {status}: {body}",
                provider.name
            );
        }
        let body: Value = res.json().await?;
        body.get("id")
            .and_then(Value::as_u64)
            .context("gateway reply has no provider id")
    }

    async fn set_enabled(&self, tenant: u64, provider_id: u64, enabled: bool) -> Result<()> {
        let res = self
            .http
            .post(self.url(tenant, &format!("/{provider_id}/enabled")))
            .bearer_auth(&self.token)
            .json(&json!({ "enabled": enabled }))
            .send()
            .await?;
        let status = res.status();
        if !status.is_success() {
            bail!("setting provider {provider_id} enabled={enabled} failed with {status}");
        }
        Ok(())
    }
}

pub trait CredentialReader: Send + Sync {
    fn read(&self, path: &std::path::Path) -> Result<Vec<u8>>;
}

pub struct FsCredentials;

impl CredentialReader for FsCredentials {
    fn read(&self, path: &std::path::Path) -> Result<Vec<u8>> {
        std::fs::read(path).with_context(|| format!("reading {}", path.display()))
    }
}

pub fn map_config(
    cfg: &PaymentMethodConfig,
    name: &str,
    creds: &dyn CredentialReader,
) -> Result<NewProvider> {
    let provider = cfg
        .get_provider_config()
        .context("provider config is missing or does not parse")?;
    let (method, provider_type, config) = match provider {
        ProviderConfig::Lnd(lnd) => (
            "lightning",
            "lnd",
            json!({
                "url": lnd.url,
                "cert": pem(creds, &lnd.cert_path)?,
                "macaroon": hex::encode(creds.read(&lnd.macaroon_path)?),
            }),
        ),
        ProviderConfig::OnChain(oc) => {
            let address_type = match oc.address_type {
                OnChainAddressType::WitnessPubkeyHash => "p2wkh",
                OnChainAddressType::NestedPubkeyHash => "np2wkh",
                OnChainAddressType::TaprootPubkey => "p2tr",
            };
            let mut config = json!({
                "url": oc.url,
                "cert": pem(creds, &oc.cert_path)?,
                "macaroon": hex::encode(creds.read(&oc.macaroon_path)?),
                "address_type": address_type,
                "min_confirmations": oc.min_confirmations,
            });
            if let Some(account) = oc.account {
                config["account"] = json!(account);
            }
            ("onchain", "lnd", config)
        }
        ProviderConfig::FixedFloat(ff) => {
            if cfg.supported_currencies.is_empty() {
                bail!("FixedFloat needs supported_currencies, the gateway requires a coin list");
            }
            let mut config = json!({
                "api_key": ff.api_key,
                "api_secret": ff.api_secret,
                "coins": cfg.supported_currencies.iter().map(|c| c.to_uppercase()).collect::<Vec<_>>(),
            });
            if let Some(url) = ff.url {
                config["url"] = json!(url);
            }
            if let Some(refcode) = ff.refcode {
                config["refcode"] = json!(refcode);
            }
            if let Some(afftax) = ff.afftax {
                config["afftax"] = json!(afftax);
            }
            ("fixedfloat", "fixedfloat", config)
        }
        ProviderConfig::Revolut(r) => (
            "revolut",
            "revolut",
            json!({
                "url": r.url,
                "token": r.token,
                "api_version": r.api_version,
                "public_key": r.public_key,
            }),
        ),
        ProviderConfig::Stripe(s) => (
            "stripe",
            "stripe",
            json!({
                "secret_key": s.secret_key,
                "webhook_secret": s.webhook_secret,
            }),
        ),
        ProviderConfig::Paypal(_) => {
            bail!("PayPal needs a webhook_id the old config does not have, add it in the console")
        }
    };
    Ok(NewProvider {
        method: method.to_string(),
        provider_type: provider_type.to_string(),
        name: name.to_string(),
        config,
        fee_rate: cfg.processing_fee_rate.map(f64::from),
        fee_base: cfg.processing_fee_base,
        fee_currency: cfg.processing_fee_currency.clone(),
    })
}

fn pem(creds: &dyn CredentialReader, path: &std::path::Path) -> Result<String> {
    let text = String::from_utf8(creds.read(path)?)
        .with_context(|| format!("{} is not a PEM file", path.display()))?;
    if !text.contains("BEGIN CERTIFICATE") {
        bail!("{} is not a PEM certificate", path.display());
    }
    Ok(text)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportAction {
    Create { disabled: bool },
    AlreadyPresent { id: u64 },
    Skip { reason: String },
}

#[derive(Debug, Clone)]
pub struct ImportLine {
    pub config_id: u64,
    pub company_id: u64,
    pub method: PaymentMethod,
    pub name: String,
    pub action: ImportAction,
}

#[derive(Debug, Default)]
pub struct ImportReport {
    pub lines: Vec<ImportLine>,
    pub applied: bool,
}

impl ImportReport {
    pub fn created(&self) -> usize {
        self.count(|a| matches!(a, ImportAction::Create { .. }))
    }

    pub fn present(&self) -> usize {
        self.count(|a| matches!(a, ImportAction::AlreadyPresent { .. }))
    }

    pub fn skipped(&self) -> usize {
        self.count(|a| matches!(a, ImportAction::Skip { .. }))
    }

    fn count(&self, f: impl Fn(&ImportAction) -> bool) -> usize {
        self.lines.iter().filter(|l| f(&l.action)).count()
    }
}

pub struct ImportOptions {
    pub tenant: u64,
    pub apply: bool,
    pub company_id: Option<u64>,
}

pub async fn import_providers(
    db: &Arc<dyn LNVpsDb>,
    gateway: &dyn GatewayAdmin,
    creds: &dyn CredentialReader,
    opts: &ImportOptions,
) -> Result<ImportReport> {
    let configs: Vec<PaymentMethodConfig> = db
        .list_payment_method_configs()
        .await?
        .into_iter()
        .filter(|c| opts.company_id.is_none_or(|id| c.company_id == id))
        .collect();
    let multiple_companies = configs
        .iter()
        .map(|c| c.company_id)
        .collect::<HashSet<_>>()
        .len()
        > 1;
    let existing = gateway.list_providers(opts.tenant).await?;
    let mut report = ImportReport {
        applied: opts.apply,
        ..Default::default()
    };
    let mut seen: HashSet<(String, String, String)> = existing
        .iter()
        .map(|e| (e.method.clone(), e.provider_type.clone(), e.name.clone()))
        .collect();

    for cfg in configs {
        let name = if multiple_companies {
            format!("{} (company {})", cfg.name, cfg.company_id)
        } else {
            cfg.name.clone()
        };
        let line = |action| ImportLine {
            config_id: cfg.id,
            company_id: cfg.company_id,
            method: cfg.payment_method,
            name: name.clone(),
            action,
        };
        let provider = match map_config(&cfg, &name, creds) {
            Ok(p) => p,
            Err(e) => {
                report.lines.push(line(ImportAction::Skip {
                    reason: format!("{e:#}"),
                }));
                continue;
            }
        };
        let key = (
            provider.method.clone(),
            provider.provider_type.clone(),
            provider.name.clone(),
        );
        if let Some(found) = existing
            .iter()
            .find(|e| e.method == key.0 && e.provider_type == key.1 && e.name == key.2)
        {
            report
                .lines
                .push(line(ImportAction::AlreadyPresent { id: found.id }));
            continue;
        }
        if !seen.insert(key) {
            report.lines.push(line(ImportAction::Skip {
                reason: "another config in this run has the same method, type and name".into(),
            }));
            continue;
        }
        let disabled = !cfg.enabled;
        if opts.apply {
            let id = gateway.create_provider(opts.tenant, &provider).await?;
            if disabled {
                gateway.set_enabled(opts.tenant, id, false).await?;
            }
        }
        report.lines.push(line(ImportAction::Create { disabled }));
    }
    Ok(report)
}

pub fn render_report(report: &ImportReport) -> String {
    let mut out = String::new();
    for l in &report.lines {
        let what = match &l.action {
            ImportAction::Create { disabled: false } => "create".to_string(),
            ImportAction::Create { disabled: true } => "create (disabled)".to_string(),
            ImportAction::AlreadyPresent { id } => format!("already present as provider {id}"),
            ImportAction::Skip { reason } => format!("skip: {reason}"),
        };
        out.push_str(&format!(
            "config {} company {} {:?} '{}': {}\n",
            l.config_id, l.company_id, l.method, l.name, what
        ));
    }
    out.push_str(&format!(
        "{}: {} created, {} already present, {} skipped\n",
        if report.applied { "applied" } else { "dry run" },
        report.created(),
        report.present(),
        report.skipped()
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::MockDb;
    use lnvps_db::{
        FixedFloatProviderConfig, LNVpsDbBase, LndConfig, OnChainProviderConfig,
        PaypalProviderConfig, RevolutProviderConfig,
    };
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    struct Files;

    impl CredentialReader for Files {
        fn read(&self, p: &Path) -> Result<Vec<u8>> {
            match p.to_str().unwrap() {
                "/lnd/tls.cert" => Ok(b"-----BEGIN CERTIFICATE-----\nabc\n".to_vec()),
                "/lnd/admin.macaroon" => Ok(vec![1, 2, 3]),
                other => bail!("no such file {other}"),
            }
        }
    }

    #[derive(Default)]
    struct FakeAdmin {
        existing: Mutex<Vec<ExistingProvider>>,
        created: Mutex<Vec<NewProvider>>,
        disabled: Mutex<Vec<u64>>,
    }

    #[async_trait]
    impl GatewayAdmin for FakeAdmin {
        async fn list_providers(&self, _tenant: u64) -> Result<Vec<ExistingProvider>> {
            Ok(self.existing.lock().unwrap().clone())
        }

        async fn create_provider(&self, _tenant: u64, p: &NewProvider) -> Result<u64> {
            let mut created = self.created.lock().unwrap();
            created.push(p.clone());
            Ok(100 + created.len() as u64)
        }

        async fn set_enabled(&self, _tenant: u64, id: u64, enabled: bool) -> Result<()> {
            assert!(!enabled);
            self.disabled.lock().unwrap().push(id);
            Ok(())
        }
    }

    fn lnd() -> LndConfig {
        LndConfig {
            url: "https://lnd:10009".into(),
            cert_path: PathBuf::from("/lnd/tls.cert"),
            macaroon_path: PathBuf::from("/lnd/admin.macaroon"),
        }
    }

    fn cfg(company: u64, name: &str, enabled: bool, p: ProviderConfig) -> PaymentMethodConfig {
        PaymentMethodConfig::new_with_config(company, p.payment_method(), name.into(), enabled, p)
    }

    async fn db_with(configs: Vec<PaymentMethodConfig>) -> Arc<dyn LNVpsDb> {
        let db = MockDb::default();
        for c in configs {
            db.insert_payment_method_config(&c).await.unwrap();
        }
        Arc::new(db)
    }

    fn opts(apply: bool) -> ImportOptions {
        ImportOptions {
            tenant: 7,
            apply,
            company_id: None,
        }
    }

    #[test]
    fn apply_needs_the_exact_confirmation() {
        assert!(confirm_apply(false, None).is_ok());
        assert!(confirm_apply(false, Some("no")).is_ok());
        for bad in [None, Some("no"), Some(""), Some("YES"), Some("yes ")] {
            let err = confirm_apply(true, bad).unwrap_err().to_string();
            assert!(err.contains("GATEWAY_IMPORT_CONFIRM"), "{err}");
        }
        assert!(confirm_apply(true, Some("yes")).is_ok());
    }

    #[test]
    fn lnd_config_is_sent_with_inline_credentials() {
        let c = cfg(1, "main", true, ProviderConfig::Lnd(lnd()));
        let p = map_config(&c, "main", &Files).unwrap();
        assert_eq!(
            (p.method.as_str(), p.provider_type.as_str()),
            ("lightning", "lnd")
        );
        assert_eq!(p.config["macaroon"], "010203");
        assert!(
            p.config["cert"]
                .as_str()
                .unwrap()
                .contains("BEGIN CERTIFICATE")
        );
        assert!(p.config.get("cert_path").is_none());
    }

    #[test]
    fn onchain_config_keeps_address_type_and_confirmations() {
        let c = cfg(
            1,
            "chain",
            true,
            ProviderConfig::OnChain(OnChainProviderConfig {
                url: "https://lnd:10009".into(),
                cert_path: PathBuf::from("/lnd/tls.cert"),
                macaroon_path: PathBuf::from("/lnd/admin.macaroon"),
                address_type: OnChainAddressType::TaprootPubkey,
                account: Some("deposits".into()),
                min_confirmations: 3,
                unpaid_purge_grace_hours: 24,
            }),
        );
        let p = map_config(&c, "chain", &Files).unwrap();
        assert_eq!(
            (p.method.as_str(), p.provider_type.as_str()),
            ("onchain", "lnd")
        );
        assert_eq!(p.config["address_type"], "p2tr");
        assert_eq!(p.config["min_confirmations"], 3);
        assert_eq!(p.config["account"], "deposits");
    }

    #[test]
    fn fixedfloat_needs_a_coin_list_and_carries_it_over() {
        let ff = || {
            ProviderConfig::FixedFloat(FixedFloatProviderConfig {
                api_key: "k".into(),
                api_secret: "s".into(),
                url: None,
                refcode: Some("ref".into()),
                afftax: Some(0.5),
            })
        };
        let empty = cfg(1, "ff", true, ff());
        assert!(map_config(&empty, "ff", &Files).is_err());

        let mut listed = cfg(1, "ff", true, ff());
        listed.supported_currencies =
            lnvps_db::CommaSeparated::new(vec!["xmr".to_string(), "LTC".to_string()]);
        let p = map_config(&listed, "ff", &Files).unwrap();
        assert_eq!(p.config["coins"], json!(["XMR", "LTC"]));
        assert_eq!(p.config["refcode"], "ref");
        assert_eq!(p.config["afftax"], 0.5);
    }

    #[test]
    fn fees_and_revolut_map_across_and_paypal_is_refused() {
        let mut rev = cfg(
            1,
            "card",
            true,
            ProviderConfig::Revolut(RevolutProviderConfig {
                url: "https://merchant.revolut.com".into(),
                token: "t".into(),
                api_version: "2024-09-01".into(),
                public_key: "pk".into(),
                webhook_secret: Some("never sent".into()),
            }),
        );
        rev.processing_fee_rate = Some(1.5);
        rev.processing_fee_base = Some(20);
        rev.processing_fee_currency = Some("EUR".into());
        let p = map_config(&rev, "card", &Files).unwrap();
        assert_eq!(p.fee_rate, Some(1.5));
        assert_eq!(p.fee_base, Some(20));
        assert_eq!(p.fee_currency.as_deref(), Some("EUR"));
        assert!(p.config.get("webhook_secret").is_none());

        let pay = cfg(
            1,
            "pp",
            true,
            ProviderConfig::Paypal(PaypalProviderConfig {
                client_id: "i".into(),
                client_secret: "s".into(),
                mode: "live".into(),
            }),
        );
        assert!(map_config(&pay, "pp", &Files).is_err());
    }

    #[tokio::test]
    async fn dry_run_reports_and_creates_nothing() {
        let db = db_with(vec![cfg(1, "main", true, ProviderConfig::Lnd(lnd()))]).await;
        let admin = FakeAdmin::default();
        let report = import_providers(&db, &admin, &Files, &opts(false))
            .await
            .unwrap();
        assert_eq!(report.created(), 1);
        assert!(!report.applied);
        assert!(admin.created.lock().unwrap().is_empty());
        let text = render_report(&report);
        assert!(text.contains("dry run: 1 created"), "{text}");
        assert!(!text.contains("010203"), "secrets are never printed");
    }

    #[tokio::test]
    async fn apply_creates_providers_and_disables_disabled_ones() {
        let db = db_with(vec![
            cfg(1, "main", true, ProviderConfig::Lnd(lnd())),
            cfg(1, "old", false, ProviderConfig::Lnd(lnd())),
        ])
        .await;
        let admin = FakeAdmin::default();
        let report = import_providers(&db, &admin, &Files, &opts(true))
            .await
            .unwrap();
        assert_eq!(report.created(), 2);
        assert_eq!(admin.created.lock().unwrap().len(), 2);
        assert_eq!(admin.disabled.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_second_run_creates_nothing_new() {
        let db = db_with(vec![cfg(1, "main", true, ProviderConfig::Lnd(lnd()))]).await;
        let admin = FakeAdmin::default();
        admin.existing.lock().unwrap().push(ExistingProvider {
            id: 55,
            method: "lightning".into(),
            provider_type: "lnd".into(),
            name: "main".into(),
        });
        let report = import_providers(&db, &admin, &Files, &opts(true))
            .await
            .unwrap();
        assert_eq!(report.present(), 1);
        assert_eq!(report.created(), 0);
        assert!(admin.created.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unmappable_configs_are_skipped_not_fatal() {
        let db = db_with(vec![
            cfg(
                1,
                "pp",
                true,
                ProviderConfig::Paypal(PaypalProviderConfig {
                    client_id: "i".into(),
                    client_secret: "s".into(),
                    mode: "live".into(),
                }),
            ),
            cfg(1, "main", true, ProviderConfig::Lnd(lnd())),
        ])
        .await;
        let admin = FakeAdmin::default();
        let report = import_providers(&db, &admin, &Files, &opts(true))
            .await
            .unwrap();
        assert_eq!(report.skipped(), 1);
        assert_eq!(report.created(), 1);
    }

    #[tokio::test]
    async fn companies_with_the_same_config_name_do_not_collide() {
        let db = db_with(vec![
            cfg(1, "main", true, ProviderConfig::Lnd(lnd())),
            cfg(2, "main", true, ProviderConfig::Lnd(lnd())),
        ])
        .await;
        let admin = FakeAdmin::default();
        import_providers(&db, &admin, &Files, &opts(true))
            .await
            .unwrap();
        let mut names: Vec<String> = admin
            .created
            .lock()
            .unwrap()
            .iter()
            .map(|p| p.name.clone())
            .collect();
        names.sort();
        assert_eq!(names, vec!["main (company 1)", "main (company 2)"]);

        let only_two = ImportOptions {
            tenant: 7,
            apply: false,
            company_id: Some(2),
        };
        let report = import_providers(&db, &FakeAdmin::default(), &Files, &only_two)
            .await
            .unwrap();
        assert_eq!(report.lines.len(), 1);
        assert_eq!(report.lines[0].name, "main");
    }

    #[tokio::test]
    async fn http_client_sends_the_admin_token_and_reads_the_id() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/admin/tenants/7/providers"))
            .and(header("authorization", "Bearer adm"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"id": 3, "tenant_id": 7, "method": "lightning", "provider_type": "lnd",
                 "name": "x", "enabled": true}
            ])))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/admin/tenants/7/providers"))
            .and(header("authorization", "Bearer adm"))
            .and(body_json(json!({
                "method": "fixedfloat", "provider_type": "fixedfloat", "name": "ff",
                "config": {"api_key": "k"}, "fee_rate": null, "fee_base": null,
                "fee_currency": null
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": 9})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/admin/tenants/7/providers/9/enabled"))
            .and(body_json(json!({"enabled": false})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
            .mount(&server)
            .await;

        let admin = HttpGatewayAdmin::new(&server.uri(), "adm");
        assert_eq!(admin.list_providers(7).await.unwrap()[0].id, 3);
        let id = admin
            .create_provider(
                7,
                &NewProvider {
                    method: "fixedfloat".into(),
                    provider_type: "fixedfloat".into(),
                    name: "ff".into(),
                    config: json!({"api_key": "k"}),
                    fee_rate: None,
                    fee_base: None,
                    fee_currency: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(id, 9);
        admin.set_enabled(7, 9, false).await.unwrap();
    }
}
