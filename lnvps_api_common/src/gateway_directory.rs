use crate::{GatewayClient, OffSessionRenewals, PaymentGateway};
use anyhow::Result;
use lnvps_db::{
    GatewayOffSession, GatewayProviderConfig, LNVpsDb, PaymentMethod, PaymentMethodConfig,
};
use std::sync::Arc;

pub const GATEWAY_PROVIDER_TYPE: &str = "gateway";

pub type GatewayFactory =
    Arc<dyn Fn(&GatewayProviderConfig) -> Arc<dyn PaymentGateway> + Send + Sync>;

pub fn default_gateway_factory() -> GatewayFactory {
    Arc::new(|c| Arc::new(GatewayClient::from_parts(&c.url, &c.api_key)))
}

pub fn off_session_from_row(mode: GatewayOffSession) -> OffSessionRenewals {
    match mode {
        GatewayOffSession::Off => OffSessionRenewals::Off,
        GatewayOffSession::DryRun => OffSessionRenewals::DryRun,
        GatewayOffSession::Live => OffSessionRenewals::Live,
    }
}

#[derive(Clone)]
pub struct GatewayRow {
    pub id: u64,
    pub company_id: u64,
    pub enabled: bool,
    pub config: GatewayProviderConfig,
}

pub fn gateway_row(config: &PaymentMethodConfig) -> Option<GatewayRow> {
    if config.provider_type != GATEWAY_PROVIDER_TYPE {
        return None;
    }
    Some(GatewayRow {
        id: config.id,
        company_id: config.company_id,
        enabled: config.enabled,
        config: config.get_provider_config()?.as_gateway()?.clone(),
    })
}

pub enum GatewaySource {
    Row,
    Yaml,
    None,
}

#[derive(Clone)]
pub struct GatewayDirectory {
    db: Arc<dyn LNVpsDb>,
    factory: GatewayFactory,
    in_process_lightning: Arc<dyn PaymentGateway>,
    lightning: Option<Arc<dyn PaymentGateway>>,
    onchain: Option<Arc<dyn PaymentGateway>>,
    swap: Option<Arc<dyn PaymentGateway>>,
    card: Option<Arc<dyn PaymentGateway>>,
    off_session: OffSessionRenewals,
}

impl GatewayDirectory {
    pub fn new(db: Arc<dyn LNVpsDb>, in_process_lightning: Arc<dyn PaymentGateway>) -> Self {
        Self {
            db,
            factory: default_gateway_factory(),
            in_process_lightning,
            lightning: None,
            onchain: None,
            swap: None,
            card: None,
            off_session: OffSessionRenewals::Off,
        }
    }

    pub fn with_factory(mut self, factory: GatewayFactory) -> Self {
        self.factory = factory;
        self
    }

    pub fn with_lightning(mut self, g: Arc<dyn PaymentGateway>) -> Self {
        self.lightning = Some(g);
        self
    }

    pub fn with_onchain(mut self, g: Arc<dyn PaymentGateway>) -> Self {
        self.onchain = Some(g);
        self
    }

    pub fn with_swap(mut self, g: Arc<dyn PaymentGateway>) -> Self {
        self.swap = Some(g);
        self
    }

    pub fn with_card(mut self, g: Arc<dyn PaymentGateway>) -> Self {
        self.card = Some(g);
        self
    }

    pub fn with_off_session(mut self, mode: OffSessionRenewals) -> Self {
        self.off_session = mode;
        self
    }

    fn legacy(&self, method: PaymentMethod) -> Option<Arc<dyn PaymentGateway>> {
        match method {
            PaymentMethod::Lightning => self.lightning.clone(),
            PaymentMethod::OnChain => self.onchain.clone(),
            PaymentMethod::FixedFloat => self.swap.clone(),
            PaymentMethod::Revolut | PaymentMethod::Stripe => self.card.clone(),
            PaymentMethod::Paypal | PaymentMethod::Gateway => None,
        }
    }

    pub async fn rows_for_company(&self, company_id: u64) -> Result<Vec<GatewayRow>> {
        Ok(self
            .db
            .list_payment_method_configs_for_company(company_id)
            .await?
            .iter()
            .filter_map(gateway_row)
            .collect())
    }

    async fn serving_row(
        &self,
        company_id: u64,
        method: PaymentMethod,
    ) -> Result<Option<GatewayRow>> {
        Ok(self
            .rows_for_company(company_id)
            .await?
            .into_iter()
            .find(|r| r.enabled && r.config.handles_method(method)))
    }

    pub async fn source(&self, company_id: u64, method: PaymentMethod) -> Result<GatewaySource> {
        let rows = self.rows_for_company(company_id).await?;
        if !rows.is_empty() {
            let serves = rows
                .iter()
                .any(|r| r.enabled && r.config.handles_method(method));
            return Ok(if serves {
                GatewaySource::Row
            } else {
                GatewaySource::None
            });
        }
        Ok(if self.legacy(method).is_some() {
            GatewaySource::Yaml
        } else {
            GatewaySource::None
        })
    }

    pub async fn gateway_for(
        &self,
        company_id: u64,
        method: PaymentMethod,
    ) -> Result<Option<Arc<dyn PaymentGateway>>> {
        let rows = self.rows_for_company(company_id).await?;
        if !rows.is_empty() {
            return Ok(rows
                .iter()
                .find(|r| r.enabled && r.config.handles_method(method))
                .map(|r| (self.factory)(&r.config)));
        }
        Ok(self.legacy(method))
    }

    pub async fn lightning_for(&self, company_id: u64) -> Result<Arc<dyn PaymentGateway>> {
        Ok(self
            .gateway_for(company_id, PaymentMethod::Lightning)
            .await?
            .unwrap_or_else(|| self.in_process_lightning.clone()))
    }

    pub async fn off_session_for(
        &self,
        company_id: u64,
        method: PaymentMethod,
    ) -> Result<OffSessionRenewals> {
        match self.serving_row(company_id, method).await? {
            Some(r) => Ok(off_session_from_row(r.config.off_session_renewals)),
            None if self.rows_for_company(company_id).await?.is_empty() => Ok(self.off_session),
            None => Ok(OffSessionRenewals::Off),
        }
    }

    pub async fn for_method_any_company(
        &self,
        method: PaymentMethod,
    ) -> Result<Option<Arc<dyn PaymentGateway>>> {
        let mut rows: Vec<GatewayRow> = self
            .db
            .list_payment_method_configs()
            .await?
            .iter()
            .filter_map(gateway_row)
            .collect();
        rows.sort_by_key(|r| r.company_id);
        if let Some(r) = rows
            .iter()
            .find(|r| r.enabled && r.config.handles_method(method))
        {
            return Ok(Some((self.factory)(&r.config)));
        }
        if rows.is_empty() {
            return Ok(self.legacy(method));
        }
        Ok(None)
    }

    pub async fn lightning_any_company(&self) -> Result<Arc<dyn PaymentGateway>> {
        Ok(self
            .for_method_any_company(PaymentMethod::Lightning)
            .await?
            .unwrap_or_else(|| self.in_process_lightning.clone()))
    }

    pub async fn in_flight(&self, company_id: u64) -> Result<Option<Arc<dyn PaymentGateway>>> {
        let rows = self.rows_for_company(company_id).await?;
        let row = rows.iter().find(|r| r.enabled).or_else(|| rows.first());
        if let Some(r) = row {
            return Ok(Some((self.factory)(&r.config)));
        }
        Ok(self
            .card
            .clone()
            .or_else(|| self.onchain.clone())
            .or_else(|| self.swap.clone())
            .or_else(|| self.lightning.clone()))
    }

    pub async fn any_gateway(&self) -> Result<Option<Arc<dyn PaymentGateway>>> {
        let mut rows: Vec<GatewayRow> = self
            .db
            .list_payment_method_configs()
            .await?
            .iter()
            .filter_map(gateway_row)
            .collect();
        rows.sort_by_key(|r| (!r.enabled, r.company_id));
        if let Some(r) = rows.first() {
            return Ok(Some((self.factory)(&r.config)));
        }
        Ok(self
            .card
            .clone()
            .or_else(|| self.onchain.clone())
            .or_else(|| self.swap.clone())
            .or_else(|| self.lightning.clone()))
    }

    pub fn has_legacy(&self) -> bool {
        self.lightning.is_some()
            || self.onchain.is_some()
            || self.swap.is_some()
            || self.card.is_some()
    }

    pub fn in_process_lightning(&self) -> Arc<dyn PaymentGateway> {
        self.in_process_lightning.clone()
    }
}
