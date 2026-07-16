use anyhow::{Result, bail};
use isocountry::CountryCode;
use log::trace;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Convert a VAT-territory 2-letter code to an [`isocountry::CountryCode`].
///
/// Greek VAT rates are published under the `EL` code rather than the ISO
/// `GR`; that special case is mapped so Greece is not silently dropped.
pub fn vat_code_to_isocountry(code: &str) -> Option<CountryCode> {
    let alpha2 = match code.to_uppercase().as_str() {
        "EL" => "GR".to_string(),
        other => other.to_string(),
    };
    CountryCode::for_alpha2(&alpha2).ok()
}

/// EU VAT rates API response
#[derive(Debug, Deserialize)]
struct EuVatRatesResponse {
    rates: HashMap<String, EuVatCountryRates>,
}

#[derive(Debug, Deserialize)]
struct EuVatCountryRates {
    standard_rate: f32,
}

/// Outcome of VIES matching a supplied trader detail (name / address parts)
/// against the registered value for a VAT number.
///
/// Not all member states support this "approximate" matching, so a field can be
/// [`TraderMatch::NotProcessed`] even when the VAT number itself is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TraderMatch {
    /// The supplied value matches the registered value.
    Valid,
    /// The supplied value does not match the registered value.
    Invalid,
    /// The member state did not process this field (matching unsupported).
    NotProcessed,
}

/// Trader (business) details supplied for VIES approximate matching.
///
/// Any subset may be provided; empty fields are omitted from the request.
#[derive(Debug, Clone, Default)]
pub struct TraderDetails {
    /// Registered business name.
    pub name: Option<String>,
    /// Street (address line).
    pub street: Option<String>,
    /// Postal / ZIP code.
    pub postal_code: Option<String>,
    /// City.
    pub city: Option<String>,
    /// Company type/legal form (rarely used).
    pub company_type: Option<String>,
}

impl TraderDetails {
    /// True when no trader field is set (nothing to verify).
    pub fn is_empty(&self) -> bool {
        let empty = |s: &Option<String>| s.as_deref().map(str::trim).unwrap_or("").is_empty();
        empty(&self.name)
            && empty(&self.street)
            && empty(&self.postal_code)
            && empty(&self.city)
            && empty(&self.company_type)
    }
}

/// EU VAT number validation response
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EuVatValidationResponse {
    valid: bool,
    user_error: Option<String>,
    name: Option<String>,
    address: Option<String>,
    request_identifier: Option<String>,
    trader_name_match: Option<TraderMatch>,
    trader_street_match: Option<TraderMatch>,
    trader_postal_code_match: Option<TraderMatch>,
    trader_city_match: Option<TraderMatch>,
    trader_company_type_match: Option<TraderMatch>,
}

/// Result of a VAT number validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VatValidationResult {
    /// Whether the VAT number is valid
    pub valid: bool,
    /// Country code extracted from the VAT number
    pub country_code: String,
    /// The VAT number without country prefix
    pub vat_number: String,
    /// Business name (if available)
    pub name: Option<String>,
    /// Business address (if available)
    pub address: Option<String>,
    /// Request identifier
    pub request_identifier: Option<String>,
    /// VIES match result for the supplied trader name, if a name was supplied.
    pub name_match: Option<TraderMatch>,
    /// VIES match result for the supplied street, if a street was supplied.
    pub street_match: Option<TraderMatch>,
    /// VIES match result for the supplied postal code, if one was supplied.
    pub postal_code_match: Option<TraderMatch>,
    /// VIES match result for the supplied city, if a city was supplied.
    pub city_match: Option<TraderMatch>,
    /// VIES match result for the supplied company type, if one was supplied.
    pub company_type_match: Option<TraderMatch>,
}

impl VatValidationResult {
    /// Human-readable labels of the trader fields VIES explicitly reported as
    /// [`TraderMatch::Invalid`]. Fields that were `NOT_PROCESSED` or matched are
    /// omitted, so an empty result means "no confirmed mismatch".
    pub fn mismatched_fields(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        let mut push = |m: &Option<TraderMatch>, label: &'static str| {
            if *m == Some(TraderMatch::Invalid) {
                out.push(label);
            }
        };
        push(&self.name_match, "name");
        push(&self.street_match, "address");
        push(&self.postal_code_match, "postcode");
        push(&self.city_match, "city");
        push(&self.company_type_match, "company type");
        out
    }
}

/// VAT rate for a specific country
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VatRate {
    /// ISO 3166-1 alpha-2 country code
    pub country_code: [u8; 2],
    /// Standard VAT rate as a percentage (e.g., 21.0 for 21%)
    pub rate: f32,
}

impl VatRate {
    /// Create a new VAT rate
    pub fn new(country_code: &str, rate: f32) -> Result<Self> {
        if country_code.len() != 2 {
            bail!("Country code must be 2 characters");
        }
        let bytes = country_code.as_bytes();
        Ok(Self {
            country_code: [bytes[0], bytes[1]],
            rate,
        })
    }

    /// Get the country code as a string
    pub fn country_code_str(&self) -> &str {
        std::str::from_utf8(&self.country_code).unwrap_or("??")
    }

    /// Calculate VAT amount from a net amount (in cents/smallest unit)
    pub fn calculate_vat(&self, net_amount: u64) -> u64 {
        ((net_amount as f64) * (self.rate as f64 / 100.0)).round() as u64
    }

    /// Calculate gross amount from net amount (in cents/smallest unit)
    pub fn gross_from_net(&self, net_amount: u64) -> u64 {
        net_amount + self.calculate_vat(net_amount)
    }

    /// Calculate net amount from gross amount (in cents/smallest unit)
    pub fn net_from_gross(&self, gross_amount: u64) -> u64 {
        ((gross_amount as f64) / (1.0 + self.rate as f64 / 100.0)).round() as u64
    }
}

/// Client for fetching VAT rates and validating VAT numbers.
///
/// Cloneable and cheap to share: clones point at the same internal rate cache
/// (`Arc<RwLock<..>>`), so refreshing rates on one clone is visible to all
/// others. The cache starts empty; call [`refresh_rates`](Self::refresh_rates)
/// (e.g. at startup and periodically) to populate it. Rate lookups
/// ([`rate_for`](Self::rate_for)) are synchronous and never hit the network.
#[derive(Debug, Clone)]
pub struct VatClient {
    /// URL for fetching VAT rates
    rates_url: String,
    /// URL for VAT validation API
    validation_url: String,
    /// Cached standard VAT rates keyed by country, shared across clones.
    cache: Arc<RwLock<HashMap<CountryCode, f32>>>,
}

impl Default for VatClient {
    fn default() -> Self {
        Self::new()
    }
}

impl VatClient {
    /// Create a new client with default API URLs and an empty rate cache.
    pub fn new() -> Self {
        Self {
            rates_url: "https://euvatrates.com/rates.json".to_string(),
            validation_url: "https://ec.europa.eu/taxation_customs/vies/rest-api/check-vat-number"
                .to_string(),
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a client with custom URLs (useful for testing)
    pub fn with_urls(rates_url: impl Into<String>, validation_url: impl Into<String>) -> Self {
        Self {
            rates_url: rates_url.into(),
            validation_url: validation_url.into(),
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a client with a pre-populated rate cache (useful for testing /
    /// offline operation). No network access is performed.
    pub fn with_rates(rates: HashMap<CountryCode, f32>) -> Self {
        let s = Self::new();
        *s.cache.write().expect("vat cache poisoned") = rates;
        s
    }

    /// Replace the cached rate table directly (no network). Useful for tests and
    /// for seeding rates from an alternative source.
    pub fn set_rates(&self, rates: HashMap<CountryCode, f32>) {
        *self.cache.write().expect("vat cache poisoned") = rates;
    }

    /// Fetch the latest rates and replace the cached table. Returns the number
    /// of countries loaded.
    pub async fn refresh_rates(&self) -> Result<usize> {
        let map = self.fetch_rates_map().await?;
        let n = map.len();
        *self.cache.write().expect("vat cache poisoned") = map;
        Ok(n)
    }

    /// Look up the cached standard VAT rate (%) for a country, if known.
    pub fn rate_for(&self, country: CountryCode) -> Option<f32> {
        self.cache
            .read()
            .expect("vat cache poisoned")
            .get(&country)
            .copied()
    }

    /// Fetch all EU VAT rates
    pub async fn fetch_rates(&self) -> Result<Vec<VatRate>> {
        trace!("Fetching VAT rates from: {}", self.rates_url);

        let response = reqwest::get(&self.rates_url).await?.text().await?;
        let vat_response: EuVatRatesResponse = serde_json::from_str(&response)?;

        let rates: Vec<VatRate> = vat_response
            .rates
            .into_iter()
            .filter_map(|(country_code, rates)| {
                VatRate::new(&country_code, rates.standard_rate).ok()
            })
            .collect();

        trace!("Fetched {} VAT rates", rates.len());
        Ok(rates)
    }

    /// Fetch all EU standard VAT rates as a map keyed by [`CountryCode`].
    ///
    /// Codes that don't resolve to a known country are skipped. Intended for
    /// building the pricing engine's rate table at startup.
    pub async fn fetch_rates_map(&self) -> Result<HashMap<CountryCode, f32>> {
        let rates = self.fetch_rates().await?;
        Ok(rates
            .into_iter()
            .filter_map(|r| vat_code_to_isocountry(r.country_code_str()).map(|cc| (cc, r.rate)))
            .collect())
    }

    /// Fetch VAT rate for a specific country
    pub async fn fetch_rate(&self, country_code: &str) -> Result<VatRate> {
        let rates = self.fetch_rates().await?;
        let country_upper = country_code.to_uppercase();

        rates
            .into_iter()
            .find(|r| r.country_code_str() == country_upper)
            .ok_or_else(|| anyhow::anyhow!("VAT rate not found for country: {}", country_code))
    }

    /// Validate a VAT number
    ///
    /// The VAT number can be provided with or without the country prefix.
    /// If no country prefix is provided, the `country_code` parameter must be set.
    ///
    /// # Examples
    /// ```ignore
    /// let client = VatClient::new();
    /// // With country prefix
    /// let result = client.validate_vat_number("DE123456789", None).await?;
    /// // Without country prefix
    /// let result = client.validate_vat_number("123456789", Some("DE")).await?;
    /// ```
    pub async fn validate_vat_number(
        &self,
        vat_number: &str,
        country_code: Option<&str>,
    ) -> Result<VatValidationResult> {
        self.validate_vat_number_with_trader(vat_number, country_code, None)
            .await
    }

    /// Validate a VAT number and, when `trader` details are supplied, ask VIES to
    /// match the business name/address against the registered values.
    ///
    /// The returned [`VatValidationResult`] carries per-field match indicators
    /// (`name_match`, `street_match`, ...). Note that many member states do not
    /// support approximate matching and will report `NOT_PROCESSED`.
    pub async fn validate_vat_number_with_trader(
        &self,
        vat_number: &str,
        country_code: Option<&str>,
        trader: Option<&TraderDetails>,
    ) -> Result<VatValidationResult> {
        let cleaned = vat_number.replace([' ', '.', '-'], "");

        let (country, number) = if let Some(cc) = country_code {
            (cc.to_uppercase(), cleaned)
        } else {
            // Extract country code from VAT number (first 2 characters).
            // Operate on chars, not bytes: byte-slicing user-supplied input like
            // "€12345" (where byte offset 2 is not a char boundary) would panic.
            let mut chars = cleaned.chars();
            let c0 = chars.next();
            let c1 = chars.next();
            let (c0, c1) = match (c0, c1) {
                (Some(a), Some(b)) if chars.next().is_some() => (a, b),
                _ => bail!("VAT number too short"),
            };
            if !c0.is_ascii_alphabetic() || !c1.is_ascii_alphabetic() {
                bail!(
                    "VAT number must start with 2-letter country code or country_code must be provided"
                );
            }
            let country = format!("{}{}", c0, c1).to_uppercase();
            let number: String = cleaned.chars().skip(2).collect();
            (country, number)
        };

        trace!("Validating VAT number: {} for country: {}", number, country);

        let mut body = serde_json::json!({
            "countryCode": country,
            "vatNumber": number
        });
        // Attach trader details for approximate matching when provided.
        if let Some(t) = trader.filter(|t| !t.is_empty()) {
            let obj = body.as_object_mut().expect("json object");
            let mut add = |key: &str, val: &Option<String>| {
                if let Some(v) = val.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    obj.insert(key.to_string(), serde_json::Value::String(v.to_string()));
                }
            };
            add("traderName", &t.name);
            add("traderStreet", &t.street);
            add("traderPostalCode", &t.postal_code);
            add("traderCity", &t.city);
            add("traderCompanyType", &t.company_type);
        }

        let client = reqwest::Client::new();
        let response = client
            .post(&self.validation_url)
            .json(&body)
            .send()
            .await?
            .text()
            .await?;

        let vat_response: EuVatValidationResponse = serde_json::from_str(&response)?;

        if let Some(error) = vat_response.user_error {
            bail!("VAT validation error: {}", error);
        }

        Ok(VatValidationResult {
            valid: vat_response.valid,
            country_code: country,
            vat_number: number,
            name: vat_response.name.filter(|s| !s.is_empty() && s != "---"),
            address: vat_response.address.filter(|s| !s.is_empty() && s != "---"),
            request_identifier: vat_response.request_identifier,
            name_match: vat_response.trader_name_match,
            street_match: vat_response.trader_street_match,
            postal_code_match: vat_response.trader_postal_code_match,
            city_match: vat_response.trader_city_match,
            company_type_match: vat_response.trader_company_type_match,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vat_code_to_isocountry() {
        assert_eq!(vat_code_to_isocountry("DE"), Some(CountryCode::DEU));
        assert_eq!(vat_code_to_isocountry("ie"), Some(CountryCode::IRL));
        // Greek VAT code EL must map to Greece.
        assert_eq!(vat_code_to_isocountry("EL"), Some(CountryCode::GRC));
        assert_eq!(vat_code_to_isocountry("GR"), Some(CountryCode::GRC));
        assert_eq!(vat_code_to_isocountry("ZZ"), None);
    }

    #[test]
    fn test_vat_rate_new() {
        let rate = VatRate::new("DE", 19.0).unwrap();
        assert_eq!(rate.country_code_str(), "DE");
        assert_eq!(rate.rate, 19.0);
    }

    #[test]
    fn test_vat_rate_invalid_country() {
        assert!(VatRate::new("DEU", 19.0).is_err());
        assert!(VatRate::new("D", 19.0).is_err());
    }

    #[test]
    fn test_calculate_vat() {
        let rate = VatRate::new("DE", 19.0).unwrap();
        // 1000 cents at 19% = 190 cents VAT
        assert_eq!(rate.calculate_vat(1000), 190);
    }

    #[test]
    fn test_gross_from_net() {
        let rate = VatRate::new("DE", 19.0).unwrap();
        // 1000 cents net + 190 cents VAT = 1190 cents gross
        assert_eq!(rate.gross_from_net(1000), 1190);
    }

    #[test]
    fn test_net_from_gross() {
        let rate = VatRate::new("DE", 19.0).unwrap();
        // 1190 cents gross / 1.19 = 1000 cents net
        assert_eq!(rate.net_from_gross(1190), 1000);
    }

    #[test]
    fn test_vat_calculation_roundtrip() {
        let rate = VatRate::new("NL", 21.0).unwrap();
        let net = 10000u64; // 100.00 EUR
        let gross = rate.gross_from_net(net);
        let net_back = rate.net_from_gross(gross);
        assert_eq!(net, net_back);
    }

    #[test]
    fn test_parse_vat_number_with_prefix() {
        // Test that VAT numbers with country prefix are parsed correctly
        let vat = "DE123456789";
        let cleaned = vat.replace([' ', '.', '-'], "");
        let cc = &cleaned[..2];
        let number = &cleaned[2..];
        assert_eq!(cc, "DE");
        assert_eq!(number, "123456789");
    }

    #[test]
    fn test_parse_vat_number_with_spaces() {
        let vat = "DE 123 456 789";
        let cleaned = vat.replace([' ', '.', '-'], "");
        assert_eq!(cleaned, "DE123456789");
    }

    #[test]
    fn test_parse_vat_number_with_dots() {
        let vat = "NL123.456.789.B01";
        let cleaned = vat.replace([' ', '.', '-'], "");
        assert_eq!(cleaned, "NL123456789B01");
    }

    #[tokio::test]
    async fn test_fetch_vat_rates() {
        let client = VatClient::new();
        let rates = client.fetch_rates().await.unwrap();

        // Should have rates for EU member states
        assert!(!rates.is_empty(), "Should fetch at least some VAT rates");
    }

    #[tokio::test]
    async fn test_validate_vat_number() {
        let client = VatClient::new();

        // Test with an invalid VAT number - should return valid=false
        let result = client
            .validate_vat_number("DE123456789", None)
            .await
            .unwrap();
        assert!(!result.valid, "Random VAT number should be invalid");
        assert_eq!(result.country_code, "DE");
        assert_eq!(result.vat_number, "123456789");
    }

    /// Regression: a VAT number starting with a multi-byte character (byte
    /// offset 2 not on a char boundary) must return an error, not panic on
    /// `&cleaned[..2]`. Parsing fails before any network call is made.
    #[tokio::test]
    async fn test_validate_vat_number_multibyte_does_not_panic() {
        let client = VatClient::new();
        let result = client.validate_vat_number("€12345", None).await;
        assert!(
            result.is_err(),
            "multi-byte VAT number should error, not panic"
        );
    }

    /// A single-character (too short) input must also error cleanly.
    #[tokio::test]
    async fn test_validate_vat_number_too_short() {
        let client = VatClient::new();
        assert!(client.validate_vat_number("D", None).await.is_err());
    }

    #[test]
    fn test_trader_details_is_empty() {
        assert!(TraderDetails::default().is_empty());
        assert!(
            TraderDetails {
                name: Some("   ".to_string()),
                ..Default::default()
            }
            .is_empty()
        );
        assert!(
            !TraderDetails {
                name: Some("ACME".to_string()),
                ..Default::default()
            }
            .is_empty()
        );
    }

    #[test]
    fn test_trader_match_deserialization() {
        assert_eq!(
            serde_json::from_str::<TraderMatch>("\"VALID\"").unwrap(),
            TraderMatch::Valid
        );
        assert_eq!(
            serde_json::from_str::<TraderMatch>("\"INVALID\"").unwrap(),
            TraderMatch::Invalid
        );
        assert_eq!(
            serde_json::from_str::<TraderMatch>("\"NOT_PROCESSED\"").unwrap(),
            TraderMatch::NotProcessed
        );
    }

    #[test]
    fn test_mismatched_fields() {
        let result = VatValidationResult {
            valid: true,
            country_code: "DE".to_string(),
            vat_number: "123".to_string(),
            name: None,
            address: None,
            request_identifier: None,
            name_match: Some(TraderMatch::Invalid),
            street_match: Some(TraderMatch::Valid),
            postal_code_match: Some(TraderMatch::NotProcessed),
            city_match: Some(TraderMatch::Invalid),
            company_type_match: None,
        };
        assert_eq!(result.mismatched_fields(), vec!["name", "city"]);
    }
}
