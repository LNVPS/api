use anyhow::{Result, bail};
use log::trace;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// EU VAT rates API response
#[derive(Debug, Deserialize)]
struct EuVatRatesResponse {
    rates: HashMap<String, EuVatCountryRates>,
}

#[derive(Debug, Deserialize)]
struct EuVatCountryRates {
    standard_rate: f32,
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

/// Client for fetching EU VAT rates and validating VAT numbers
#[derive(Debug, Clone, Default)]
pub struct EuVatClient {
    /// URL for fetching VAT rates
    rates_url: String,
    /// URL for VAT validation API
    validation_url: String,
}

impl EuVatClient {
    /// Create a new client with default API URLs
    pub fn new() -> Self {
        Self {
            rates_url: "https://euvatrates.com/rates.json".to_string(),
            validation_url: "https://ec.europa.eu/taxation_customs/vies/rest-api/check-vat-number"
                .to_string(),
        }
    }

    /// Create a client with custom URLs (useful for testing)
    pub fn with_urls(rates_url: impl Into<String>, validation_url: impl Into<String>) -> Self {
        Self {
            rates_url: rates_url.into(),
            validation_url: validation_url.into(),
        }
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
    /// let client = EuVatClient::new();
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
        let cleaned = vat_number.replace([' ', '.', '-'], "");

        let (country, number) = if let Some(cc) = country_code {
            (cc.to_uppercase(), cleaned)
        } else {
            // Extract country code from VAT number (first 2 characters)
            if cleaned.len() < 3 {
                bail!("VAT number too short");
            }
            let cc = &cleaned[..2];
            if !cc.chars().all(|c| c.is_ascii_alphabetic()) {
                bail!(
                    "VAT number must start with 2-letter country code or country_code must be provided"
                );
            }
            (cc.to_uppercase(), cleaned[2..].to_string())
        };

        trace!("Validating VAT number: {} for country: {}", number, country);

        let client = reqwest::Client::new();
        let response = client
            .post(&self.validation_url)
            .json(&serde_json::json!({
                "countryCode": country,
                "vatNumber": number
            }))
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
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let client = EuVatClient::new();
        let rates = client.fetch_rates().await.unwrap();

        // Should have rates for EU member states
        assert!(!rates.is_empty(), "Should fetch at least some VAT rates");
    }

    #[tokio::test]
    async fn test_validate_vat_number() {
        let client = EuVatClient::new();

        // Test with an invalid VAT number - should return valid=false
        let result = client
            .validate_vat_number("DE123456789", None)
            .await
            .unwrap();
        assert!(!result.valid, "Random VAT number should be invalid");
        assert_eq!(result.country_code, "DE");
        assert_eq!(result.vat_number, "123456789");
    }
}
