//! The typed decision a discount rule returns, and the Rust-side clamping that
//! makes an arbitrary rule safe to run against real money.
//!
//! A rule returns a CEL map such as `{percent: 10}` or
//! `{amount: 500, currency: 'EUR'}`. Whatever it returns is converted here into
//! a [`DiscountDecision`] and then clamped: percent is bounded to `0..=100`, a
//! fixed amount cannot be negative, and the resolved discount can never exceed
//! the order total. A badly written (or maliciously written) rule therefore
//! cannot over-discount an order.

use anyhow::{Result, bail};
use cel::Value;
use cel::objects::{Key, Map};
use serde::{Deserialize, Serialize};

/// A rule's effect on the order being priced.
///
/// An empty decision (all fields `None`) means "this discount does not apply",
/// which is what `{}`, `null` and a `false` result all deserialize to.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DiscountDecision {
    /// Percentage off the net order amount, already clamped to `0..=100`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percent: Option<u8>,
    /// Fixed amount off, in minor units of [`Self::currency`]. Never negative.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
    /// ISO currency code of [`Self::amount`]. Required whenever `amount` is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
}

impl DiscountDecision {
    /// A decision that applies no discount.
    pub fn none() -> Self {
        Self::default()
    }

    /// True when the rule declined to discount this order.
    pub fn is_empty(&self) -> bool {
        self.percent.unwrap_or(0) == 0 && self.amount.unwrap_or(0) == 0
    }

    /// Convert a CEL result into a decision, clamping every field.
    ///
    /// Accepted results:
    /// - `Map` — the documented form, keys `percent`, `amount`, `currency`.
    /// - `Null` / `Bool(false)` / empty map — no discount.
    ///
    /// Anything else is an error: silently treating e.g. a bare `10` as
    /// "10 percent" would make a typo change what customers are charged.
    pub fn from_cel_value(value: &Value) -> Result<Self> {
        match value {
            Value::Null => Ok(Self::none()),
            Value::Bool(false) => Ok(Self::none()),
            Value::Map(map) => Self::from_cel_map(map),
            other => bail!(
                "discount rule must return a map or null, got {}",
                type_name(other)
            ),
        }
    }

    fn from_cel_map(map: &Map) -> Result<Self> {
        let percent = match lookup(map, "percent") {
            Some(v) => Some(clamp_percent(as_int("percent", v)?)),
            None => None,
        };

        let amount = match lookup(map, "amount") {
            Some(v) => {
                let raw = as_int("amount", v)?;
                // A negative fixed amount would be a surcharge, not a discount.
                Some(raw.max(0) as u64)
            }
            None => None,
        };

        let currency = match lookup(map, "currency") {
            Some(Value::String(s)) => Some(s.to_uppercase()),
            Some(other) => bail!(
                "discount rule field 'currency' must be a string, got {}",
                type_name(other)
            ),
            None => None,
        };

        if amount.is_some_and(|a| a > 0) && currency.is_none() {
            bail!("discount rule returned 'amount' without 'currency'");
        }

        Ok(Self {
            percent,
            amount,
            currency,
        })
    }

    /// Resolve this decision into an amount off, in minor units of the order
    /// currency, clamped to `order_amount`.
    ///
    /// The percentage is applied to the order amount first, then any fixed
    /// amount is subtracted on top; the total is capped at the order amount so
    /// a discount can never produce a negative price. Percentage rounding is
    /// floor, i.e. rounding is never in the customer's favour by a partial
    /// minor unit.
    ///
    /// Fails when a fixed amount is denominated in a currency other than the
    /// order's — currency conversion belongs to the pricing engine, which owns
    /// the exchange-rate service, not to this pure function.
    pub fn amount_off(&self, order_amount: u64, order_currency: &str) -> Result<u64> {
        let pct = self.percent.unwrap_or(0) as u128;
        let percent_off = (order_amount as u128 * pct / 100) as u64;

        let fixed_off = match (self.amount, self.currency.as_deref()) {
            (Some(a), Some(c)) if a > 0 => {
                if !c.eq_ignore_ascii_case(order_currency) {
                    bail!(
                        "discount amount currency {} does not match order currency {}",
                        c,
                        order_currency
                    );
                }
                a
            }
            _ => 0,
        };

        Ok(percent_off.saturating_add(fixed_off).min(order_amount))
    }
}

/// Clamp a rule-supplied percentage into `0..=100`.
fn clamp_percent(raw: i64) -> u8 {
    raw.clamp(0, 100) as u8
}

/// Read a key from a CEL map, treating a null value as absent.
fn lookup<'a>(map: &'a Map, key: &str) -> Option<&'a Value> {
    match map.map.get(&Key::String(key.to_string().into())) {
        Some(Value::Null) | None => None,
        Some(v) => Some(v),
    }
}

/// Coerce a CEL numeric value into `i64`, rejecting floats.
///
/// Floats are rejected rather than rounded: money is exact in minor units, and
/// accepting `0.1` here would reintroduce the `f64` hazard the engine avoids.
fn as_int(field: &str, value: &Value) -> Result<i64> {
    match value {
        Value::Int(i) => Ok(*i),
        Value::UInt(u) => Ok((*u).min(i64::MAX as u64) as i64),
        other => bail!(
            "discount rule field '{}' must be an integer, got {}",
            field,
            type_name(other)
        ),
    }
}

/// Human-readable CEL type name, for error messages.
fn type_name(value: &Value) -> &'static str {
    match value {
        Value::List(_) => "list",
        Value::Map(_) => "map",
        Value::Function(_, _) => "function",
        Value::Int(_) => "int",
        Value::UInt(_) => "uint",
        Value::Float(_) => "float",
        Value::String(_) => "string",
        Value::Bytes(_) => "bytes",
        Value::Bool(_) => "bool",
        Value::Null => "null",
        _ => "unsupported",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn map(entries: &[(&str, Value)]) -> Value {
        let m: HashMap<Key, Value> = entries
            .iter()
            .map(|(k, v)| (Key::String(Arc::new(k.to_string())), v.clone()))
            .collect();
        Value::Map(Map { map: Arc::new(m) })
    }

    fn decision(entries: &[(&str, Value)]) -> Result<DiscountDecision> {
        DiscountDecision::from_cel_value(&map(entries))
    }

    #[test]
    fn empty_results_mean_no_discount() {
        assert_eq!(
            DiscountDecision::from_cel_value(&Value::Null).unwrap(),
            DiscountDecision::none()
        );
        assert_eq!(
            DiscountDecision::from_cel_value(&Value::Bool(false)).unwrap(),
            DiscountDecision::none()
        );
        assert_eq!(decision(&[]).unwrap(), DiscountDecision::none());
        assert!(DiscountDecision::none().is_empty());
    }

    #[test]
    fn rejects_non_map_results() {
        for v in [
            Value::Int(10),
            Value::Bool(true),
            Value::String(Arc::new("10%".to_string())),
            Value::Float(1.5),
            Value::List(Arc::new(vec![Value::Int(1)])),
            Value::Bytes(Arc::new(vec![1])),
        ] {
            assert!(
                DiscountDecision::from_cel_value(&v).is_err(),
                "expected {v:?} to be rejected"
            );
        }
    }

    #[test]
    fn percent_is_clamped_to_0_100() {
        assert_eq!(
            decision(&[("percent", Value::Int(10))]).unwrap().percent,
            Some(10)
        );
        assert_eq!(
            decision(&[("percent", Value::Int(500))]).unwrap().percent,
            Some(100)
        );
        assert_eq!(
            decision(&[("percent", Value::Int(-5))]).unwrap().percent,
            Some(0)
        );
        assert_eq!(
            decision(&[("percent", Value::UInt(u64::MAX))])
                .unwrap()
                .percent,
            Some(100)
        );
    }

    #[test]
    fn negative_amount_becomes_zero() {
        let d = decision(&[
            ("amount", Value::Int(-500)),
            ("currency", Value::String(Arc::new("eur".to_string()))),
        ])
        .unwrap();
        assert_eq!(d.amount, Some(0));
        assert_eq!(d.currency.as_deref(), Some("EUR"));
        assert!(d.is_empty());
    }

    #[test]
    fn amount_requires_currency() {
        assert!(decision(&[("amount", Value::Int(500))]).is_err());
        // ...but a zero amount is just "no discount", not an error.
        assert!(decision(&[("amount", Value::Int(0))]).unwrap().is_empty());
    }

    #[test]
    fn rejects_wrong_field_types() {
        assert!(decision(&[("percent", Value::Float(10.5))]).is_err());
        assert!(decision(&[("amount", Value::Float(10.5))]).is_err());
        assert!(decision(&[("currency", Value::Int(1))]).is_err());
    }

    #[test]
    fn null_fields_are_absent() {
        let d = decision(&[("percent", Value::Null), ("amount", Value::Null)]).unwrap();
        assert_eq!(d, DiscountDecision::none());
    }

    #[test]
    fn amount_off_applies_percent_then_fixed_and_clamps() {
        let pct = decision(&[("percent", Value::Int(10))]).unwrap();
        assert_eq!(pct.amount_off(10_000, "EUR").unwrap(), 1_000);
        // floor rounding, never in the customer's favour
        assert_eq!(pct.amount_off(999, "EUR").unwrap(), 99);

        let both = decision(&[
            ("percent", Value::Int(10)),
            ("amount", Value::Int(500)),
            ("currency", Value::String(Arc::new("EUR".to_string()))),
        ])
        .unwrap();
        assert_eq!(both.amount_off(10_000, "EUR").unwrap(), 1_500);

        // clamped to the order total
        let huge = decision(&[
            ("percent", Value::Int(100)),
            ("amount", Value::Int(999_999)),
            ("currency", Value::String(Arc::new("EUR".to_string()))),
        ])
        .unwrap();
        assert_eq!(huge.amount_off(10_000, "EUR").unwrap(), 10_000);

        // no overflow on absurd order amounts
        assert_eq!(pct.amount_off(u64::MAX, "EUR").unwrap(), u64::MAX / 10);

        assert_eq!(
            DiscountDecision::none().amount_off(10_000, "EUR").unwrap(),
            0
        );
    }

    #[test]
    fn amount_off_rejects_currency_mismatch() {
        let d = decision(&[
            ("amount", Value::Int(500)),
            ("currency", Value::String(Arc::new("USD".to_string()))),
        ])
        .unwrap();
        assert!(d.amount_off(10_000, "EUR").is_err());
        // case-insensitive match is accepted
        assert_eq!(d.amount_off(10_000, "usd").unwrap(), 500);
    }

    #[test]
    fn serializes_only_set_fields() {
        let d = decision(&[("percent", Value::Int(10))]).unwrap();
        assert_eq!(serde_json::to_string(&d).unwrap(), r#"{"percent":10}"#);
    }

    #[test]
    fn type_name_covers_value_variants() {
        assert_eq!(type_name(&Value::Null), "null");
        assert_eq!(type_name(&Value::Int(1)), "int");
        assert_eq!(type_name(&Value::UInt(1)), "uint");
        assert_eq!(type_name(&Value::Float(1.0)), "float");
        assert_eq!(type_name(&Value::Bool(true)), "bool");
        assert_eq!(type_name(&Value::String(Arc::new(String::new()))), "string");
        assert_eq!(type_name(&Value::Bytes(Arc::new(vec![]))), "bytes");
        assert_eq!(type_name(&Value::List(Arc::new(vec![]))), "list");
        assert_eq!(type_name(&map(&[])), "map");
        assert_eq!(
            type_name(&Value::Function(Arc::new("f".to_string()), None)),
            "function"
        );
    }
}
