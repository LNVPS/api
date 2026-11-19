# Currency Handling

The project uses `payments_rs::currency::CurrencyAmount` for all currency conversions.

## Database Storage

- All money amounts are stored as `u64` in **smallest currency units** (cents for fiat, millisats for BTC)
- This includes: cost plan amounts, custom pricing costs (`cpu_cost`, `memory_cost`, `ip4_cost`, `ip6_cost`, disk cost), fees, payment amounts

## Admin API

The admin API accepts and returns amounts as `u64` in smallest currency units.

| Method | Description |
|---|---|
| `CurrencyAmount::from_u64(Currency, u64)` | Construct from smallest units directly |
| `CurrencyAmount::from_f32(Currency, f32)` | Construct from human-readable value |
| `.value()` | Returns `u64` smallest units |
| `.value_f32()` | Returns `f32` human-readable value |

## Currency Decimal Places

| Currency | Decimal places | Note |
|---|---|---|
| EUR, USD, GBP, CAD, CHF, AUD | 2 | 100 cents = 1 unit |
| JPY | 0 | No subdivisions |
| BTC | — | Uses millisats (1000 millisats = 1 satoshi) |
| MEUR, MUSD, MGBP, MCAD, MCHF, MAUD, MJPY | 5 | Milli fiat: 1000 = 1 cent of the base currency |

## Milli Fiat Currencies

`MEUR` and the others are the same money as their base currency (`Currency::base()`), counted in thousandths of a cent so an hourly price can be a fraction of a cent. Use them only as a list price currency: the currency of a pricing model, its subscriptions and their line items.

- Rate lookups go through the base currency, so MEUR converts at the EUR rate. Converting from a milli currency rounds **up** in the target unit.
- Payments, credit balances, top-ups and company `base_currency` are never milli. A card processor refuses a milli amount (`payments_rs::fiat::chargeable_minor_units`); `CurrencyAmount::to_base()` rounds up to the base currency's cent.
- Prefer a milli currency over `rate_scale` for new sub-cent prices.

## Example

```rust
use payments_rs::currency::{Currency, CurrencyAmount};

// Working with smallest units (preferred for API)
let amount = CurrencyAmount::from_u64(Currency::EUR, 1099); // €10.99 = 1099 cents
assert_eq!(amount.value(), 1099);       // 1099 cents
assert_eq!(amount.value_f32(), 10.99); // €10.99

// Converting human-readable to smallest units
let amount = CurrencyAmount::from_f32(Currency::EUR, 10.99); // €10.99
assert_eq!(amount.value(), 1099); // 1099 cents
```
