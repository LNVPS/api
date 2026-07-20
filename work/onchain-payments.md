# On-chain Bitcoin Payments (issue #109)

**Status:** in-progress
**Started:** 2026-07-20
**Last updated:** 2026-07-20

**Design decisions (from review):**
- No new provider config struct — `ProviderConfig::OnChain(LndConfig)` reuses `LndConfig`.
- On-chain provider is **required**, injected into `SubscriptionHandler::new` as
  `Arc<dyn OnChainProvider>` exactly like `node: Arc<dyn LightningNode>`; built via
  `Settings::get_onchain()` which mirrors `get_node()` (LND arm gated by the existing
  `onchain` cargo feature, other backends bail). No Option, no type alias.
- `payments-rs` stays a plain workspace dep (`0.4.1` from crates.io); the trait is
  available through the default `onchain` feature, same as `lightning` via `lnd`.

## Goal

Support on-chain Bitcoin payments. A customer requesting an on-chain payment gets
a freshly derived receive address; a background watcher streams chain updates and
records each confirmed deposit as a `subscription_payment` row. Because on-chain
funds can arrive at any time (including after expiry), late payments are pro-rated
and new `subscription_payment` entries are inserted automatically.

Backend: `payments-rs` `OnChainProvider` (LND on-chain, `method-lnd-onchain`
feature), now available on crates.io as `payments-rs = 0.4.1`.

## Findings

### payments-rs API (crates.io 0.4.1, module `payments_rs::onchain`)
- `OnChainProvider` trait:
  - `new_address(NewAddressRequest) -> NewAddressResponse` — derive receive address.
    `NewAddressRequest { amount: CurrencyAmount, memo, label }`,
    `NewAddressResponse { address, label }`.
  - `subscribe_payments(from: Option<PaymentCursor>) -> Stream<ChainPaymentUpdate>`
    — resumable, at-least-once. **De-dupe on `txid`** for exactly-once accounting.
- `LndOnChainProvider::new(url, tls_cert, macaroon, LndOnChainConfig { address_type,
  account, min_confirmations })`.
- `ChainPaymentUpdate::{Detected, Confirmed, Error}`; each payment variant carries
  `address`, `txid`, `amount_msat` (real amount received), `confirmations`, `label`
  (LND leaves `label` = None → correlate by `address`).
- Amounts in **millisats**; `sats_to_msat` / `msat_to_sats` helpers.
- `PaymentCursor { block_height, block_hash }` — persist to resume without missing/
  double-counting deposits across restarts.
- Feature flags to enable in `lnvps_api/Cargo.toml`: `method-lnd-onchain`.

### Existing LNVPS structures to extend
- `lnvps_db::PaymentMethod` enum (`model.rs:1471`) — add `OnChain`. Update `Display`
  (1487) and `FromStr` (1498) arms.
- `lnvps_db::ProviderConfig` enum (`model.rs:2503`) — add `OnChain(LndOnChainConfig)`
  variant + a new config struct near `LndConfig` (2443). Serde-tagged like siblings.
- `SubscriptionPayment` (`model.rs:2023`): `external_id: Option<String>` (unique) =
  **txid**; `external_data: EncryptedString` = **bitcoin address**. `SubscriptionPaymentType`
  needs an on-chain-relevant handling; reuse existing types.
- Payment factory `lnvps_api/src/payment_factory.rs` — currently splits Lightning
  node vs fiat service. Add `create_onchain_provider(&config) -> Arc<dyn OnChainProvider>`
  and a `get_onchain_provider_for_company`.
- Listener wiring `lnvps_api/src/payments/mod.rs::listen_all_payments` — add an
  on-chain handler task loop (like Revolut/Stripe), gated behind an `onchain` feature.
- New module `lnvps_api/src/payments/onchain.rs` — the watcher: subscribe, de-dupe
  txids, resolve address→(subscription/order), insert `subscription_payment`,
  pro-rate late payments, persist `PaymentCursor`.
- Pricing/quote surface `lnvps_api_common/src/pricing.rs` — on-chain amount is BTC
  like Lightning; expose as a payable method.
- Migration under `lnvps_db/migrations/` — persist cursor + any address→order table,
  and confirm `subscription_payment.external_id` uniqueness/index.

### Amount / currency
- On-chain BTC amounts are millisats — align with `CurrencyAmount::millisats` and the
  existing BTC handling in `docs/agents/currency.md`.

## Tasks

- [x] Switch `payments-rs` from the git rev to the published crates.io `0.4.1`
      (`Cargo.toml`, `cargo update`, verified payment crates compile).

### Increment 1 — DB layer (S/M)
- [x] Add `PaymentMethod::OnChain` (+ `Display`/`FromStr`) in `lnvps_db/src/model.rs`.
- [x] `ProviderConfig::OnChain(LndConfig)` variant (reuses `LndConfig`) + `as_onchain()`.
- [x] Migration `20260720172401_onchain_payments.sql`: unique index on
      `subscription_payment.external_id` (txid de-dupe). No cursor persistence
      needed — watcher resubscribes from genesis and de-dupes by txid.
- [x] Unit tests for enum round-trips (Display/FromStr/serde) + `as_onchain`.
- [x] New DB method `list_subscription_payments_by_method` (trait + mysql + mock);
      mock `update_subscription_payment` fixed to mirror all MySQL columns.

### Increment 2 — provider wiring (S)
- [x] `onchain` feature flag in `lnvps_api/Cargo.toml` (`payments-rs/method-lnd-onchain`,
      in defaults).
- [x] `Settings::get_onchain()` mirroring `get_node()`; required provider injected into
      `SubscriptionHandler::new` after `node` (all call sites updated).
- [x] `MockOnChainProvider` in `lnvps_api/src/mocks.rs` (mirrors `MockNode`; scripted
      updates via `updates`, records derived `addresses`).

### Increment 3 — address derivation / create-payment flow (M)
- [x] `SubscriptionHandler::new_onchain_address` helper (`new_address` on provider).
- [x] `PaymentMethod::OnChain` arms in both payment-creation matches
      (`subscription/mod.rs`): BTC-only, 3600s expiry, address in `external_data`,
      `external_id = None` until the watcher sees the txid.
- [x] API surface: `ApiPaymentData::OnChain { address }`, `ApiPaymentMethod::OnChain`,
      BTC default currency (`routes.rs`); admin `AdminPaymentMethod(Type)::OnChain` +
      `SanitizedProviderConfig::OnChain`.
- [x] Test `renew_subscription_onchain_derives_address` (payment-creation arm).
- [x] `get_amount_and_rate` in `pricing.rs` treats OnChain like Lightning (BTC
      conversion); processing fee is config-driven (0 without config).

### Increment 4 — chain watcher + pro-rating (M/L)
- [x] `lnvps_api/src/payments/onchain.rs`: `OnChainPaymentHandler` — subscribe loop,
      txid de-dupe, address→payment correlation (decrypt in memory), settle on
      `Confirmed`, pro-rate partial/late/over-payments, insert new pro-rated renewal
      on address reuse.
- [x] Registered in `listen_all_payments` (provider passed from `bin/api.rs`).
- [x] 8 watcher tests: exact/partial deposits, replay de-dupe, unknown address,
      address-reuse renewal, listen loop, stream error.
- [x] Rate is **re-calculated at tx discovery** (review feedback): time credited =
      `time_value × received_msat × rate_now / (expected_msat × rate_quoted)`;
      the quote only fixes the price in the subscription currency, never the BTC
      rate. Current rate is recorded on the settled payment. BTC-denominated subs
      reduce to the plain msat ratio. `PricingEngine::get_ticker` made pub.

### Increment 5 — API surface + docs (S)
- [x] `ApiPaymentMethod::OnChain` / `ApiPaymentData::OnChain { address }` exposed.
- [x] `API_CHANGELOG.md` updated (Unreleased).
- [ ] Label issue #109 and prep PR referencing `Fixes #109`.

## Notes

- Decisions: store **txid in `external_id`** (unique) and **address in `external_data`**
  (encrypted), per issue #109.
- LND cannot label on-chain outputs, so the watcher must correlate by **address**, not
  `label`.
- De-dup on `txid` — the stream is at-least-once and replays across restarts.
- Load `docs/agents/migrations.md`, `docs/agents/currency.md`,
  `docs/agents/api-guidelines.md`, `docs/agents/code-style.md`, and coverage docs when
  implementing each increment.
