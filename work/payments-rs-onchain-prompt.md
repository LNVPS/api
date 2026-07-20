# Prompt: Add on-chain Bitcoin payment support to `payments-rs`

You are working in the **`payments-rs`** crate (https://github.com/v0l/payments-rs), a Rust
library that abstracts multiple payment providers behind trait objects. It is consumed by
`lnvps-api`, which needs on-chain Bitcoin receive support to satisfy
[LNVPS/api#109](https://github.com/LNVPS/api/issues/109).

## Goal

Add a new **on-chain Bitcoin** payment method to `payments-rs`, following the exact structural
and stylistic conventions already used for the Lightning and fiat providers. The consumer only
needs to **receive** payments: derive a fresh receive address per order, and be notified when
funds arrive (including confirmations and the txid).

## Study the existing patterns first

Mirror these — do not invent a new project layout:

- `src/lightning/mod.rs` — defines the `LightningNode` trait plus shared request/response structs
  (`AddInvoiceRequest`, `AddInvoiceResponse`, `InvoiceUpdate` enum with `Created`/`Settled`/…),
  gated provider modules (`#[cfg(feature = "method-lnd")] mod lnd;`), and a `subscribe_invoices`
  method returning `Pin<Box<dyn Stream<Item = InvoiceUpdate> + Send>>`.
- `src/fiat/mod.rs` — `FiatPaymentService` trait, `LineItem`, boxed-future method signatures.
- `src/currency.rs` — `Currency` (already has a `BTC` variant stored as **milli-satoshis**) and
  `CurrencyAmount`. Reuse these; do **not** add a new money type.
- `src/lib.rs` — module gating via feature flags; add `#[cfg(feature = "onchain")] pub mod onchain;`.
- `Cargo.toml` — feature-flag layout (`method-lnd`, `method-bitvora`, …). Add analogous flags.

## Deliverables

### 1. New module `src/onchain/`

Create `src/onchain/mod.rs` defining a provider-agnostic trait, plus at least one concrete backend
module gated behind a feature flag (see below). Suggested trait shape (adapt names to match
existing conventions, e.g. async_trait usage like `LightningNode`):

```rust
#[async_trait]
pub trait OnChainProvider: Send + Sync {
    /// Derive/allocate a fresh receive address for a new order.
    /// `external_id` is the caller's order reference (stored so incoming
    /// txs can be correlated back). Returns the address + any provider id.
    async fn new_address(&self, req: NewAddressRequest) -> Result<NewAddressResponse>;

    /// Stream chain events (payment detected / confirmed) for watched
    /// addresses, resumable from a cursor (block height or provider marker).
    async fn subscribe_payments(
        &self,
        from: Option<PaymentCursor>,
    ) -> Result<Pin<Box<dyn Stream<Item = ChainPaymentUpdate> + Send>>>;
}
```

Shared types to define in `mod.rs` (model them on `AddInvoiceRequest`/`InvoiceUpdate`):

- `NewAddressRequest { amount: CurrencyAmount, memo: Option<String>, external_id: Option<String> }`
- `NewAddressResponse { address: String, external_id: Option<String> }`
- `ChainPaymentUpdate` enum, e.g.:
  - `Detected { address, txid, amount_msat: u64, confirmations: u32, external_id: Option<String> }`
  - `Confirmed { address, txid, amount_msat: u64, confirmations: u32, external_id: Option<String> }`
  - `Error(String)`

Design notes to honour the consuming issue (#109):
- Amounts must round-trip cleanly to **milli-satoshis** so callers can compare against
  `CurrencyAmount::millisats(..)`. Convert on-chain sats → msat at the boundary.
- The **txid** must be surfaced on every update (the consumer stores it as a unique `external_id`).
- Partial / late / over-payments must still be reported — do **not** filter by "exact amount"
  inside the library; report the actual `amount_msat` received and let the caller pro-rate.
- `subscribe_payments` must be **resumable** (a cursor param) so a restarted consumer does not miss
  or double-count deposits. Prefer block-height + txid dedup semantics; document exactly-once vs
  at-least-once guarantees.

### 2. Concrete backend

Implement one backend behind a feature flag. Recommended: **Bitcoin Core RPC** (`method-bitcoind`)
using a watch-only descriptor/xpub wallet:
- Config struct `BitcoindConfig { url, auth (cookie or user/pass), xpub or wallet name, network,
  min_confirmations }` following the style of `LndConfig` / `BitvoraConfig`.
- `new_address` derives the next unused address from the xpub descriptor (or `getnewaddress` on a
  named watch-only wallet) and registers it for watching.
- `subscribe_payments` polls (e.g. `listsinceblock` / `listtransactions` / `getaddressinfo`) on an
  interval and emits `ChainPaymentUpdate`s, tracking a block-height cursor.
- Keep all bitcoind-specific deps `optional = true` and only pulled in by the feature.

If a full bitcoind client is out of scope for a first pass, still land the trait + types + a
`MockOnChainProvider` (test-only) so `lnvps-api` can integrate against a stable interface, and
leave a clearly-marked `TODO` module for the real backend.

### 3. Feature flags (`Cargo.toml`)

- Add `onchain = [...]` (analogous to `lightning`/`fiat`) enabling the shared module.
- Add `method-bitcoind = ["onchain", "dep:...", ...]`.
- Add `method-bitcoind` to the `default` feature list **only if** the other methods are enabled by
  default (match current convention — currently all methods are default).
- Wire `tls-ring`/`tls-aws` if the RPC client needs TLS, matching existing optional dep patterns.

### 4. Exports & docs

- `src/lib.rs`: `#[cfg(feature = "onchain")] pub mod onchain;` with a module-level doc comment in
  the same style as the lightning/fiat modules (overview + `rust,ignore` example).
- Re-export concrete types from `onchain/mod.rs` (`#[cfg(feature = "method-bitcoind")] pub use bitcoind::*;`).
- Add a usage example under `examples/` gated with `required-features = ["method-bitcoind"]`,
  matching the `revolut`/`stripe` example entries.

### 5. Tests

- Follow the in-file `#[cfg(test)] mod tests` convention (see the extensive unit tests at the
  bottom of `src/lightning/mod.rs`): cover clone/debug/round-trip for every new struct and enum
  variant, sats↔msat conversion edge cases, and cursor resume logic.
- Provide a `MockOnChainProvider` (behind a `test`/`mock` cfg) that emits scripted
  `ChainPaymentUpdate`s so downstream (`lnvps-api`) integration tests need no real node.

## Constraints / house style

- Reuse `anyhow::Result`, `async_trait`, `futures::Stream`, `Pin<Box<...>>` exactly as the
  existing modules do. Match their import ordering and doc-comment density.
- No breaking changes to existing `LightningNode` / `FiatPaymentService` APIs.
- Keep every new external dependency `optional = true` and feature-gated.
- `cargo build`, `cargo test`, `cargo clippy --all-features` and `cargo fmt --check` must all pass.
- Bump the crate version and note the addition in the changelog if the repo keeps one.

## Definition of done

- A downstream crate can, with only `payments-rs` + `method-bitcoind` (or the mock):
  1. call `new_address(...)` to get a receive address tied to an order id,
  2. `subscribe_payments(cursor)` and receive `Detected`/`Confirmed` updates carrying the real
     txid and actual received `amount_msat`,
  3. resume the subscription after a restart without missing deposits.
- All new public items are documented; all tests pass; clippy/fmt clean.

## After merging here

Once released, update the `payments-rs` git `rev` in `lnvps-api/Cargo.toml` and implement the
`lnvps-api` side of #109 (new `PaymentMethod::OnChain` + `ProviderConfig`, DB migration, a
monitoring loop that inserts pro-rated `subscription_payment` rows using the txid as `external_id`
and the address as `external_data`). That work is tracked separately from this crate.
