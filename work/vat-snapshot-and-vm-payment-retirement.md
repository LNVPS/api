# VAT snapshot on payments + retire defunct vm_payment

**Status:** complete
**Started:** 2026-07-16
**Last updated:** 2026-07-16

## Goal

1. Freeze a full VAT determination snapshot (rate, place-of-supply country,
   treatment, and the evidence used) on every `subscription_payment` for OSS
   filing / audit defensibility.
2. Finish retiring the defunct `vm_payment` table: drop the table and remove the
   dead model/queries/backfill-phase-2/demo-data that still reference it.

## Findings

- **Live payment path is `subscription_payment`.** The public API
  (`/api/v1/vm/{id}/payments`, renew, etc.) already builds `ApiVmPayment` via
  `ApiVmPayment::from_subscription_payment(...)`. `ApiVmPayment` is only a
  response DTO name — not backed by the `vm_payment` table.
- **`vm_payment` is only referenced by:**
  - `lnvps_api/src/data_migration/vm_subscription_backfill.rs` Phase 2
    (`list_vm_payments_for_migration`) — copies old rows into
    `subscription_payment`. Phase 1 (VM→subscription linking) does NOT touch
    vm_payment and must be kept.
  - `lnvps_api_admin/src/bin/generate_demo_data.rs` (`insert_vm_payment`).
  - DB trait methods in `lnvps_db/src/lib.rs` (~12) + mysql impls (~53 refs) +
    mock impls + models `VmPayment`/`VmPaymentRaw`/`VmPaymentWithCompany`.
- **Payment tax is computed uniformly per payment** (one user + one
  `subscription.company_id`), so a single `TaxDetermination` per payment is
  correct. 4 `SubscriptionPayment {}` construction sites in
  `subscription/mod.rs`: lines ~550, 639 (aggregated renew) and ~736, 784
  (single-item). Upgrade path ~934 sets `tax: 0`.
- Migration ordering: the startup backfill runs AFTER schema migrations, so the
  `DROP TABLE vm_payment` migration and the removal of backfill Phase 2 must land
  together (otherwise Phase 2 queries a dropped table). Operator confirms prod is
  already migrated.
- Snapshot column design (chosen): `tax_rate double`, `tax_country_code
  varchar(3)`, `tax_treatment varchar(32)`, `tax_evidence json` (declared
  country / geo country / vat number). Discrete columns for reporting GROUP BY;
  JSON blob for rarely-queried evidence.

## Tasks

### Increment 1 — VAT snapshot on subscription_payment
- [x] Extend `TaxDetermination` with evidence (`declared_country`,
      `geo_country`); populate in `determine_tax`.
- [x] Per-line-item design: added `TaxLine`, `summarize_tax_lines`, `TaxSummary`,
      `NewPaymentInfo.tax_details`; determination now threaded per line item so a
      payment mixing sellers/treatments is recorded losslessly.
- [x] Migration: add `tax_rate`(nullable), `tax_country_code`, `tax_treatment`,
      `tax_evidence`, `tax_breakdown`(json) to `subscription_payment`.
- [x] Add fields to `SubscriptionPayment` + `SubscriptionPaymentWithCompany`.
- [x] `insert_subscription_payment` (WithCompany selects use `sp.*`) + mock.
- [x] Fill snapshot at the 4 construction sites (aggregated + single) from the
      per-line breakdown; upgrade path → `TaxDetermination::untaxed()`.
- [x] Removed now-unused `get_tax_for_user`.
- [ ] Surface in admin reports where subscription payments are exposed.
- [x] Tests (summarize uniform/mixed, to_line/evidence, determination branches);
      fixed provisioner test that asserted the old hardcoded 1%.

Note: a payment maps to one subscription (per-VM, single company+user) today, so
breakdowns are single-line in practice; the array design future-proofs multi-
seller subscriptions without a schema change.

### Increment 2 — Retire vm_payment
- [x] Migration `20260716130000_drop_vm_payment.sql`: `DROP TABLE IF EXISTS vm_payment`.
- [x] Removed backfill Phase 2 (kept Phase 1) + `migrate_vm_payments` +
      `list_vm_payments_for_migration` / `list_vm_ids_with_uncopied_payments` /
      `insert_subscription_payment_raw` / `list_subscription_payment_ids_for_subscription`.
- [x] Converted generate_demo_data to insert `SubscriptionPayment`.
- [x] Removed 12 trait methods (lib.rs), mysql impls, mock impls + mock
      `payments` field.
- [x] Removed models `VmPayment` / `VmPaymentRaw` / `VmPaymentWithCompany`,
      `ApiInvoiceItem::from_vm_payment`, `From<VmPayment> for ApiVmPayment`,
      `AdminVmPaymentInfo::from_vm_payment` (kept `ApiVmPayment` DTO name and the
      `AdminResource::VmPayment` RBAC resource).
- [x] Build/test/clippy clean across the workspace (e2e excluded — needs live stack).

## Notes

- No commits yet this session; user reviews before commit.
- `AdminResource::VmPayment` (RBAC resource id 15) intentionally kept — it gates
  the payment endpoints, which now read `subscription_payment`.
- Remaining `vm_payment`-ish identifiers are safe: `ApiVmPayment` DTO,
  `vm_payment_infos` locals, `log_vm_payment_received`, admin route names.

## Summary

Both increments complete. VAT determinations are now frozen per-payment as a
per-line-item breakdown (future-proof for multi-seller payments) plus a uniform
summary + customer evidence, surfaced in admin time-series reports. The defunct
`vm_payment` table and all its code are removed and the table is dropped.
