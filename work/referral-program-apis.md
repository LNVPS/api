# Referral Program API Completion

**Status:** complete
**Started:** 2026-07-18
**Last updated:** 2026-07-18 (all 4 PRs complete)

## Goal

Complete the referral program so it is fully operable end-to-end: a configurable
commission (percentage of the referred VM's first payment), admin management APIs
(list/inspect referrers, earnings, payouts; manual payout + reconcile), automated
payout processing (pay referrers via Lightning address / NWC, capture preimage),
and the missing user-facing endpoints. Delivered as a sequence of L-or-smaller
PRs, one increment at a time.

## Findings

Current state (as of investigation):

- **User API** `lnvps_api/src/api/referral.rs`: `POST` enroll, `GET` state,
  `PATCH` payout prefs. State exposes per-currency `earned`, `payouts`, and
  success/failed counts. No `DELETE`, no per-referral VM detail list.
- **Attribution**: `vm.ref_code` set at order time (`provisioner/vm.rs`).
  Earnings basis = first paid subscription payment per referred VM
  (`list_referral_usage` in `lnvps_db/src/mysql.rs:2980`).
- **DB layer** (`lnvps_db/src/lib.rs:790+`, `model.rs:1310+`): `Referral`,
  `ReferralPayout` (has `is_paid`, `invoice`, `pre_image`), `ReferralCostUsage`,
  and `insert/update_referral_payout`.
- **DEAD CODE**: `insert_referral_payout` / `update_referral_payout` are never
  called in production — no accrual, no worker payout job, `pre_image` unused,
  `payouts` is always empty in practice.
- **Admin**: only `GET /api/admin/v1/reports/referral-usage/time-series`
  (`admin/reports.rs`). No referral CRUD, no payout management. No dedicated
  RBAC resource (report reuses `analytics::view`).
- **Config**: no commission rate / cap / threshold anywhere. `earned` currently
  sums the *full* first payment.

Decisions:

- **Commission model**: configurable **percentage of the first payment** per
  referred VM. The effective rate is **per-referrer with a company default**:
  `referral.referral_rate` (nullable override on the referrer's entry) takes
  precedence, else `company.referral_rate` (the referred VM's company). Payments
  are company-scoped, so a referrer with no override uses each referred VM's
  company default; an override applies to all of that referrer's referrals.
- Follow the project's explicit per-feature RBAC grant convention (grant new
  `Referral` resource to `super_admin`; extend `read_only`/`admin` only if we
  add it deliberately — mirror how existing resources were introduced).

## Tasks

### PR 1 — Commission config + flexible payout mode  [M]
- [x] Replace `referral.use_nwc` boolean with a `ReferralPayoutMode` enum column
      (`lightning_address` | `nwc` | `account_credit`, extensible). Migration
      migrates use_nwc=1 -> nwc. API `mode` field replaces `use_nwc`;
      `account_credit` reserved/rejected until implemented.
- [x] Migration: add `referral_rate FLOAT NOT NULL DEFAULT 0` to `company`
      (default) and `referral_rate FLOAT NULL` to `referral` (per-user override).
- [x] `Company` + `Referral` models + all inserts/updates/selects (`lnvps_db`).
- [x] Admin company GET/PATCH expose + edit `referral_rate` (`admin/companies.rs`).
- [x] User `GET /api/v1/referral` exposes the per-referrer override (read-only;
      admin-controlled — users cannot set their own commission).
- [x] Compute reward = first_payment * effective_rate% where
      effective_rate = referral.referral_rate ?? company.referral_rate: surfaced
      in `list_referral_usage` / `ReferralCostUsage.effective_rate`, applied in
      `ApiReferralState` `earned` and the admin report (`effective_rate`,`commission`).
- [x] Tests (commission floor/0%, mode roundtrip, parse_payout_mode), docs + changelog.

**PR1 committed:** `4048398`. Note: per-referrer override is set by admins (PR2),
not users. `referral.referral_rate` NULL = use company default.

### PR 2 — Admin referral management APIs + RBAC  [L]
- [x] Add `AdminResource::Referral = 25` (Display/FromStr/TryFrom/all + roundtrip
      test); explicit permission migration `20260718002000` (grants super_admin).
- [x] DB: `admin_list_referrals` (paginated + search by code substring or 64-char
      hex pubkey via SQL HEX()), `admin_get_referral`; extended
      `update_referral_payout` to also set invoice; mock impls + test.
- [x] Endpoints (`admin/referrals.rs`): list, detail (earnings + payouts +
      counts), PATCH commission override, list/create payout, PATCH reconcile
      (is_paid/invoice/pre_image).
- [x] Sanitized (no NWC secrets). Tests, docs, changelog.

**PR2 committed:** `4d19600`. Per-referrer override is set here via
`PATCH /api/admin/v1/referrals/{id}`.

### PR 3 — Automated payout processing (worker)  [L]
- [x] Accrual: owed BTC = sum(commission on first payments) − sum(existing BTC
      payouts, paid + reserved). Only BTC is auto-paid (Lightning settles sats);
      fiat commission left for manual admin payout.
- [x] Config: opt-in `referral` settings section (`min-payout-sats`, default
      1000). Absent = automated payouts disabled. Job scheduled hourly, gated on config.
- [x] Dedicated `ReferralPayoutHandler` (`lnvps_api/src/referral/mod.rs`) —
      **not** in SubscriptionHandler. Reserve-then-pay (delete reservation on
      failure) so no double-pay; LNURL-pay + NWC make_invoice; captures pre_image;
      notifies referrer. New DB base methods `list_all_referrals` /
      `delete_referral_payout`; `update_referral_payout` also persists invoice.
- [x] Expose `pre_image` (hex) in `ApiReferralPayout`. Tests (payable math),
      docs, changelog.

**PR3 committed:** `8980e48`. Note: enabled lnurl-rs `async-https-native`
feature; new `WorkJob::ProcessReferralPayouts`; `Worker::new` gained a `node` param.

### PR 4 — User API extras  [M]
- [x] `DELETE /api/v1/referral` (leave program). Blocks on pending payout (409)
      and on paid payout history (retained for accounting). New base DB method
      `delete_referral` + mock test.
- [x] `GET /api/v1/referral/usage` — per-referred-VM breakdown (vm_id, first
      payment, currency, effective_rate, commission).
- [x] `pre_image` already surfaced in payout records (PR3). Tests, docs, changelog.

**PR4 committed:** `b5dac33`.

## Summary

All four increments are merged: PR1 `4048398` (commission rate + payout mode),
PR2 `4d19600` (admin management + RBAC), PR3 `8980e48` (automated payout worker),
PR4 `b5dac33` (leave program + per-VM usage). The referral program is now
complete end-to-end: configurable per-referrer/company commission, admin
management, automated BTC Lightning payouts (opt-in), and full user self-service.

## Notes

- Currency: earnings/payouts are per-currency (referred VMs may span companies /
  currencies). Payout via Lightning implies BTC; conversion policy for non-BTC
  earned balances must be decided in PR 3.
- Keep one writer per PR; do not start PR N+1 until PR N is committed.
