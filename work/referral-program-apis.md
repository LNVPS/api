# Referral Program API Completion

**Status:** in-progress
**Started:** 2026-07-18
**Last updated:** 2026-07-18 (PR1 in progress: commission rate + payout mode)

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
- [ ] Migration: add `referral_rate FLOAT NOT NULL DEFAULT 0` to `company`
      (default) and `referral_rate FLOAT NULL` to `referral` (per-user override).
- [ ] `Company` + `Referral` models + all inserts/updates/selects (`lnvps_db`).
- [ ] Admin company GET/PATCH expose + edit `referral_rate` (`admin/companies.rs`).
- [ ] User `GET`/`PATCH /api/v1/referral` expose + edit the per-user override
      (`referral_rate`, null = use company default).
- [ ] Compute reward = first_payment * effective_rate% where
      effective_rate = referral.referral_rate ?? company.referral_rate: surface
      both the company rate and the referrer override in `list_referral_usage` /
      `ReferralCostUsage`, apply in `ApiReferralState` `earned` and the admin report.
- [ ] Tests (override wins, company default fallback, 0% default), docs + changelog.

### PR 2 — Admin referral management APIs + RBAC  [L]
- [ ] Add `AdminResource::Referral = 25`; explicit permission migration.
- [ ] DB: `admin_list_referrals` (paginated + search by code/user), `admin_get_referral`,
      `admin_list_referral_payouts`, earnings aggregation per referral.
- [ ] Endpoints: list referrals, get referral detail (earnings + payouts),
      create manual payout record, mark payout paid / reconcile (with external ref).
- [ ] Sanitize responses (no NWC secrets). Tests, docs, changelog.

### PR 3 — Automated payout processing (worker)  [L]
- [ ] Accrual: owed = sum(reward per referred VM first payment) − sum(existing payouts) per currency.
- [ ] Config: min payout threshold + schedule; expose in settings.
- [ ] Worker job: create `ReferralPayout`, pay via Lightning address (LNURL-pay)
      or NWC, capture `pre_image`, mark `is_paid`; failure handling + retries + notifications.
- [ ] Expose `pre_image` (hex) in `ApiReferralPayout`. Tests, docs, changelog.

### PR 4 — User API extras  [M]
- [ ] `DELETE /api/v1/referral` (leave program; guard pending payouts).
- [ ] `GET /api/v1/referral/usage` — per-referred-VM breakdown.
- [ ] Refine payout status surfacing. Tests, docs, changelog.

## Notes

- Currency: earnings/payouts are per-currency (referred VMs may span companies /
  currencies). Payout via Lightning implies BTC; conversion policy for non-BTC
  earned balances must be decided in PR 3.
- Keep one writer per PR; do not start PR N+1 until PR N is committed.
