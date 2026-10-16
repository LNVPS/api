# Account Credit

**Status:** complete (code, tests, docs); PR not yet opened
**Started:** 2026-10-15

Tracks [#145](https://github.com/LNVPS/api/issues/145).

## Goal

A customer tops up a credit balance and spends it against purchases, renewals
and upgrades, in full or as part of a larger bill. Every movement is a signed
row in `account_credit_event`, and the balance always equals their sum.

## Decisions (agreed with @v0l)

| Question | Decision |
|---|---|
| Top-up | `POST /api/v1/account/credit/topup {amount}` (msat) issues a Lightning invoice; settling it credits the balance. |
| Spend | Opt-in per user (`auto_apply`). Every renewal and upgrade quote applies `min(unreserved balance, net + tax)`. |
| Holding | `account_credit_debit` rows hold credit from the moment an order is priced until it expires. Unsettled, unexpired rows are subtracted from the balance when quoting, reserving and clawing back, so credit is never promised twice. |
| Settlement | `apply_payment` settles the debit. A debit whose hold expired is clamped to what live holds leave over, so a late payment can never spend credit promised to another order. |
| Fully credit-funded | No external invoice: `external_data = "credit"`, the debit is settled strictly before `complete_payment`. The API shows `data: "credit"`. |
| Processing fee | Scaled to the share still collected, like a discount. A remainder below the method minimum uses less credit so the remainder meets it. |
| On-chain | The watcher claims the credit at deposit time and prices `received + credit`. |
| Auto-renewal | Credit alone when it covers the whole renewal, otherwise the saved method pays the remainder. |
| Refunds | Automated VM refunds pay cash only up to the cash share of each payment and return the credit share to the balance. The reversal including credit must fit what the VM is owed. |

## Increments

- [x] Schema, DB layer, MockDb
- [x] Top-up API and Lightning listener
- [x] Quote-time credit with holds
- [x] Settlement (Lightning, Revolut, on-chain, fully funded)
- [x] Auto-renewal
- [x] Refunds return credit
- [x] Admin API and RBAC
- [x] E2E: API surface plus MariaDB tests for holds, late settles and concurrent settles (`./scripts/run-e2e.sh --filter credit`, with `LNVPS_ADMIN_API_URL=http://localhost:18001` when 8001 is taken)
- [ ] Label issue #145 with `enhancement`, `api`, `database`, `payments` when the PR opens

## Notes

- MariaDB snapshot isolation: every transaction that moves the balance takes the
  `account_credit` row lock (`lock_account_credit`) before any consistent read,
  otherwise concurrent settles fail with error 1020.
- `PayoutMode::AccountCredit` (referral payouts) can land into this ledger later.
