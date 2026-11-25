# Payment gateway migration

LNVPS moves payment collection onto the payment gateway in stages. The in-process
payment code (`lnvps_api/src/payments/`, `payment_factory.rs`) stays until a final
cleanup issue, after a clean month on the gateway.

## Flows today and how they map

| Flow | Today | Gateway mapping |
|---|---|---|
| VM purchase, renewal, upgrade, add-on change | `SubscriptionHandler::build_payment` creates a `subscription_payment` and a provider object | One gateway payment per `subscription_payment`. `reference` is the hex payment id, `customer_ref` the user id, `metadata` carries `subscription_id` and `payment_type` |
| App and VPN line items | Same path, line item handlers run in `apply_payment` | Same |
| Credit top up | `account_credit_topup` with an invoice hash, settled by `NodeInvoiceHandler` | Stage 4: created through the gateway with the same handles as payments, settled by `payment.paid` |
| Credit funded payments | No provider object, settled in process | Never reach the gateway |
| Refunds | `refund.rs` records a `Refund` payment row and pays out | Stage 4: gateway payments (on-chain, FixedFloat, card) refund through `refund_payment` (`payment_method: "gateway"` on `POST /api/admin/v1/vms/{id}/refund`, optional `destination`). Lightning payments keep the node payout |
| Saved Revolut cards, off session renewals | `user_payment_method`, `charge_subscription` | Stage 3: gateway saved methods API (`charge_saved_method`), rows imported with their external ids |
| On-chain | `OnChainPaymentHandler` with derived addresses | Stage 4: gateway `onchain` attempt, address stored in `external_data`, `external_id` `pgw:<id>`, settled by `payment.paid`. Enabled with `onchain` in `gateway.methods` |
| FixedFloat altcoins | `SwapProvider` | Stage 4: gateway `fixedfloat` attempt (option = coin), swap details stored as `SwapData`. Enabled with `fixedfloat` in `gateway.methods`. The company coin list is still enforced by LNVPS |

### Invoice lines

`INVOICE_MODEL_DESIGN.md` lines (one per subscription line item, with its own
tax treatment) map to gateway `line_items`: name, quantity, unit amount and
`tax_amount` per line. Stage 2 sends only the totals (`amount` and `tax`),
since the frozen `tax_breakdown` on `subscription_payment` stays the source of
truth for receipts. Sending lines is stage 3 work, when card receipts need them.

## Customer visible parity audit

The customer must see the same thing whether a payment runs in process or through the gateway. Verdicts: OK (identical, covered by `subscription/gateway_contract_tests.rs`), FIXED (differed, changed here), OPEN (needs something outside this repo).

### a. Payment data shapes

| Method | In process | Gateway | Verdict |
|---|---|---|---|
| Lightning | bolt11 string in `external_data` | `details.bolt11` stored the same way | OK |
| Revolut | `{"token"}` from the order | `details.widget.token` stored as `{"token"}` | FIXED: card attempts now go through `create_card_attempt` |
| Stripe | not creatable in process ("not implemented") | `details.session_id` stored as `{"session_id"}` | FIXED: new, same `ApiPaymentData::Stripe` shape |
| On-chain | address string | `details.address`, `external_id` `pgw:<id>` | OK, `pgw:` ids are filtered out of `outpoint` by `deposit_outpoint` |
| FixedFloat | `SwapData` JSON | `details` mapped into `SwapData` | OK, API shows `{coin, address, amount}` |
| Credit | marker, no provider object | never reaches the gateway | OK |

The gateway `checkout_url` is dropped when the attempt is stored. It is never put in `external_data`, never returned and never used.

### b. Ids, expiry, polling, 0-conf

- Payment ids are random 32 bytes created by LNVPS and sent as the gateway `reference`. The `pgw:` `external_id` is internal and never serialised. OK.
- Expiry: Lightning 600 s, on-chain 3600 s, FixedFloat 1800 s are sent as `expires_in` and the LNVPS row keeps its own clock. Card payments now use 3600 s, the same as the in process Revolut order. OK.
- Status polling reads the LNVPS row, settled by the signed webhook. The client polls the same endpoints. OK.
- "Payment received, waiting for confirmation": the in process path sets `outpoint` at the first mempool sighting. A gateway on-chain payment has no LNVPS outpoint until the gateway reports it. OPEN: the gateway client at 64b456d exposes neither the seen-but-unconfirmed state (`progress` and receipts exist only on the public pay page, not on `Attempt`) nor an `attempt.received` webhook, so a 0-conf gateway deposit shows no outpoint until `payment.paid`. Filed as LNVPS issue 1433 (to move to payment-gateway, priority 40). The ignored test `onchain_seen_unconfirmed_shows_the_outpoint_like_in_process` names it. FixedFloat has the same gap.

### c. Save card and saved card list

- The `save_card` opt-in is honoured with the same rules as in process (opt in, no usable saved method yet, not an upgrade) and sent as `save_method`. The gateway needs the customer email to save a card, so a user with no email gets a plain card payment, as the in process path also fell back to an order. OK.
- `PaymentMethodResponse` exposes provider, name, brand, last four and expiry only. `gateway_method_id` is never serialised. OK.
- Importing existing Stripe and Revolut methods into the gateway is still blocked on the client import call. OPEN, unchanged.

### d. Receipts and emails

- Line items: card attempts send one line item carrying the net amount and the tax amount, so the gateway total equals the charge and the tax matches the frozen LNVPS breakdown. Per subscription line items stay stage 3 work. The LNVPS invoice remains the receipt customers get.
- Gateway emails: the only customer facing mail in the gateway is `send_receipt_mail`, which needs `customer_email` on the payment. At the pinned revision nothing calls it, and LNVPS sends `customer_email` only on a save card attempt (Revolut needs it to create the customer), never on a plain payment. Plain card, Lightning, on-chain and FixedFloat payments carry no email. OPEN: a per-project switch to turn customer receipt email off is filed as LNVPS issue 1434 (to move to payment-gateway, priority 45). Until it ships, the sandbox run must confirm no mail and that Stripe does not send its own receipt (an account setting on the Stripe side).
- Operator emails (webhook abandoned, refund failed, provider failing) go to tenant owners only.

### e. Failure messages

- A declined card arrives as `attempt.failed` and the text is unchanged: `Your card payment failed: <reason>.\nPlease try another payment method.` OK.
- Errors from the gateway client (`gateway create_attempt failed`) reach the customer through `ApiError::internal`, which returns "An internal error occurred" unless verbose errors are on (admin API only). Test `customer_text_never_names_the_gateway` covers a failing gateway. OK.

### f. Clients

No API field, enum variant or type changed, so the web app and the Nostr and API clients need no change. The only edit outside the payment code is making `api::model` crate visible so the contract test can serialise real responses.

### g. Return urls

Card attempts set `success_url` and `cancel_url` to the LNVPS `public-url`. The gateway checks them against the project allowed origins, so the LNVPS origin must be listed on the gateway project. Never a gateway page.

### Open items

1. Sandbox run against the sandbox gateway: not done, no sandbox key exists yet. Steps: enable a gateway row for revolut and stripe, buy with each, check the widget opens, the `external_id` starts `pgw:`, no email arrives from the gateway, the webhook settles once.
2. Mirror gateway on-chain and FixedFloat progress into `outpoint`: blocked on 1433.
3. Customer receipt email switch: blocked on 1434.
4. Add the LNVPS origin to the gateway project allowed origins (owner, on the gateway project).

## Stages

1. A `PaymentGateway` trait in `lnvps_api_common::gateway` with `InProcessGateway` (the LND node, default) and `GatewayClient` (the gateway API). Chosen per method by config. Done.
2. Lightning invoices through the gateway, settled by the signed `payment.paid` webhook. Done behind config.
3. Saved cards through the gateway. Done behind config: `gateway_method_id` on `user_payment_method`, charge and delete through the gateway, off-session renewals gated by `off-session-renewals` (`off`, `dry-run`, `live`). Not done: gateway line items and importing existing Stripe and Revolut methods, both blocked on the pinned client (payment-gateway issue 1027); the real client returns a "not supported by the pinned client" error for import.
4. On-chain, FixedFloat, refunds, credit top ups and the provider import script. Done behind config.
5. Remove `payments/` and `payment_factory.rs` after a clean month. Follow up issue.

## Stage 4 details

- Credit top ups (Lightning, on-chain, FixedFloat) now create their invoice or address through the same gateway handles as payments. The top up `invoice_hash` is the gateway payment `reference` (hex), so the `payment.paid` webhook settles it through `settle_credit_topup`, which is idempotent. Top ups created on the gateway have a `pgw:` `external_id` and the in-process chain watcher skips them, so nothing settles twice.
- API responses never expose a `pgw:` id as a deposit outpoint.
- Gateway refunds book one refund row whose id derives from the payment and the gateway refund id. The `refund.completed` webhook uses the same id, so the payout and the webhook never double book.
- Underpaid or overpaid gateway deposits are decided by the gateway: the LNVPS payment is only marked paid by `payment.paid`.

## Provider import script

`import_gateway_providers` copies `payment_method_config` rows into providers of the LNVPS gateway project. LNVPS registers its own LND, so no shared providers are involved. It maps `lnd` to `lightning/lnd`, `onchain` to `onchain/lnd`, `fixedfloat` to `fixedfloat` (the `supported_currencies` list becomes `coins` and must not be empty), `revolut` and `stripe` across, and skips PayPal (needs a webhook id the old config lacks). LND certificates and macaroons are read from the configured paths and sent inline. Disabled rows are created and then disabled. Rows already present by method, type and name are reported and left alone, so reruns are safe.

```
import_gateway_providers --config config.yaml --gateway-url https://pay.example --tenant 7
GATEWAY_ADMIN_TOKEN=... GATEWAY_IMPORT_CONFIRM=yes import_gateway_providers --config config.yaml --tenant 7 --apply
```

The default is a dry run that prints what it would create. `--apply` refuses unless `GATEWAY_IMPORT_CONFIRM=yes` is set. Use `--company-id` to import one company. Secrets are never printed.

## Configuration

```yaml
gateway:
  url: "https://pay-sandbox.apexstrata.ie"
  api-key: "<LNVPS project API key>"
  webhook-secret: "<signing secret of the webhook endpoint>"
  methods: ["lightning"]
```

Without a `gateway` section, or without `lightning` in `methods`, nothing changes.

## Staging runbook

1. In the gateway, create a project for LNVPS. Register the LNVPS LND as a `lightning/lnd` provider on that project (LNVPS keeps its own LND, so not the shared providers).
2. Add a webhook endpoint `https://<staging api>/api/v1/webhook/gateway` with events `payment.paid`, `payment.expired`, `payment.cancelled`. Copy its secret.
3. Add the `gateway` section above to the staging `config.yaml` and restart the API.
4. Check the log line `Lightning invoices are created through the payment gateway`.
5. Buy or renew a VM with Lightning, pay the invoice, and check: the payment row has `external_id` starting `pgw:`, the gateway shows the payment paid, the webhook returned 200, the subscription expiry moved once.
6. Replay the webhook from the gateway console. The expiry must not move again.
7. Let one invoice expire. The `subscription_payment` stays unpaid and expires on its own clock (both sides use 600 seconds).

## Settlement and expiry

- The webhook handler verifies the `X-Gateway-Signature` header, looks up the `subscription_payment` by the `reference`, and calls `SubscriptionHandler::complete_payment`. `subscription_payment_paid` only updates a row with `is_paid = 0`, and the handler also skips rows already paid, so replays are no-ops.
- The in-process `NodeInvoiceHandler` keeps running, so invoices created before the cutover still settle on the old path.
- Competing upgrade payments that get expired on settlement are cancelled at the gateway when their `external_id` starts with `pgw:`.
- `payment.expired` and `payment.cancelled` events are logged only. The LNVPS row expires by its own `expires` column. A sweep (every 60 seconds, only when a `gateway` section exists) cancels the gateway payment of every unpaid `pgw:` row past its `expires`, then renames its `external_id` to `pgw-cancelled:<id>` so it is cancelled once. A failed cancel is retried on the next pass.
- `attempt.failed` expires the unpaid LNVPS row and notifies the user; it never extends the subscription. `refund.completed` books one `Refund` row (keyed by the gateway refund id, capped at what is still refundable) and never re-credits or touches expiry. Both ignore references that are not `pgw:` payments of this deployment, and replays change nothing.

## Switch a company over

The gateway is a payment method row (`provider_type` `gateway`) an admin adds, enables and disables per company. No config edit or deploy is needed to switch.

### Precedence

1. If the company has any `gateway` row, the rows decide and the YAML `gateway:` section is ignored for that company. A disabled row means in process, not YAML.
2. If the company has no row, the legacy YAML `gateway:` section applies (`methods`, `off-session-renewals`).
3. With neither, payments are created in process.

The API logs which source is active at startup: `Payment gateway source: payment_method_config rows`, `YAML gateway section (legacy)` or `none`.

A row serves a payment method only while it is enabled and lists the method in `handles`. `handles` takes `lightning`, `onchain`, `fixedfloat`, `revolut` and `stripe`. PayPal is not accepted (the gateway cannot take it yet). A company can have one enabled gateway row, the admin API refuses a second.

The row holds `url`, `api_key`, `webhook_secret`, `tolerance_seconds` (default 300) and `off_session_renewals` (`off` default, `dry-run`, `live`). The admin API never returns the two secrets, only `has_api_key` and `has_webhook_secret`, and a PATCH that omits them keeps the stored values.

### Runbook

1. Dry run: `import_gateway_providers --config config.yaml --tenant <id> --company-id <company> --create-gateway-row --gateway-api-key ... --webhook-secret ...` (or `GATEWAY_API_KEY` and `GATEWAY_WEBHOOK_SECRET`). It lists the providers it would register and the gateway row it would add, and changes nothing.
2. Apply: the same command with `--apply` and `GATEWAY_IMPORT_CONFIRM=yes` and `GATEWAY_ADMIN_TOKEN`. It registers the company's LND, Revolut, Stripe and chain providers on the gateway and adds the `gateway` row **disabled**, with `handles` set to the methods it registered. It prints the next steps.
3. In the gateway, add a webhook endpoint `https://<api>/api/v1/webhook/gateway` for `payment.paid`, `attempt.failed`, `refund.completed`, `payment.expired` and `payment.cancelled`. If its secret differs from the one in the row, PATCH the row.
4. `POST /api/admin/v1/payment_methods/<id>/gateway/test` checks the url and key and reports a clear error if the gateway is unreachable or rejects the key.
5. `PATCH /api/admin/v1/payment_methods/<id>` with `{"enabled": true}`. New payments of the handled methods now go through the gateway. The change is immediate, no restart.
6. Watch `GET /api/admin/v1/payment_methods/<id>/gateway/status`: methods handled, time of the last paid gateway payment and the number of gateway payments in the last 24 hours.

### Rollback

`PATCH` the row with `{"enabled": false}` (or remove a method from `handles`). New payments go back in process at once. Payments already created on the gateway finish there: their `external_id` starts with `pgw:`, the webhook secret of the row still verifies while the row exists (enabled or not), and expiry cancellation still calls the gateway. Keep the row (disabled) rather than deleting it while gateway payments are open.

## Cutover

Enable on staging first, run the checks above for a few days, then add the section to production config. No data migration is needed for stage 2.

## Rollback (YAML section)

Remove the `gateway` section (or `lightning` from `methods`) and restart. New invoices come from the node again. Gateway invoices already issued keep settling through the webhook as long as the section's `webhook-secret` is kept, so for a clean rollback leave the section in with `methods: []`.
