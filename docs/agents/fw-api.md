# lnvps_fw control API

`lnvps_fw_service` exposes a small **HTTPS** RESTful API (increment 7). The
daemon is the *server*; the primary `lnvps_api` service is the *client* and the
source of truth. The daemon keeps **no database**: rules are pushed by
`lnvps_api` and held in memory, and mitigation events go into a bounded
in-memory ring buffer that `lnvps_api` polls (via a monotonic cursor) and
persists itself.

Source: `lnvps_fw_service/src/api.rs` (server + handlers + dashboard),
`src/publish.rs` (tick→snapshot/event diffing), wired in `src/main.rs`.

## Transport & auth

- **HTTPS is required.** TLS via rustls. Provide `api.tls-cert` / `api.tls-key`
  (PEM); if omitted, a **self-signed** cert is generated at startup (rcgen)
  covering `localhost` + the listen IP, so HTTPS always works. `lnvps_api`
  accepts/pins the self-signed cert over the private management link.
- **Bearer token** on every API request: `Authorization: Bearer <api.token>`
  (constant-time compare). Missing/wrong → `401`.
- Optional **source-IP allow-list** (`api.allow-ips`); non-listed peer → `403`.

Config lives under the `api:` section (see `config.example.yaml`). Omit the
section to disable the API entirely.

## Endpoints (`/api/v1`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/status` | daemon health: version, uptime, interfaces, counts, events cursor |
| GET | `/rules` | current ruleset (protected prefixes + manual overrides) |
| PUT | `/rules` | replace the ruleset atomically (idempotent; re-push desired state) |
| GET | `/mitigations` | currently-active mitigations (auto + manual) with peak rates |
| POST | `/mitigations` | add/replace a manual override `{cidr, flags}` |
| DELETE | `/mitigations?cidr=<cidr>` | clear a manual override (`404` if absent) |
| GET | `/events?since=<cursor>` | events with `seq > cursor`, plus the next `cursor` |

`flags` is the `DEST_MODE_*` protection bitmask: `PORT_FILTER=1`, `SYN_PROXY=2`,
`RATE_CAPS=4`, `SOURCE_BLOCK=8`.

### Rules / overrides model

`PUT /rules` sets `{ protected: ["203.0.113.0/24", ...], overrides: [{cidr,
flags}, ...] }`. On change the control loop refreshes the protected-prefix list
used by prefix (carpet-bomb) detection and reconciles manual overrides into the
dest-state BPF trie (added/removed as the set changes). Malformed CIDRs are
rejected with `400`.

### Event polling

`GET /events?since=0` returns all buffered events and a `cursor`; poll again
with `since=<cursor>` for only new ones. The buffer is bounded
(`api.events-buffer`); on overflow the oldest are dropped — durable history is
`lnvps_api`'s responsibility.

## Dashboard

An internal, self-contained HTML dashboard is served at `/` (plain HTML + vanilla
JS, no external assets). It is outside the bearer-token layer (a browser can't
send a bearer header on navigation) but still behind the source-IP allow-list;
the page prompts once for the token (kept in `localStorage`) and calls the JSON
API. It shows status, active mitigations, rules/overrides, and a live event
feed.

## Local preview / smoke test (no root)

```sh
cargo run -p lnvps_fw_service --example serve_api
curl -k -H 'Authorization: Bearer devtoken' https://127.0.0.1:8899/api/v1/status
# dashboard: open https://127.0.0.1:8899/ and paste token `devtoken`
```

## Tests

`lnvps_fw_service/tests/api.rs` drives the router via `tower::oneshot` (no TLS /
no root): auth accept/reject, rules round-trip + bad-CIDR rejection, manual
override add/delete, incremental event polling, and the unauthenticated
dashboard. Pure logic (CIDR parse, constant-time compare, event ring
cursor/overflow, IP allow-list, self-signed cert generation) is unit-tested in
`src/api.rs`; the tick→snapshot/event diffing in `src/publish.rs`.
