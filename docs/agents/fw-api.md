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
| GET | `/limits` | live detection thresholds (destination, prefix **and per-source**) |
| PUT | `/limits` | live-edit the thresholds (in-memory; control loop reloads next tick) |
| GET | `/tracked` | live per-destination RX/TX rates (paginated + filtered) |
| GET | `/ports` | learned open ports per protected IP (paginated + filtered) |
| GET | `/sources` | **the** unified source list: every rate-tracked source (3-state + live pps) plus manual blocks, paginated + filtered |
| GET | `/blocks` | legacy: currently-blocked sources only (manual CIDRs + kernel-blocked /32s|/128s), paginated |
| POST | `/blocks` | add a permanent manual source block `{cidr}` (updates the ruleset) |
| DELETE | `/blocks?cidr=<cidr>` | remove a manual source block |
| GET | `/upgrade` | cached self-upgrade status: `current`, `latest`, `available`, `deb_url` |
| POST | `/upgrade` | download the latest release `.deb` and install + restart (202) |

### Self-upgrade

The daemon checks the GitHub releases API (`api.github-repo`, default
`LNVPS/api`) at startup and every 6h, caching the result. `GET /upgrade` returns
it; the dashboard shows an **upgrade** button when a newer release with a `.deb`
asset exists. `POST /upgrade` downloads that `.deb`, verifies it, and runs
`dpkg -i` + `systemctl restart lnvps_fw` in a **detached transient systemd
unit** (`systemd-run`) so the install completes across the service restart.
Requires releases to exist — tag `vX.Y.Z` so the `lnvps_fw-deb.yml` workflow
builds and attaches the package.

`flags` is the `DEST_MODE_*` protection bitmask: `PORT_FILTER=1`, `SYN_PROXY=2`,
`RATE_CAPS=4`, `SOURCE_BLOCK=8`.

### Limits (`/limits`)

There are **two independent pps thresholds** and both are exposed here so
neither can hide:

- `pps`/`syn_pps`/`bps` (+ `net_*` prefix aggregates) — *destination* entry
  thresholds: “is this dest under attack?”
- `src_rate_pps` (+ `src_cooldown_secs`) — the *per-source* auto-block
  threshold, enforced by the in-kernel rate machine over an exact 1s window:
  once a dest is mitigating, any single source over this rate is blocked for
  the cooldown. Necessarily much lower than the dest threshold, but keep it
  well above shared-infrastructure rates (CDN/reverse-proxy edges, CGNAT) —
  default 10 000 pps. Mirrors `escalation.src-rate-pps` in the config file;
  the API value wins after a PUT (userspace re-writes the kernel config map).
- `syn_proxy_pps` — engage the SYN-proxy once a mitigating entity's SYN rate
  reaches this many SYNs/second. **`0` disables the SYN-proxy** (live-toggle
  it off here without a restart). The SYN-proxy `XDP_TX`s a cookie SYN-ACK out
  the *ingress* NIC and cannot re-encapsulate it or steer it to another
  egress, so it only works on symmetric, directly-reachable, single-hook
  topologies — set `0` on tunneled / GRE-backed / asymmetric-routed routers or
  it black-holes real services.
- `learn_leak_pps` — per-destination budget of **new distinct-port probes/sec**
  the port filter leaks through while mitigating (first-touch: each unknown TCP
  or UDP port is probed once, given a grace window for the reply, then assumed
  closed and suppressed — re-probed periodically), so a genuinely-open port can
  still answer and be passively learned. `0` = drop-all (black-holes any open
  port not learned before the flood). Default 100. Amplification-safe: the
  probe key is `(dest,port)`, so a spoofed UDP amp flood to one port leaks only
  ~1 packet/cycle. **WireGuard** handshake-initiation packets (type 1, 148
  bytes) are fast-pathed — leaked (rate-capped, bypassing suppression) so a
  tunnel re-establishes even under a garbage flood to its port. Learned ports
  are also refreshed from ingress traffic, so a long-lived connection active in
  either direction won't age out mid-flight under mitigation.

Omitting any of these fields in a PUT (older clients) falls back to its default
rather than zeroing it.

### Source list (`/sources`)

While a destination is under mitigation, the **XDP datapath itself** runs a
fixed-window rate machine per source IP: it counts each source over a 1s
window and blocks over-rate sources in-line (`blocked_until` in its state
map), with drops engaging once the destination escalates to `SOURCE_BLOCK`.
Userspace is not in the decision path — it snapshots the kernel state map
(batched) purely for this view. `GET /sources` is the **single** source list
the UI shows, plus operator-pushed manual blocks. An auto block is simply an
entry whose `state` is `dropping`.

Each item is `{ ip, pps, state, manual, age_secs }` where `state` is one of:

- `normal` — under the per-source limit (`src-rate-pps`); counted but **not**
  blocked.
- `dropping` — tripped the limit; the kernel drops its packets until the
  cooldown expires (re-extended every window it stays over-rate).

`pps` is estimated from the current kernel window (count over elapsed); an
idle source's rate decays toward zero naturally. A `normal` source idle for
60s is swept from the kernel state map by the daemon's GC timer.

`manual: true` rows are permanent operator blocks (from `POST /blocks`); they are
dropped before per-source counting so they always report `pps: 0` and are pinned
to the top. `?q=` substring-filters on the IP, `?offset=`/`?limit=` paginate
(limit clamps to `1..=1000`, default 100), otherwise most-active-first.

`GET /blocks` remains for the raw enforced-trie view (manual + auto, CIDR blocks
possibly aggregated to /24 etc), but the dashboard now uses the unified
`/sources` list. Manual blocks are still managed via `POST`/`DELETE /blocks`.

### GeoIP enrichment

Every IP-bearing item on `/sources`, `/blocks`, `/tracked`, `/prefixes`, and
`/mitigations` is optionally annotated with flattened `{asn, org, country}`
fields (ASN number, AS/ISP org name, ISO country code) looked up from MaxMind
GeoLite2 databases. The fields are **omitted** from the JSON when the value is
unknown or no database is configured, so the schema is unchanged when
enrichment is off. Configure it under the top-level `geoip:` key. Databases come from either:

- **Auto-download** — set `license-key` (a free MaxMind license key) and the
  `GeoLite2-ASN` and `GeoLite2-Country` databases are downloaded on startup
  into `download-dir` (default: the state dir `/var/lib/lnvps_fw`), verified
  against MaxMind's companion SHA-256, and **hot-reloaded** every
  `refresh-interval-hours` (default 24). Downloads are best-effort: a failure
  falls back to the last good copy on disk. The license key is only ever placed
  in the request URL, never logged.
- **Explicit paths** — `asn-db` (GeoLite2-ASN.mmdb → asn + org) and/or
  `country-db` (GeoLite2-Country.mmdb → country) point at `.mmdb` files the
  operator manages. Explicit paths take precedence over auto-download for that
  edition.

Enrichment is loaded in the background, so requests before the first load (or
when no DB is configured) simply carry no geo fields. A missing/unreadable DB
logs a warning and disables that field rather than failing startup. Lookups run
at response-build time over the bounded page — never on the detection hot path.
For a CIDR the network address is looked up. The GeoLite2 EULA forbids bundling
the databases, so they are never shipped with the `.deb`.

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
