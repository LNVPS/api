# App Deployments (managed apps on shared k8s infra)

**Status:** in-progress
**Started:** 2026-07-24
**Last updated:** 2026-07-25

## Goal

Offer pre-defined "apps" (Nostr relay, Blossom server, …) as managed deployments on
the existing shared Kubernetes cluster (no per-user VMs / no IP-space usage). A generic
catalog (`app`) defines each app as a docker-compose-style YAML blob (image / ports /
env / volumes); user instances (`app_deployment`) are billed through the existing
subscription engine and reconciled into k8s by `lnvps_operator` (Deployment + Service +
Ingress + PVC + Secret), one namespace per deployment for isolation. Future: user-defined
images (higher isolation risk — design the boundary in now).

## Decisions (from user)

- **Billing:** reuse the subscription engine — add `SubscriptionType::App = 4`; deployments
  link via `app_deployment.subscription_line_item_id` exactly like `vm.subscription_line_item_id`.
- **Catalog schema:** a **compose-ish YAML blob** on the `app` row (our own format, not strict
  docker-compose). The UI renders standard forms that serialize into that YAML; the operator
  parses it back into k8s objects. Grammar is **plain top-level keys — no `x-*` extensions**:
  `services:`, `secrets:` (operator-generated), `config:` (user-provided form fields). See
  "Compose grammar" below.
- **Target catalog (Nostr services):** strfry, haven relay, route96 (+ its MariaDB), a generic
  Blossom server for the first cut (all pure HTTP ingress). **zap-stream-core** is the driver
  for the L4 (`expose: tcp/udp`) work (RTMP `1935/tcp` + SRT `udp` ingest) — later.
- **Isolation:** **namespace per deployment** (`app-{id}`) with default-deny NetworkPolicy,
  ResourceQuota/LimitRange, restricted PodSecurity, and a locked-down pod securityContext.
  Predefined apps are low-risk; keep the boundary so user-defined images later is a tightening
  (runtimeClass/egress), not a redesign.
- Scope now: **predefined apps only**.

## Findings

- `lnvps_operator` (kube 1.1 + k8s-openapi 0.25) already runs a periodic DB→k8s reconcile loop
  (`src/main.rs`) and builds cert-manager/nginx **Ingress** for nostr domains
  (`src/nostr_domains.rs`). App reconcile is the same pattern + Deployment/Service/PVC/Secret.
- Billing pattern to mirror: `Subscription` → `SubscriptionLineItem` (`subscription_type`) →
  product back-ref table (`vm.subscription_line_item_id`). Pricing shape = `VmCostPlan`
  (amount/currency/interval_amount/interval_type:`IntervalType{Day,Month,Year}`).
- `EncryptedString` (`lnvps_db::encrypted_string`) for secret-at-rest columns (used by `user.email`).
- `SubscriptionType`: IpRange=0, AsnSponsoring=1, DnsHosting=2, Vps=3 → **App=4** next.

## Tasks

### Increment 0 — prep: rename vm_host_region -> region (DONE, PR #213 merged)
- [x] Neutral `region` table + `Region` struct; API kept stable (`ApiVmHostRegion`).

### Increment 1 — DB foundation (this PR)
- [x] Migration: `app` catalog + `app_cluster` + `app_deployment` tables (cluster FK -> region).
- [x] `SubscriptionType::App = 4` (Display + repr) + `ApiSubscriptionLineItemResource::App`.
- [x] Model: `App`, `AppCluster`, `AppDeployment`, `AppDeploymentStatus`,
      `AppDeploymentDesiredState`.
- [x] DB trait methods (app catalog CRUD; app_cluster CRUD; deployment CRUD;
      `list_user_app_deployments`, `get_app_deployment_by_line_item`,
      `list_all_app_deployments` for the operator).
- [x] mysql impl + MockDb impl.
- [x] Unit tests (mock CRUD round-trips: catalog, cluster, deployment).

### Increment 2 — Admin catalog API (DONE, PR pending)
- [x] `lnvps_api_admin` CRUD for `app` + `app_cluster`; `AdminResource::App = 26` + RBAC migration.
- [x] Admin model (AdminAppInfo/AdminAppClusterInfo + create/update requests); slug/field
      validation (compose non-empty; full compose schema deferred to the operator).
- [x] Unit test (validate_app_fields) + e2e admin CRUD test (apps + clusters, auth enforcement).
- [x] ADMIN_API_ENDPOINTS.md + API_CHANGELOG.md.

### Increment 3a — Customer API (read-only) (DONE, PR #217 open)
- [x] `GET /api/v1/apps`, `GET /api/v1/apps/{id}` (catalog); `GET /api/v1/app-deployments`,
      `GET /api/v1/app-deployments/{id}` (own deployments, ownership-checked).
- [x] ApiApp / ApiAppDeployment response models (compose exposed for the deploy form;
      subscription_id resolved from the line item).
- [x] e2e customer test (seed_app_deployment helper) + API_DOCUMENTATION.md + API_CHANGELOG.md.

### Increment 3b — Customer ordering / lifecycle (billing) — TODO
- [ ] Create deployment (validate config vs compose env schema → subscription + line item
      (type App) + payment invoice, mirroring VM order); delete/stop/start; renew via subscription.

### Increment 4a — Shared compose parser (DONE, PR #218 merged)
- [x] New `lnvps_compose` crate (serde + serde_yaml, no heavy deps): typed model (`Compose`
      /`Service`/`Port`/`Volume`/`SecretDecl`/`ConfigField`/`Backup`), `parse` + `validate`
      (ingress=http only, mount-path traversal guard, depends_on refs, backup command|volume),
      `referenced_vars`, `resolve_env` (`${…}` substitution, errors on unknown).
- [x] Shared with the API: `lnvps_api_admin` validates `compose` via `lnvps_compose::Compose::parse`
      on catalog create/update (same parser the operator will use).
- [x] Unit tests (9) in the crate + admin validator test updated.

### Increment 4a+ — Config files (`files:`) (DONE, PR pending)
- [x] `files:` per service: read-only injected config, `content` (templated) or `content_from`
      (a `config` field, incl. new `type: file`), optional `sensitive` (→ Secret vs ConfigMap).
      Operator mounts via `subPath` at `path`.
- [x] Validation: absolute/non-traversal path, single content source, ≤256 KiB inline,
      `content_from` must be a declared config field, file must not overlap a data volume.
- [x] `resolve_files(vars) -> {service: [ResolvedFile{path,content,sensitive}]}`;
      `referenced_vars` also scans file content. Distinct from `volumes:` (PVC, read-write).

### Increment 4b — Operator reconcile (DONE, PR pending)
- [x] `lnvps_operator/src/app_deployments.rs`: pure k8s object builders (Namespace w/ restricted
      PSS, default-deny NetworkPolicy, PVC, ConfigMap/Secret for files, Deployment w/ locked-down
      securityContext + PVC/file subPath mounts, ClusterIP Service, cert-manager Ingress) — all
      unit-tested (13). Generated-secret stability via a namespace `generated` Secret.
- [x] `reconcile_app_deployments(ctx)`: server-side apply per deployment (filtered by the
      operator's `app_cluster_id`), resolve env+files via `lnvps_compose`, status/hostname
      write-back, and namespace GC for removed/deleted deployments. Wired into the reconcile loop.
- [x] Retention: an **expired** subscription scales the workload to **0 replicas** (pods stop,
      PVCs/data retained); only real deletion GCs the namespace. PVCs use the **cluster default
      StorageClass** (no `storageClassName` set) — decided.
- [ ] ResourceQuota + container resource requests deferred to the capacity increment (a
      `limits.*` quota needs container limits first). Builder present, `#[allow(dead_code)]`.

### Increment 4c-i — Resources + footprint + operator enforcement (DONE, PR pending)
- [x] Compose: per-service `resources: { cpu, memory }` (defaults 250m/256Mi); `Compose::footprint()`
      = Σ service cpu/mem + Σ volume sizes → `Footprint { cpu_milli, memory_bytes, storage_bytes }`;
      `parse_cpu_milli` / `parse_bytes` (k8s quantities). Unit-tested (15 total).
- [x] Operator: container requests==limits from `resources:` (Guaranteed QoS, 1:1); ResourceQuota
      sized from `compose.footprint()` now applied (caps the namespace at what was provisioned).

### Increment 4c-ii — Capacity admission (DONE, PR pending)
- [x] DB: `app` footprint columns (`cpu_milli`/`memory_bytes`/`storage_bytes`) + `app_cluster`
      static `capacity_*` columns (admin-set), 1:1.
- [x] `AppClusterCapacityService` (lnvps_api_common, mirrors `HostCapacityService`): `used` /
      `available` / `fits` / `select_in_region` (available = capacity − Σ non-deleted deployment
      footprints). Unit-tested via MockDb.
- [x] Admin: footprint computed from compose (`lnvps_compose::footprint`) + stored on app
      create/update; `capacity_*` on cluster create/update; both exposed on the info responses.
      e2e admin test asserts footprint + capacity echo.

### Increment 5 — Seed launch apps
- [ ] Seed **strfry**, **haven relay**, **route96 (+ MariaDB)**, **generic Blossom** (compose
      YAML) via migration or admin seed. All HTTP-ingress; route96 exercises multi-service +
      generated secrets.
- [ ] Integration/e2e coverage where feasible.

### Increment 6 — Volume backups (post-MVP)
- [ ] Compose `backup:` grammar (per-service `command:` app-native dump | `volume:` raw tar;
      top-level `backup: { schedule, retention }`).
- [ ] Operator backup/restore **Jobs** in the deployment namespace (PVC mounted RO for backup;
      app scaled to 0 for restore). Prefer logical dumps; CSI VolumeSnapshots for fast PITR if
      the storage class supports it.
- [ ] Delivery: on-demand artifact (LNVPS object storage) with one-time, Nip98-auth, time-boxed
      download URLs; OR scheduled push to a customer-owned target (S3/WebDAV/**Blossom**).
- [ ] API: `POST/GET /api/v1/app-deployments/{id}/backups`, `GET .../backups/{bid}` (download),
      `POST .../backups/{bid}/restore`, `PATCH .../backup-config`.
- [ ] **Security (see "Volume security" below) — mandatory before shipping.**

### Increment 7 (optional) — L4 apps + zap-stream-core
- [ ] `expose: tcp/udp` via ingress-controller TCP/UDP ConfigMap (or NodePort); seed
      zap-stream-core (RTMP/SRT ingest).

## Catalog candidates (from awesome-nostr)

Self-hostable server-side software a customer would want their own instance of. Fit = MVP
(single/multi-service HTTP ingress) unless noted. Curated 2026-07-25.

**Relays (wss:// http ingress):**
- strfry (C++/LMDB) — high-perf, popular. **launch**
- HAVEN (Go) — 4 relays + Blossom in one; sovereign personal setup. **launch**
- Chorus (Rust) — personal/community relay.
- rnostr (Rust) — high-perf scalable (redis/…); Chronicle (Go) — personal note archive.
- khatru (Go) framework → Pyramid (invite-only WoT), relay29/groups-relay (NIP-29 communities),
  zooid (multi-tenant community relay).
- WoT relay / AlgoRelay (bitvora, Go) — web-of-trust / algorithmic personal feed.
- Nerostr (Go) — **paid** relay (Monero) → good demo of the paid-relay angle.
- SW2 (bitvora) — private whitelisted relay/dropbox; grain (Go/Mongo) — configurable multipurpose.

**Media / Blossom / file storage (https):**
- route96 (v0l, Rust, +MariaDB) — Blossom/NIP-96. **launch**
- Blossom (hzrd149) — reference blob server; bloom (nostrnative) — Blossom+relay hybrid.
- HORNET Storage — multimedia relay w/ large media.

**All-in-one servers (relay + blossom + nip-05 + more):**
- nostrcheck-server — relay + file hosting + Nostr Address + LN redirects + NWC + WoT. Strong.
- Alienos — plugin-able relay/blossom/nip-05 stack, tor-friendly. Zapstore/server — relay+blossom.

**NIP-05 identity (https, simple):**
- zaps.lol / nostr-address-provider (jigglycrumb) — self-hostable address provider. **easy launch**
- nanostr (Deno) — NIP-05 name server.

**Lightning / LN address / zaps (https; needs a funding backend the customer configures):**
- LNbits — LN accounting + extensions + zappable LN addresses. Very popular self-host.
- nostdress (satdress fork) — LN address server w/ NIP-05/NIP-57.
- Alby Hub — self-hosted LN node + NWC (heavier: runs a node).

**DVMs / compute (https, Lightning-paid — great V4V fit):**
- NostrDVM (python framework); DVMDash (backend + dashboard).
- dvm-textgen / dvm-imagegen (Go) — text/image gen DVMs paid via Lightning.
- vertexlab / DVMCP — WoT-as-a-service / MCP↔DVM bridge.

**Bridges & gateways (https):**
- njump — static Nostr→HTML gateway (nice public service). atomstr / rssnotes / nostrss — RSS↔Nostr.
- Mostr (Soapbox) — Nostr↔Fediverse bridge.

**Web of Trust / indexing:**
- wot-relay, graperank-nodejs, nostr-wot-oracle, wot-scoring. Primal caching service (heavy: pg+relays).

**Later / heavier (L4 or big footprint):**
- zap-stream-core (v0l) — streaming, RTMP `1935/tcp` + SRT `udp` → needs increment 7.
- Ditto (Soapbox) — full community server; Servus (Rust) — CMS/blog + personal relay; Hivetalk —
  Nostr+LN video conferencing.

**Suggested launch set:** strfry, HAVEN, route96(+MariaDB), a generic Blossom, and a NIP-05
address provider — with LNbits + a DVM as strong fast-followers.

## Compose grammar & k8s mapping (increment 4)

Four top-level keys, plain (no `x-*`): `services`, `secrets`, `config`. Example
(route96 + its own MariaDB — multi-service with a generated DB password):

```yaml
services:
  mariadb:                                   # no exposed port -> internal only
    image: mariadb:11
    env:
      MARIADB_DATABASE: route96
      MARIADB_USER: route96
      MARIADB_PASSWORD: ${DB_PASSWORD}       # from secrets:
      MARIADB_ROOT_PASSWORD: ${DB_ROOT_PASSWORD}
    volumes:
      - { name: db, path: /var/lib/mysql, size: 5Gi }
    backup:
      command: ["sh","-c","mariadb-dump --all-databases -uroute96 -p$DB_PASSWORD"]
      artifact: route96.sql
  route96:
    image: ghcr.io/v0l/route96:latest
    depends_on: [mariadb]                     # advisory only (app retries; k8s has no hard order)
    ports:
      - { name: http, container: 8000, protocol: http, expose: ingress }
    env:
      DATABASE_URL: "mysql://route96:${DB_PASSWORD}@mariadb:3306/route96"
      PUBLIC_URL: "https://${HOSTNAME}"       # operator-injected from cluster ingress domain
      MAX_UPLOAD_MB: ${max_upload_mb}         # from config:
    volumes:
      - { name: blobs, path: /app/data, size: 20Gi }
    backup:
      volume: blobs                           # raw tar of the named PVC (append-only blobs -> safe)

secrets:                                      # operator generates ONCE per deployment, stored in a k8s Secret
  - { name: DB_PASSWORD, generate: password }
  - { name: DB_ROOT_PASSWORD, generate: password }

config:                                       # rendered as the customer's deploy form; values -> app_deployment.config (encrypted)
  - { name: max_upload_mb, label: "Max upload (MB)", type: int, default: 100 }
```

**Mapping (per deployment namespace `app-{id}`):**
- each `services.*` → a workload: **Deployment**, or **StatefulSet** if it has volumes (stable
  identity + PVC), + a **ClusterIP Service** named after the service (→ compose-style DNS, e.g.
  `mariadb:3306`, works because each deployment has its own namespace).
- `services.*.volumes[]` → **PVC** per named volume, mounted at `path`.
- `secrets:` → one **Secret**; each entry generated once (`generate: password|token|...`) and
  injected wherever `${NAME}` is referenced (across services).
- `config:` → customer form values (stored encrypted on `app_deployment.config`) injected as env.
- `${HOSTNAME}` → `{deployment.name}.{cluster.ingress_domain}`; `${service}` → in-namespace DNS.
- **Ports / ingress (opt-in per port via `expose`):**

| `expose` | k8s objects | Host/TLS | Notes |
|---|---|---|---|
| `none` (default) | ClusterIP Service only | no | internal/sidecar/DB |
| `ingress` | Service + nginx Ingress + cert-manager TLS | yes (`name.{cluster.ingress_domain}`) | **http only** (WS rides http → wss/relay/blossom). Operator rejects `ingress` on tcp/udp. |
| `tcp`/`udp` | Service via ingress-controller TCP/UDP ConfigMap (or NodePort) | no (L4) | increment 7; not in MVP |

- MVP supports `none` + `ingress` only (all first-cut apps are http ingress). `tcp`/`udp` later.
- `app_deployment.hostname` is `Option` precisely because apps without an `ingress` port
  have no public HTTP host — no schema change needed for ingress-less apps.

## Volume backups (increment 6)

- `backup:` per service selects the method: `command:` (app-consistent logical dump, captured
  from stdout — default for DBs) or `volume: <name>` (raw tar of a PVC — only for append-only
  data). Top-level `backup: { schedule, retention }` for automatic runs.
- Backup/restore run as **Jobs** in the deployment namespace: backup mounts the PVC **read-only**;
  restore scales the app to 0, prefers `mysql < dump`, else guarded untar, then scales back up.
- Delivery: on-demand artifact in LNVPS object storage with one-time / time-boxed / Nip98-auth
  download URLs; OR scheduled push to a customer-owned S3/WebDAV/**Blossom** target (keeps the
  customer as data custodian; Blossom target is Nostr-native).

## Volume security (directory-traversal) — mandatory for increment 6

The two load-bearing controls: **(a) no hostPath + least-privilege pods** cap the blast radius to
one PVC/namespace regardless of app bugs; **(b) sanitized extraction with logical dumps preferred**
closes the one place (restore) where attacker-controlled paths could escape.

- **Opaque IDs, never client paths.** Backups referenced by DB `backup_id`; stored key is
  server-derived (`deployments/{id}/{uuid}`) with an ownership check. No `?file=`/path segments.
- **No `hostPath` ever.** Compose volumes map only to PVCs; the catalog validator rejects any
  host-path mount. So a traversal tops out at the container's own PVC — never the node.
- **Validate mount paths at catalog time:** `volumes[].path` absolute, no `..`, under an allowed
  prefix; `name` a slug; `backup.volume` must match a declared volume name (lookup, not a path).
- **Archive extraction (tar/Zip-Slip) on restore:** prefer logical dumps (no path semantics); for
  raw-tar restore, canonicalize each entry and assert it stays under the target, reject absolute
  paths / `..` / symlinks-hardlinks pointing outside / device files; never `tar -x` untrusted
  input blindly. Restore Job: PVC is the only writable mount, non-root, read-only rootfs.
- **Runtime pods:** non-root, `readOnlyRootFilesystem`, drop ALL caps, `allowPrivilegeEscalation:
  false`, seccomp `RuntimeDefault`, volumes only at declared paths, default-deny NetworkPolicy.
- Any future live SFTP/filebrowser must jail to the single PVC mount (pod mounts only that volume).

## Notes

- Deployment `config` stored encrypted (EncryptedString over JSON) so secret env values are
  protected at rest.
- Keep resource sizing in the app's compose for now (flat per-catalog pricing); per-deployment
  resource overrides can come later.
