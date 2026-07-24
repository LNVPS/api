# App Deployments (managed apps on shared k8s infra)

**Status:** in-progress
**Started:** 2026-07-24
**Last updated:** 2026-07-24

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
- **Catalog schema:** a **docker-compose-style YAML blob** on the `app` row. The UI renders
  standard forms (add/remove ports + env) that serialize into that YAML; the operator parses
  the YAML back into k8s objects.
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

### Increment 3 — Customer API
- [ ] `GET /api/v1/apps` (catalog), create deployment (→ subscription + line item + invoice,
      mirroring VM order), list/get/delete deployments, status + endpoint.
- [ ] Validate submitted env/config against the app's compose env schema.
- [ ] Tests + API_DOCUMENTATION.md + API_CHANGELOG.md.

### Increment 4 — Operator reconcile
- [ ] `lnvps_operator/src/app_deployments.rs`: parse compose YAML + deployment config →
      Namespace + Deployment + Service + Ingress + PVC + Secret + NetworkPolicy + ResourceQuota,
      locked-down securityContext; status write-back to DB. Wire into the reconcile loop.

### Increment 5 — Seed launch apps
- [ ] Seed Nostr relay + Blossom apps (compose YAML) via migration or admin seed.
- [ ] Integration/e2e coverage where feasible.

## Compose port → k8s mapping (increment 4)

Ingress is opt-in per port. Every declared port becomes a ClusterIP Service port;
external exposure is driven by an explicit `expose` field:

```yaml
services:
  relay:
    image: ghcr.io/hoytech/strfry:latest
    ports:
      - { name: ws, container: 7777, protocol: http, expose: ingress, path: / }
```

| `expose` | k8s objects | Host/TLS | Notes |
|---|---|---|---|
| `none` (default) | ClusterIP Service only | no | internal/sidecar/DB |
| `ingress` | Service + nginx Ingress + cert-manager TLS | yes (`name.apps.lnvps.tld`) | **http only** (WS rides http → wss/relay/blossom). Operator rejects `ingress` on tcp/udp. |
| `tcp`/`udp` | Service via ingress-controller TCP/UDP ConfigMap (or NodePort) | no (L4) | follow-up; not in MVP |

- MVP supports `none` + `ingress` only (both launch apps are http ingress). `tcp`/`udp` later.
- `app_deployment.hostname` is `Option` precisely because apps without an `ingress` port
  have no public HTTP host — no schema change needed for ingress-less apps.

## Notes

- Deployment `config` stored encrypted (EncryptedString over JSON) so secret env values are
  protected at rest.
- Keep resource sizing in the app's compose for now (flat per-catalog pricing); per-deployment
  resource overrides can come later.
