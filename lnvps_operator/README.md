# LNVPS Kubernetes Operator

A Kubernetes operator that automatically manages Ingress resources for LNVPS nostr domains with TLS certificates via cert-manager.

## Features

- **Single Ingress Management**: Creates one unified Ingress resource for all enabled nostr domains
- **Automatic TLS**: Integrates with cert-manager for automatic TLS certificate generation
- **Configurable**: Supports custom ingress classes, annotations, and service backends
- **Database Integration**: Uses the LNVPS database to discover enabled nostr domains
- **Periodic Reconciliation**: Keeps Ingress resources in sync with database changes

## Quick Start

### Prerequisites

- Kubernetes cluster with Ingress controller (e.g., nginx-ingress)
- cert-manager installed for TLS certificates
- Access to LNVPS MySQL database
- Docker for building the operator image

### 1. Build the Operator Image

```bash
# From the project root
docker buildx bake lnvps-operator   # shared root Dockerfile, target lnvps-operator
```

### 2. Update Configuration

Edit the ConfigMap in `k8s-minimal.yaml`:

```yaml
data:
  config.yaml: |
    # Set the namespace where your nostr service runs
    namespace: "your-namespace"
    
    # Configure your service backend
    service-name: "your-lnvps-nostr-service"
    port-name: "http"
    
    # Set your cert-manager cluster issuer
    cluster-issuer: "your-cluster-issuer"
```

The database connection string does not go in the ConfigMap. See
[Database user](#database-user).

### 3. Deploy the Operator

```bash
kubectl apply -f lnvps_operator/k8s-deployment.yaml
```

### 4. Verify Deployment

```bash
# Check if operator is running
kubectl get pods -n lnvps-system

# Check operator logs
kubectl logs -n lnvps-system deployment/lnvps-operator

# Check if Ingress is created (when domains exist)
kubectl get ingress -n your-namespace
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `db` | string | **required** | MySQL connection string |
| `namespace` | string | `"default"` | Kubernetes namespace to manage |
| `reconcile-interval` | number | `60` | Seconds between reconciliation runs |
| `error-retry-interval` | number | `30` | Seconds to wait before retrying on errors |
| `verbose` | boolean | `false` | Enable verbose logging |
| `service-name` | string | `"lnvps-nostr"` | Name of the service backend |
| `port-name` | string | `"http"` | Port name on the service |
| `cluster-issuer` | string | `"letsencrypt-prod"` | cert-manager ClusterIssuer name |
| `ingress-class` | string | `"nginx"` | Ingress class name |
| `annotations` | object | `{}` | Additional ingress annotations |
| `prometheus.url` | string | unset | Prometheus HTTP API to read deployment CPU/memory/volume usage from. Omit to collect no usage |
| `prometheus.timeout-seconds` | number | `10` | Per-query timeout; collection is best-effort and never blocks a reconcile |

Usage collection needs a Prometheus scraping cAdvisor (`container_cpu_usage_seconds_total`,
`container_memory_working_set_bytes`) and, for volume usage, the kubelet
(`kubelet_volume_stats_used_bytes`). Without the kubelet series, CPU and memory are still
reported and `storage_bytes` is null.

## Example Generated Ingress

The operator creates a single Ingress resource like this:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: lnvps-nostr-domains
  namespace: default
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/ssl-redirect: "false"
    # Plus any custom annotations from config
spec:
  tls:
  - hosts:
    - domain1.example.com
    - domain2.example.com
    - domain3.example.com
    secretName: lnvps-nostr-tls
  rules:
  - host: domain1.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: lnvps-nostr
            port:
              name: http
  # ... rules for other domains
```

## RBAC Permissions

The ClusterRole in [`k8s-minimal.yaml`](k8s-minimal.yaml) is the list, and each
rule there is annotated with the call that needs it. Every verb is one the
reconcile loop issues: `create` accompanies `patch` because server-side apply
creates the object on the first pass, and the operator holds no watches, so
`watch` is granted nowhere.

### Secret access is scoped per namespace

The operator holds no cluster-wide grant on Secrets. `lnvps-operator-appns` is a
second ClusterRole carrying the secret verbs, and it is never bound
cluster-wide: as the operator creates each `app-N` namespace it writes a
RoleBinding to it in that namespace, so its token reads only namespaces it
provisioned — not `kube-system`, not cert-manager's, not another deployment's
TLS keys.

Writing that binding is allowed by two narrow rules rather than by holding the
secret verbs: `rolebindings: create, patch`, and `bind` on
`lnvps-operator-appns` by name. `bind` exists for exactly this — it permits a
binding to a named role without holding that role's permissions.

The subject comes from the downward API (`LNVPS_OPERATOR_NAMESPACE`,
`LNVPS_OPERATOR_SERVICE_ACCOUNT`). With either missing the operator writes no
binding at all and relies on whatever grant it already has, which is what makes
the rollout survivable.

**Rollout is three ordered steps, and the manifest is the end state:**

1. Apply `lnvps-operator-appns` and add the `rolebindings` + `bind` rules to
   `lnvps-operator`, *keeping* its existing `secrets` rule.
2. Roll the new image with the two downward-API env vars. Each namespace gets
   its binding on the next reconcile pass.
3. Remove the `secrets` rule from `lnvps-operator`.

Doing 3 before 2 leaves the operator unable to read `generated`, which now fails
the reconcile loudly rather than regenerating every password. Namespaces created
before step 2 are repaired by the pass that binds them; the binding is deleted
with its namespace, so nothing outlives a deployment.

## Runtime hardening

The image runs as uid/gid `65534` and the Deployment enforces
`runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation:
false` and `capabilities: drop: ["ALL"]`. The operator writes nothing to its own
filesystem: the config is a read-only ConfigMap mount, and everything else it
creates lives in the Kubernetes API or the database.

One consequence for the field-encryption key: `encryption.auto-generate` cannot
work on a read-only root filesystem, and a generated key would not match the
API's in any case. Supply the key through `LNVPS_ENCRYPTION_KEY` (as the
manifest does) or mount it as a read-only Secret volume and point
`encryption.key-file` at it.

## Database user

The operator connects with its own MySQL user, not root, and reads the DSN from
the `LNVPS_DATABASE_URL` environment variable (a Secret in the manifest). The
config file's `db` key is still honoured as a fallback for local runs; the
environment wins when both are set.

It reads nostr domains, apps, app clusters, app deployments and the
subscription rows that decide whether a deployment is paid for, and it writes
to exactly one table: `app_deployment`. No inserts, no deletes, and it never
runs migrations, so it needs no DDL:

```sql
CREATE USER 'lnvps_operator'@'%' IDENTIFIED BY '<password>';
GRANT SELECT ON lnvps.* TO 'lnvps_operator'@'%';
GRANT UPDATE ON lnvps.app_deployment TO 'lnvps_operator'@'%';
```

```bash
kubectl -n lnvps-system create secret generic lnvps-operator-db \
  --from-literal=url='mysql://lnvps_operator:<password>@mysql-service:3306/lnvps'
```

Create the Secret before applying the Deployment. The `secretKeyRef` is
required, so a container scheduled without it sits in
`CreateContainerConfigError` and never starts.

A schema change that makes the operator write another table, insert or delete
needs the grant widened first, or the reconcile fails at that statement.

## Monitoring

The deployment includes:

- **Liveness/Readiness Probes**: Basic process health checks
- **Resource Limits**: CPU and memory constraints
- **Security Context**: Non-root execution, read-only filesystem
- **Metrics Service**: Placeholder for Prometheus metrics (port 8080)

## Troubleshooting

### Operator Not Starting

```bash
# Check pod status
kubectl get pods -n lnvps-system

# Check logs for errors
kubectl logs -n lnvps-system deployment/lnvps-operator
```

### Database Connection Issues

```bash
# Test database connectivity from cluster
kubectl run mysql-test --rm -it --image=mysql:8 -- \
  mysql -h your-mysql-host -u username -p database_name
```

### RBAC Permission Issues

```bash
# Check if ServiceAccount exists
kubectl get sa lnvps-operator -n lnvps-system

# Check ClusterRoleBinding
kubectl get clusterrolebinding lnvps-operator
```

### No Ingress Created

1. Verify nostr domains are enabled in the database:
   ```sql
   SELECT * FROM nostr_domain WHERE enabled = 1;
   ```

2. Check operator logs for database query issues
3. Ensure the target namespace exists

## Development

### Local Testing

```bash
# Build and test locally
cargo build -p lnvps_operator

# Run with custom config
./target/debug/lnvps_operator --config /path/to/config.yaml
```

### Custom Annotations

Add any nginx-ingress or other annotations in the config:

```yaml
annotations:
  nginx.ingress.kubernetes.io/rate-limit: "100"
  nginx.ingress.kubernetes.io/cors-allow-origin: "*"
  nginx.ingress.kubernetes.io/configuration-snippet: |
    more_set_headers "X-Frame-Options: SAMEORIGIN";
```

## Security Considerations

- The operator runs as non-root user (UID 65534)
- Uses read-only root filesystem
- The database DSN is read from a Secret, never the ConfigMap
- Network policies can restrict operator traffic
- Consider using Pod Security Standards/Admission Controllers