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
docker build -f lnvps_operator/Dockerfile -t lnvps-operator:latest .
```

### 2. Update Configuration

Edit the ConfigMap in `k8s-deployment.yaml`:

```yaml
data:
  config.yaml: |
    # Update the database connection string
    db: "mysql://username:password@your-mysql-host:3306/lnvps"
    
    # Set the namespace where your nostr service runs
    namespace: "your-namespace"
    
    # Configure your service backend
    service-name: "your-lnvps-nostr-service"
    port-name: "http"
    
    # Set your cert-manager cluster issuer
    cluster-issuer: "your-cluster-issuer"
```

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

The operator requires these Kubernetes permissions:

- **networking.k8s.io/ingresses**: `get`, `list`, `watch`, `create`, `update`, `patch`, `delete`
- **core/events**: `create`, `patch` (for event logging)

These are automatically created by the deployment manifest.

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
- Database credentials should be stored in Secrets
- Network policies can restrict operator traffic
- Consider using Pod Security Standards/Admission Controllers