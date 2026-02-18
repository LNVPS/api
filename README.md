## LNVPS

A Bitcoin-powered VPS platform. Customers pay with Bitcoin Lightning (or optionally fiat) to provision and renew virtual machines on Proxmox or LibVirt hypervisors.

## Features

- **Payments**
  - Bitcoin Lightning via [LND](https://github.com/lightningnetwork/lnd)
  - Fiat via [RevolutPay](https://www.revolut.com/business/revolut-pay/)
  - [LNURL-pay](https://github.com/lnurl/luds/blob/luds/06.md) for VM renewal (scan-to-pay)
  - [Nostr Wallet Connect (NIP-47)](https://github.com/nostr-protocol/nips/blob/master/47.md) for fully automatic renewal
- **VM Backends**
  - Proxmox (production-ready)
  - LibVirt (WIP)
- **Network / DNS**
  - [Mikrotik JSON-API](https://help.mikrotik.com/docs/display/ROS/REST+API) — static ARP for anti-spoofing
  - OVH Additional IP virtual MAC management
  - Cloudflare API — forward A/AAAA and reverse PTR records
- **Nostr integration**
  - NIP-17 direct-message notifications
  - NIP-05 identity server (`lnvps_nostr`)
  - NIP-47 Nostr Wallet Connect for auto-renewal
  - NIP-90 Data Vending Machine (DVM) for provisioning via Nostr
- **Security**
  - XDP eBPF SYN-flood rate limiter (`lnvps_ebpf` + `lnvps_fw_service`)
  - Database field-level AES-GCM encryption for sensitive columns
  - Cloudflare Turnstile captcha (optional)
- **Observability**
  - VM time-series metrics (CPU, memory, disk, network) from Proxmox RRD
  - Network health monitoring with Prometheus metrics (`lnvps_health`)
  - Grafana dashboard included (`grafana.json`)
- **Other**
  - WebSocket serial console proxy
  - EU VAT validation via VIES
  - Per-country tax rates
  - Multi-region host support
  - Kubernetes operator for Nostr domain Ingress management (`lnvps_operator`)
  - OpenAPI/Swagger generation (`--features openapi`)
  - Redis for shared state and horizontal scaling (optional)

## Workspace Crates

| Crate | Binary | Description |
|---|---|---|
| `lnvps_api` | `lnvps_api` | Main user-facing HTTP API + background worker |
| `lnvps_api_admin` | `lnvps_api_admin` | Admin HTTP API with privileged operations |
| `lnvps_api_common` | — | Shared types, pricing engine, exchange rates, Redis queue, NIP-98 auth |
| `lnvps_db` | — | Database abstraction (MySQL/SQLx), migrations, field-level encryption |
| `lnvps_nostr` | `lnvps_nostr` | Standalone NIP-05 identity server (`/.well-known/nostr.json`) |
| `lnvps_operator` | `lnvps_operator` | Kubernetes operator — reconciles Nostr domain Ingress objects |
| `lnvps_health` | `lnvps_health` | Network health monitor — TCP MSS/PMTU checks, DNS, Prometheus metrics |
| `lnvps_ebpf` | — | XDP eBPF SYN-flood rate limiter (kernel program) |
| `lnvps_fw_service` | `lnvps_fw_service` | Userspace loader for the eBPF firewall |

## Building

```bash
cargo build --release -p lnvps_api
cargo build --release -p lnvps_api_admin
cargo build --release -p lnvps_nostr
cargo build --release -p lnvps_operator
cargo build --release -p lnvps_health
```

The eBPF crates (`lnvps_ebpf`, `lnvps_fw_service`) are not part of the main workspace and require a nightly eBPF toolchain; build them separately.

## Running

`lnvps_api` can run as a combined API + worker, or split into separate processes:

```bash
./lnvps_api --config config.yaml              # API + worker (default)
./lnvps_api --config config.yaml --mode api   # HTTP server only
./lnvps_api --config config.yaml --mode worker # background worker only
```

## Development Environment

```bash
docker compose up -d
# Starts: MariaDB on :3376, Redis on :6398, Krill (RPKI) on :3000
```

## Config Reference

### Core (`lnvps_api`)

```yaml
# MySQL connection string (required)
db: "mysql://root:root@localhost:3376/lnvps"

# Public base URL used in webhook callbacks (required)
public-url: "https://api.example.com"

# HTTP listen address (default: 0.0.0.0:8000)
listen: "0.0.0.0:8000"

# Days after VM expiry before hard deletion
delete-after: 3

# Prevent VM creation/deletion
read-only: false
```

### Lightning node (exactly one required)

```yaml
lightning:
  lnd:
    url: "https://127.0.0.1:10003"
    cert: "$HOME/.lnd/tls.cert"
    macaroon: "$HOME/.lnd/data/chain/bitcoin/mainnet/admin.macaroon"
```

### Provisioner (VM backend)

```yaml
provisioner:
  proxmox:
    qemu:
      machine: "q35"
      os-type: "l26"
      bridge: "vmbr0"
      cpu: "kvm64"
      kvm: false
      arch: "x86_64"
      # Per-NIC Proxmox firewall (optional)
      firewall-config:
        dhcp: true
        enable: true
        ip-filter: true
        mac-filter: true
        ndp: true
        policy-in: "DROP"    # ACCEPT | REJECT | DROP
        policy-out: "ACCEPT"
    # SSH access for host-side CLI commands (optional)
    ssh:
      key: "/root/.ssh/id_ed25519"
      user: "root"
    # MAC prefix for generated NICs (default: bc:24:11)
    mac-prefix: "bc:24:11"

  # LibVirt (WIP)
  libvirt:
    qemu:
      machine: "q35"
      os-type: "l26"
      bridge: "vmbr0"
      cpu: "kvm64"
      kvm: false
```

### Revolut fiat payments (optional)

```yaml
revolut:
  url: "https://merchant.revolut.com"
  token: "my-revolut-api-token"
  api-version: "2024-09-01"
  public-key: "my-revolut-public-key"
```

### SMTP notifications (optional)

```yaml
smtp:
  admin: 1                    # user ID to receive system alerts (optional)
  server: "smtp.gmail.com"
  from: "LNVPS <no-reply@example.com>"   # optional
  username: "no-reply@example.com"
  password: "mypassword123"
```

### Nostr notifications — NIP-17 (optional)

```yaml
nostr:
  relays:
    - "wss://relay.snort.social"
    - "wss://relay.damus.io"
    - "wss://nos.lol"
  nsec: "nsec1234xxx"
```

### DNS — Cloudflare (optional)

```yaml
dns:
  # Zone ID for forward A/AAAA records (created as vm-<vmid>.<zone>)
  forward-zone-id: "my-cloudflare-zone-id"
  api:
    cloudflare:
      token: "my-api-token"
```

### Redis (optional — enables horizontal scaling)

```yaml
redis:
  url: "redis://localhost:6379"
```

When configured, exchange rates, VM state cache, and the work queue all use Redis.

### Database field encryption (optional)

```yaml
encryption:
  key-file: "/etc/lnvps/encryption.key"
  auto-generate: true   # generate key if absent
```

Encrypted fields: SSH key material, NWC connection strings, email addresses, host API tokens.

### Taxes

```yaml
# ISO 3166-1 alpha-2 country codes, values are whole-number percentages
tax-rate:
  IE: 23
  US: 15
```

Taxes are applied based on the user's specified country. EU VAT numbers are validated against the VIES service before being stored.

### Nostr address host (optional)

```yaml
# Enables NIP-05 routing under this hostname
nostr-address-host: "nostr.example.com"
```

### Captcha (optional)

```yaml
captcha:
  turnstile:
    secret-key: "my-cloudflare-turnstile-secret"
```

---

### `lnvps_nostr` config

Standalone NIP-05 identity server. Reads domain/handle records from the shared database.

```yaml
db: "mysql://root:root@localhost:3376/lnvps"
listen: "0.0.0.0:8001"
```

---

### `lnvps_operator` config (Kubernetes)

Reconciles Kubernetes `Ingress` and cert-manager `Certificate` objects for Nostr domains.

```yaml
db: "mysql://root:root@localhost:3376/lnvps"
namespace: "default"
reconcile-interval: 60        # seconds
error-retry-interval: 30
service-name: "lnvps-nostr"
port-name: "http"
cluster-issuer: "letsencrypt-prod"
ingress-class: "nginx"
annotations:
  nginx.ingress.kubernetes.io/ssl-redirect: "true"
```

---

### `lnvps_health` config

Network health monitoring daemon. Runs TCP MSS/PMTU probes, DNS checks, exposes Prometheus metrics, and sends email alerts.

```yaml
interval-secs: 600           # check interval
alert-cooldown-secs: 3600    # minimum time between repeated alerts

metrics:
  enabled: true
  bind: "127.0.0.1:9090"    # Prometheus scrape endpoint (/metrics)

smtp:
  host: "smtp.gmail.com"
  port: 587
  username: "alerts@example.com"
  password: "password"
  from: "alerts@example.com"
  to: "admin@example.com"

mss-checks:
  - name: "My Server"
    host: "server1.example.com"
    port: 443
    expected-mss: 1460
    expected-mss-v6: 1440    # optional, defaults to expected-mss - 20
```

```bash
./lnvps_health --config config.yaml         # run continuously
./lnvps_health --config config.yaml --once  # run once and exit
```
