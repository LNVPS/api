## LNVPS

A VPS hosting platform. Customers provision and renew virtual machines on
Proxmox or LibVirt hypervisors, paying through pluggable payment providers
(Bitcoin Lightning, Bitcoin on-chain, or fiat via Revolut). The backend is a
Rust workspace: a user-facing API + background worker, an admin API, and a set
of supporting services (Nostr identity, AI support agent, health monitoring, a
Kubernetes operator, and an eBPF firewall).

> **Payment providers are configured in the database, not in YAML.** Provider
> credentials are stored per company in `payment_method_config` rows and managed
> through the admin API (`POST`/`PATCH /api/admin/v1/payment_method_configs`).
> Startup fails if no enabled payment provider exists for the default company.
> There are no `lightning:` / `revolut:` YAML sections.

## Features

- **Payments** (providers configured in the DB via the admin API)
  - Lightning via [LND](https://github.com/lightningnetwork/lnd)
  - Bitcoin on-chain deposits (configurable confirmations, address type, account)
  - Fiat via [RevolutPay](https://www.revolut.com/business/revolut-pay/)
  - [LNURL-pay](https://github.com/lnurl/luds/blob/luds/06.md) for VM renewal (scan-to-pay)
  - [Nostr Wallet Connect (NIP-47)](https://github.com/nostr-protocol/nips/blob/master/47.md) for fully automatic renewal
  - Referral program with optional automated commission payouts
- **VM Backends**
  - Proxmox (production-ready)
  - LibVirt (WIP)
- **Network / DNS**
  - [Mikrotik JSON-API](https://help.mikrotik.com/docs/display/ROS/REST+API) — static ARP for anti-spoofing
  - OVH Additional IP virtual MAC management
  - Cloudflare API — forward A/AAAA and reverse PTR records
  - Route-server management — BGP session, tunnel (GRE/VXLAN/WireGuard) and default-route visibility/control across RouterOS and Linux (BIRD/Pathvector over SSH) routers
- **Authentication**
  - [Nostr NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md) HTTP auth
  - OAuth/OIDC login (Google, GitHub, Facebook, Sign in with Apple, generic OIDC)
  - Passwordless WebAuthn / passkeys
  - Stateless session JWTs (shared by OAuth and passkey login)
- **Notifications**
  - Email (SMTP)
  - Nostr NIP-17 direct messages
  - Telegram bot
  - WhatsApp Cloud API
- **Nostr integration**
  - NIP-17 direct-message notifications
  - NIP-05 identity server (`lnvps_nostr`)
  - NIP-47 Nostr Wallet Connect for auto-renewal
  - NIP-90 Data Vending Machine (DVM) for provisioning via Nostr
- **AI support agent** (`lnvps_agent`)
  - Handles customer support requests with an OpenAI-compatible LLM and API-calling tools
  - Email channel (IMAP IDLE inbox watching + SMTP replies) and Nostr kind-1 mention channel
- **Security**
  - XDP eBPF SYN-flood rate limiter with self-upgrading `.deb` daemon (`lnvps_ebpf` + `lnvps_fw_service`)
  - Per-VM firewall rules and default policy (applied on the host)
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
| `lnvps_agent` | `lnvps_agent` | AI support agent — answers support requests via email (IMAP/SMTP) and Nostr kind-1 mentions using an OpenAI-compatible LLM with API-calling tools |
| `lnvps_operator` | `lnvps_operator` | Kubernetes operator — reconciles Nostr domain Ingress objects |
| `lnvps_health` | `lnvps_health` | Network health monitor — TCP MSS/PMTU checks, DNS, Prometheus metrics |
| `lnvps_host_util` | — | Host-side helper utilities packaged for isolated Docker builds |
| `lnvps_e2e` | — | End-to-end integration test suite (spins up API + worker against a real DB/LND) |
| `lnvps_ebpf` | — | XDP eBPF SYN-flood rate limiter (kernel program) |
| `lnvps_fw_common` | — | Shared types between the eBPF datapath and the userspace loader |
| `lnvps_fw_service` | `lnvps_fw_service` | Userspace loader + HTTP control API for the eBPF firewall, with self-upgrade from GitHub `.deb` releases |

> The `lnvps_ebpf`, `lnvps_fw_common`, and `lnvps_fw_service` crates live in the separate `lnvps_fw/` workspace (excluded from the root one) because the eBPF datapath needs its own nightly `rust-src` + `bpf-linker` toolchain and target.

## Building

```bash
cargo build --release -p lnvps_api
cargo build --release -p lnvps_api_admin
cargo build --release -p lnvps_nostr
cargo build --release -p lnvps_agent
cargo build --release -p lnvps_operator
cargo build --release -p lnvps_health
```

The eBPF crates (`lnvps_ebpf`, `lnvps_fw_common`, `lnvps_fw_service`) live in the separate `lnvps_fw/` workspace and require a nightly eBPF toolchain (`rust-src` + `bpf-linker`); build them separately. Tagging a `vX.Y.Z` release builds and attaches a `.deb` of `lnvps_fw_service` to the GitHub release, which running daemons install via their self-upgrade endpoint.

## Running

`lnvps_api` can run as a combined API + worker, or split into separate processes:

```bash
./lnvps_api --config config.yaml              # API + worker (default)
./lnvps_api --config config.yaml --mode api   # HTTP server only
./lnvps_api --config config.yaml --mode worker # background worker only
```

## Development Environment

```bash
docker compose up -d      # reads docker-compose.yaml
# Starts: MariaDB on :3376, Redis on :6398, Krill (RPKI) on :3000
```

## Quick Start

1. Start the dev dependencies (MariaDB, Redis, Krill):

   ```bash
   docker compose up -d
   ```

2. Create a minimal `config.yaml`:

   ```yaml
   db: "mysql://root:root@localhost:3376/lnvps"
   public-url: "http://localhost:8000"
   listen: "0.0.0.0:8000"
   read-only: false
   delete-after: 3

   provisioner:
     proxmox:
       qemu:
         machine: "q35"
         os-type: "l26"
         bridge: "vmbr0"
         cpu: "kvm64"
         kvm: false
         arch: "x86_64"
       ssh:
         key: "/root/.ssh/id_ed25519"
         user: "root"
   ```

3. Run the API + worker:

   ```bash
   cargo run -p lnvps_api -- --config config.yaml
   ```

4. Add a payment provider. Providers (Lightning, on-chain, Revolut) are **not**
   in the YAML — configure at least one via the admin API
   (`POST /api/admin/v1/payment_method_configs`), or startup will refuse to
   provision VMs. See the [config reference](docs/config.md) for details.

## Configuration

Every service is configured with a YAML file (the AI agent reads `settings.yaml`
from its working directory). The snippet above is the bare minimum for
`lnvps_api`. Everything else — auth (OAuth/passkeys), notifications (SMTP, Nostr,
Telegram, WhatsApp), DNS, Redis, field encryption, VAT, captcha — is optional.

See **[docs/config.md](docs/config.md)** for the full reference, including the
standalone `lnvps_nostr`, `lnvps_operator`, `lnvps_health`, and `lnvps_agent`
services.
