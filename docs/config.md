# Configuration Reference

Configuration for all LNVPS services. Each service reads a YAML config file
passed via `--config` (the AI agent reads `settings.yaml` from its working
directory). See the [README](../README.md) for a project overview.


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

# Global cap on how far in advance a subscription may be renewed/prepaid.
# Overridden per company (max_prepay_days); 0 there inherits this. Default: 365.
max-prepay-days: 365
```

> **Payment providers** (Lightning node, on-chain wallet, Revolut) are **not**
> configured here — they live in the `payment_method_config` DB table and are
> managed via `POST`/`PATCH /api/admin/v1/payment_method_configs`.

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

  # LibVirt / QEMU-KVM
  libvirt:
    qemu:
      machine: "q35"
      os-type: "l26"
      # Guests are attached to this bridge. See vlan-aware-bridge below if the
      # host record carries a vlan_id.
      bridge: "vmbr0"
      # "host" / "host-passthrough" exposes the physical CPU; anything else is
      # used as an exact custom model.
      cpu: "host"
      kvm: true
      arch: "x86_64"
    # Storage pool caching OS images on the host (default: "default").
    # VM disks are cloned from images in this pool; it may be the same pool the
    # disks live in. The pool's target path must be one AppArmor allows QEMU to
    # read (e.g. under /var/lib/libvirt/images), or guests fail to start with a
    # confusing "Permission denied".
    image-pool: "default"
    # Where the API caches downloaded OS images before uploading them to a host
    # (default: a lnvps-os-images dir under the system temp dir).
    image-cache-dir: "/var/cache/lnvps/os-images"
    # Declares that `bridge` has VLAN filtering enabled (vlan_filtering=1).
    # libvirt accepts a <vlan> tag on any bridge, but a plain Linux bridge
    # silently ignores it and puts the VM on the untagged network, so VM
    # creation fails when a host has a vlan_id and this is not set.
    vlan-aware-bridge: false
    # UEFI secure boot. Requires an OVMF secure-boot firmware on the host and a
    # signed bootloader in the guest image; ordinary cloud images will not boot
    # with it on (default: false).
    secure-boot: false
    # Seconds a graceful ACPI shutdown is given before the VM is powered off by
    # force (default: 60). Without the forced stop, a guest that ignores ACPI
    # would leave `stop_vm` reporting success while it keeps running.
    shutdown-timeout-secs: 60
```

### Session tokens (required for OAuth / passkey login)

```yaml
session:
  # Signs session JWTs, OAuth CSRF state and WebAuthn challenges.
  # Changing it invalidates all outstanding sessions.
  secret: "a-strong-stable-random-string"
  ttl: 2592000                 # session lifetime in seconds (default: 30 days)
```

When omitted, `Bearer` session auth is disabled and only Nostr (NIP-98) auth works.

### OAuth / OIDC login (optional)

```yaml
oauth:
  # Where to send the browser after login (token appended as #token=<jwt>).
  success-redirect: "https://app.example.com/login"
  allowed-redirects:
    - "https://app.example.com"
  providers:
    google:
      type: google
      client-id: "..."
      client-secret: "..."
    github:
      type: github
      client-id: "..."
      client-secret: "..."
    apple:
      type: apple
      client-id: "com.example.service"   # Services ID
      team-id: "TEAMID"
      key-id: "KEYID"
      private-key: |
        -----BEGIN PRIVATE KEY-----
        ...
        -----END PRIVATE KEY-----
    my-oidc:
      type: oidc                            # fully generic provider
      client-id: "..."
      client-secret: "..."
      auth-url: "https://idp.example.com/authorize"
      token-url: "https://idp.example.com/token"
      userinfo-url: "https://idp.example.com/userinfo"
```

Supported `type` values: `google`, `github`, `facebook`, `apple`, `oidc`.
Requires the `session:` block.

### WebAuthn / passkeys (optional)

```yaml
webauthn:
  rp-id: "app.example.com"                  # PERMANENT — changing it kills all passkeys
  rp-origin: "https://app.example.com"
  rp-name: "LNVPS"
  require-resident-key: true                # usernameless "Sign in with a passkey"
```

Requires the `session:` block.

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

### Telegram notifications (optional)

```yaml
telegram:
  token: "123456:bot-token-from-BotFather"
  username: "MyLnvpsBot"       # without @, used for account-linking deep links
```

### WhatsApp notifications (optional)

```yaml
whatsapp:
  access-token: "whatsapp-cloud-api-token"
  phone-number-id: "1234567890"
  api-version: "v21.0"
  message-template: "lnvps_notification"    # approved template, single {{1}} body param
  message-template-lang: "en"
  verify-template: "lnvps_verify"           # approved template for verification codes
  verify-template-lang: "en"
```

### Referral payouts (optional)

```yaml
# Automated Lightning commission payouts are opt-in. Omit this section and
# commission still accrues for manual admin payout, but nothing is paid out
# automatically.
referral:
  min-payout-sats: 1000        # minimum accrued BTC commission before an auto-payout
  min-fiat-payout-sats: 1000   # same for fiat-settled commission, valued at the quote; omit to disable
```

Fiat-settled commission is paid by converting the balance to sats at the rate
quoted when the payout is sent. The payout record keeps both sides — `amount`
in the earned currency, `sent_amount` in BTC, plus the `rate` — so it can be
reconciled without a price feed. Omit `min-fiat-payout-sats` and fiat
commission accrues for manual payout exactly as before.

On-chain referrers settle their fiat balance in the same batched transaction as
their BTC balance: one quote per currency is taken immediately before the
transaction is broadcast, and each row's share of the network fee is converted
back at that same quote. The floor applied to those rows is the higher of
`min-fiat-payout-sats` and `min-onchain-payout-sats`, because an on-chain payout
must also clear the mempool fee it pays.

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

The encryption key can be supplied two ways (the environment variable takes
precedence):

1. **Environment variable** — `LNVPS_ENCRYPTION_KEY`, a hex-encoded 32-byte key
   (64 hex characters):
   ```bash
   export LNVPS_ENCRYPTION_KEY=$(openssl rand -hex 32)
   ```
2. **Key file** — configured in `config.yaml`, used as a fallback when the
   environment variable is not set:
   ```yaml
   encryption:
     key-file: "/etc/lnvps/encryption.key"
     auto-generate: true   # generate key if absent
   ```

When neither is provided, field encryption is disabled and values are
stored/read as plaintext.

Encrypted fields: SSH key material, NWC connection strings, email addresses, host API tokens.

Ciphertexts use the format `ENC1:<key-id>:<base64(nonce||ciphertext)>`. The
embedded key id (first 4 bytes of SHA-256 of the key) identifies which key
encrypted a value, enabling future key rotation. Legacy `ENC:` values written
before key ids are still decrypted transparently.

### Taxes (VAT)

This implements **EU VAT only**. The seller's country is taken from the
company's own VAT number (`tax_id`) when set — that number is the company's VIES
registration and identifies the country it is registered in — otherwise from the
company's `country_code`. EU VAT applies only when that country is in the EU VAT
area; if it is outside the list (e.g. a US company), no tax is applied here —
other tax systems (such as US sales tax) are not handled.

When the seller is in the EU, standard rates for all member states are fetched
from an external source at startup and refreshed daily (cached in-memory by the
shared `VatClient`). The rate applied to a payment is then determined from the
seller's country and the customer:

- **B2B** with a stored (VIES-validated) VAT number: same country as seller →
  domestic VAT; another EU country → reverse charge (0%); outside the EU → out
  of scope (0%).
- **B2C**: place of supply is taken from the self-declared country, falling back
  to the IP-derived country. EU → that country's destination rate (OSS); non-EU
  → out of scope (0%).
- **Undetermined** (no country evidence): the seller's domestic rate is applied
  conservatively when the seller is in the EU, otherwise out of scope.

IP geolocation (for the fallback location signal) requires the optional
`geoip-database` setting pointing at a MaxMind GeoLite2/GeoIP2 Country `.mmdb`.
EU VAT numbers are validated against the VIES service before being stored.

Until the first successful rate refresh (or if the rate source is unreachable),
no rates are known and VAT falls back to 0%.

> **Disclaimer:** This VAT handling is an automated, best-effort determination
> from the available evidence and configuration — it is **not tax or legal
> advice** and makes no guarantee of compliance in any jurisdiction. Rates and
> validation come from third-party sources that may lag official changes. The
> operator is solely responsible for confirming the correct VAT/OSS treatment
> for their business and should have it reviewed by a qualified tax professional.

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

### Live-chat support agent (optional)

AI support agent served in-process by `lnvps_api` over the
`/api/v1/support/chat` websocket. Requires building with the `agent` feature
(`cargo build -p lnvps_api --features agent`); it is off by default. When the
`agent` section is omitted the endpoint still exists but refuses connections.

This is distinct from the standalone [`lnvps_agent`](#lnvps_agent-config)
service, which serves the email and Nostr channels and has its own
`settings.yaml`.

```yaml
agent:
  openai:                                    # OpenAI-compatible LLM (required)
    base-url: "http://localhost:11434/v1"   # Ollama, vLLM, https://api.openai.com/v1, ...
    api-key: "sk-..."                       # optional (not needed for Ollama)
    model: "gpt-4o"
    max-tokens: 2048
  system-prompt: |                           # optional EXTRA instructions (see below)
    Billing questions go to billing@example.com.
  max-message-chars: 4000                    # reject longer single messages (default 4000)
  max-turns-per-connection: 50               # messages allowed per websocket (default 50)
```

**`system-prompt` is optional and additive — not an override.** The agent's
system prompt is compiled into the binary
(`lnvps_agent/src/agent/prompts.rs`, plus the live-chat channel prompt in
`lnvps_agent/src/session.rs`) and is always used. Anything set here is appended
after it, for deployment-specific guidance (tone, escalation wording, house
rules). Leave it unset to run the default agent prompt as-is.

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
transition-reconcile-interval: 5   # sweep this often while a deployment is still moving
error-retry-interval: 30
service-name: "lnvps-nostr"
port-name: "http"
cluster-issuer: "letsencrypt-prod"
ingress-class: "nginx"
app-tls-secret: "apps-wildcard-tls"   # managed apps: shared wildcard cert for the default host
app-cluster-id: 1             # managed apps: the cluster this operator serves
redis: "redis://localhost:6379"   # reconcile on payment instead of at the next poll
annotations:
  nginx.ingress.kubernetes.io/ssl-redirect: "true"
```

`app-tls-secret` is optional and only meaningful alongside `app-cluster-id`. It
names a secret, mirrored into every `app-*` namespace by the cluster (e.g. with
reflector), holding a wildcard certificate for the apps domain. When set, a
deployment's default host serves that certificate and the operator leaves the
cert-manager annotation off its Ingress, so no certificate is issued per
deployment — otherwise every new app spends one of the ACME account's weekly
certificates for the registered domain, which caps how many customers can be
onboarded in a week. Customer custom domains always keep their own certificate:
theirs is only solvable once their DNS points at us. Omit the key to issue one
certificate per deployment.

The cluster-side half — the wildcard `Certificate` and the reflector
annotations that mirror its secret into the deployment namespaces — is in
[`lnvps_operator/apps-wildcard-tls.example.yaml`](../lnvps_operator/apps-wildcard-tls.example.yaml).

Give the shared secret a name of its own rather than `app-tls`: namespaces
provisioned before this setting already hold a per-deployment secret under that
name, and the ingress would serve whichever of the two the mirror had not
overwritten yet.

`transition-reconcile-interval` is the gap between app-deployment sweeps while
at least one deployment on the cluster is `pending` or `deleting`, so a
customer watching a deployment come up sees its status move in seconds rather
than once per `reconcile-interval`. Once every deployment is settled
(`running`, `stopped` or `error`) the loop returns to `reconcile-interval` —
a settled deployment only changes when something acts on it, and that path
reconciles on its own. Values above `reconcile-interval` are capped to it, and values below one second
are raised to it. The fast cadence lasts at most five minutes per deployment: a workload that
never becomes ready reads as `pending` forever, and sweeping the whole cluster
every few seconds for it is load with no end. A deployment that starts
transitioning after that gets its own five minutes, so one wedged app does not
cost the next customer their fast cadence.
Nostr domain reconciliation is unaffected and always runs on
`reconcile-interval`.

`redis` is optional and only meaningful alongside `app-cluster-id`: the operator
consumes `app-cluster-{id}` and reconciles a deployment as soon as its payment
settles, rather than up to `reconcile-interval` later. Point it at the same
Redis the API publishes to. The periodic reconcile remains the backstop, so a
lost trigger is a delay rather than a deployment that never happens; omit the
key to poll only.

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

---

### `lnvps_agent` config

AI support agent. Watches an email inbox (IMAP IDLE) and/or Nostr kind-1 mentions, and answers
support requests using an OpenAI-compatible LLM with tools that call the LNVPS APIs. Config is loaded from a `settings.yaml` file in the working directory; all keys can also be overridden with
`LNVPS_AGENT__*` environment variables.

```yaml
listen: "0.0.0.0:8080"                       # agent HTTP server (default)
admin-api-url: "https://api.example.com"     # LNVPS admin API base URL (required)
user-api-url: "https://api.example.com"      # LNVPS user API base URL (required)
nsec: "nsec1234xxx"                           # signs NIP-98 auth events / Nostr ops (required)
system-prompt: "Billing goes to billing@..." # optional EXTRA instructions, appended to the built-in prompt
conversation-history-path: "/var/lib/lnvps-agent"  # optional history store dir

openai:                                       # OpenAI-compatible LLM (required)
  base-url: "http://localhost:11434/v1"      # e.g. Ollama, or https://api.openai.com/v1
  api-key: "sk-..."                          # optional (not needed for Ollama)
  model: "gpt-4o"
  max-tokens: 2048

email:                                        # email channel (optional)
  imap-server: "imap.gmail.com:993"
  imap-username: "support@example.com"
  imap-password: "app-password"
  imap-mailbox: "INBOX"                       # optional
  smtp-server: "smtp.gmail.com:587"
  smtp-username: "support@example.com"
  smtp-password: "app-password"
  smtp-from: "support@example.com"
  smtp-from-name: "LNVPS Support"            # optional

kind1:                                        # Nostr kind-1 mention channel (optional)
  relays:
    - "wss://relay.damus.io"
  mention-pubkeys: []                          # hex pubkeys to watch; defaults to the bot's own
  poll-interval-secs: 30
```
