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

  # LibVirt (WIP)
  libvirt:
    qemu:
      machine: "q35"
      os-type: "l26"
      bridge: "vmbr0"
      cpu: "kvm64"
      kvm: false
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
  min-payout-sats: 1000        # minimum accrued commission before an auto-payout
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
system-prompt: "You are LNVPS support..."    # optional system prompt override
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
