# LNVPS API Documentation for TypeScript Frontend Development

This document provides comprehensive API specifications for generating TypeScript frontend code that interacts with the LNVPS Lightning Network VPS service.

## Base Configuration

- **Base URL**: `https://api.lnvps.com` (replace with actual production URL)
- **Authentication**: either NIP-98 (Nostr) **or** an OAuth session token (see [Authentication](#authentication-types)) on all authenticated endpoints
- **Content Type**: `application/json`
- **Error Response Format**: `{ "error": "Error message" }`
- **Success Response Format**: `{ "data": <response_data> }`

## Enums

**DiskType**: `"hdd"`, `"ssd"`
**DiskInterface**: `"sata"`, `"scsi"`, `"pcie"`
**VmState**: `"unknown"`, `"running"`, `"stopped"`, `"creating"`
**CostPlanIntervalType**: `"day"`, `"month"`, `"year"`
**OsDistribution**: `"ubuntu"`, `"debian"`, `"centos"`, `"fedora"`, `"freebsd"`, `"opensuse"`, `"archlinux"`,
`"redhatenterprise"`, `"almalinux"`, `"rockylinux"`, `"alpine"`, `"nixos"`, `"openbsd"`, `"netbsd"`, `"gentoo"`,
`"voidlinux"`
**CpuMfg**: `"unknown"`, `"intel"`, `"amd"`, `"apple"`, `"nvidia"`, `"arm"`
**CpuArch**: `"unknown"`, `"x86_64"`, `"arm64"`
**CpuFeature**: `"SSE"`, `"SSE2"`, `"SSE3"`, `"SSSE3"`, `"SSE4_1"`, `"SSE4_2"`, `"AVX"`, `"AVX2"`, `"FMA"`, `"F16C"`,
`"AVX512F"`, `"AVX512VNNI"`, `"AVX512BF16"`, `"AVXVNNI"`, `"NEON"`, `"SVE"`, `"SVE2"`, `"AES"`, `"SHA"`, `"SHA512"`,
`"PCLMULQDQ"`, `"RNG"`, `"GFNI"`, `"VAES"`, `"VPCLMULQDQ"`, `"VMX"`, `"NestedVirt"`, `"AMX"`, `"SME"`, `"SGX"`, `"SEV"`,
`"TDX"`, `"EncodeH264"`, `"EncodeHEVC"`, `"EncodeAV1"`, `"EncodeVP9"`, `"EncodeJPEG"`, `"DecodeH264"`, `"DecodeHEVC"`,
`"DecodeAV1"`, `"DecodeVP9"`, `"DecodeJPEG"`, `"DecodeMPEG2"`, `"DecodeVC1"`, `"VideoScaling"`, `"VideoDeinterlace"`,
`"VideoCSC"`, `"VideoComposition"`

## Authentication Types

Every authenticated endpoint accepts **either** of two `Authorization` schemes.
You never mix them on a single request — pick whichever the logged-in user has.

```typescript
interface AuthHeaders {
  // Nostr accounts: "Nostr <base64 NIP-98 event>"
  // OAuth accounts: "Bearer <session JWT>"
  'Authorization': string;
  'Content-Type': 'application/json';
}
```

- **Nostr (NIP-98)** — `Authorization: Nostr <base64-event>`. Unchanged; used by
  users who log in with a Nostr key.
- **OAuth session token** — `Authorization: Bearer <jwt>`. Obtained from the
  OAuth login flow below. The token is opaque to the frontend: store it and
  echo it back on every request.

### OAuth login flow (Google / GitHub / Facebook / Apple)

External login is a full-page browser redirect through the provider, ending back
at your app with a session token. The frontend never sees the provider or the
authorization code — only the final token.

```
[React] click "Login with Google"
   → window.location = `${API}/api/v1/oauth/google/login`
       → provider consent screen
           → provider redirects to `${API}/api/v1/oauth/google/callback`  (registered with the provider, NOT your app)
               → API exchanges the code, creates/updates the account, issues a JWT
                   → 302 to your configured success-redirect:  `https://app.example.com/oauth/complete#token=<jwt>`
```

The token is delivered in the URL **fragment** (`#token=…`) so it is never sent
to or logged by any server. Provider tags are `google`, `github`, `facebook`,
`apple` (whichever are enabled server-side).

**1. Start login** (plain navigation, not `fetch`):

```typescript
const API = import.meta.env.VITE_API_URL;
function startLogin(provider: 'google' | 'github' | 'facebook' | 'apple') {
  window.location.href = `${API}/api/v1/oauth/${provider}/login`;
}
```

**Per-request return URL (optional).** Pass `?redirect=<url>` on the login
endpoint to override the server's configured `success-redirect` for this login
only — useful in local development so the browser lands back on your dev origin:

```typescript
function startLogin(provider: string) {
  const redirect = `${window.location.origin}/oauth/complete`;
  window.location.href =
    `${API}/api/v1/oauth/${provider}/login?redirect=${encodeURIComponent(redirect)}`;
}
```

The requested URL is validated server-side against an allowlist and, once
accepted, round-tripped through the signed `state` so it cannot be tampered
with. A URL is accepted when its host is `localhost` (always allowed, for local
dev), or when it exactly equals / extends at a path boundary the configured
`success-redirect` or an entry in `allowed-redirects`. Anything else is rejected
with `400` (this prevents an open-redirect / token-theft hole where
`?redirect=https://evil.com` would leak the JWT). The provider-registered
`/callback` URL is never affected.

Server config (`config.yaml`) — allow a dev origin in addition to the default
success redirect:

```yaml
oauth:
  success-redirect: "https://app.lnvps.com/oauth/complete"
  allowed-redirects:
    - "http://localhost:3000"
  providers:
    # ...
```

**2. Handle the landing route** (`/oauth/complete`): read the fragment, store the
token, scrub the URL:

```typescript
const params = new URLSearchParams(window.location.hash.slice(1)); // drop '#'
const token = params.get('token');
if (token) {
  localStorage.setItem('session_token', token);
  window.history.replaceState({}, '', window.location.pathname); // remove token from history
  // navigate to your authenticated area
}
```

**3. Call authenticated endpoints** with the token:

```typescript
fetch(`${API}/api/v1/account`, {
  headers: { Authorization: `Bearer ${localStorage.getItem('session_token')}` },
});
```

> If the server is configured **without** a `success-redirect`, the callback
> instead returns JSON `{ "data": { "token": string, "token_type": "Bearer",
> "expires_in": number } }` — suitable for a popup/`postMessage` flow. The
> redirect-fragment flow above is recommended for a standard SPA.

On first OAuth login the provider's email is synced into the account (and marked
verified when the provider asserts it), so `AccountInfo.email` /
`email_verified` may already be populated for these users.

### Passkey (WebAuthn) login

Passwordless login with a platform passkey (Face ID / Touch ID / Windows Hello)
or a security key. Like OAuth, a passkey **is** the account (`account_type` is
`oauth`-style synthetic — see the note below) and login yields the same
`Bearer` session token. Unlike OAuth this is a **`fetch`/XHR flow** driven by the
browser's `navigator.credentials` API, not a redirect.

Each ceremony is two calls — `start` returns a challenge plus an opaque signed
`state`; you run the WebAuthn browser API, then post the result back with that
same `state` to `finish`, which returns the session token.

**Register (new account):**

```typescript
import { startRegistration } from '@simplewebauthn/browser';

// 1. begin
const start = await fetch(`${API}/api/v1/webauthn/register/start`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ name: 'my device' }), // optional label
}).then(r => r.json());
// start.data = { challenge, state }

// 2. run the authenticator (challenge.publicKey per the WebAuthn spec)
const credential = await startRegistration(start.data.challenge.publicKey);

// 3. finish -> session token
const done = await fetch(`${API}/api/v1/webauthn/register/finish`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ state: start.data.state, credential }),
}).then(r => r.json());
localStorage.setItem('session_token', done.data.token); // { token, token_type, expires_in }
```

**Login (existing passkey, usernameless):**

```typescript
import { startAuthentication } from '@simplewebauthn/browser';

const start = await fetch(`${API}/api/v1/webauthn/login/start`, { method: 'POST' })
  .then(r => r.json()); // { challenge, state }
const credential = await startAuthentication(start.data.challenge.publicKey);
const done = await fetch(`${API}/api/v1/webauthn/login/finish`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ state: start.data.state, credential }),
}).then(r => r.json());
localStorage.setItem('session_token', done.data.token);
```

The signed `state` must be round-tripped unchanged and expires after ~5 minutes.
Passkey accounts are Nostr-less exactly like OAuth accounts — hide npub / NIP-17
UI for them (they are reported with `account_type` distinct from `nostr`).

## Core Data Types

### User Account

```typescript
interface AccountInfo {
  email?: string;
  email_verified?: boolean; // Present when email is set; true if email has been verified
  account_type: 'nostr' | 'oauth' | 'webauthn'; // Read-only. Only 'nostr' has a usable Nostr key — hide npub / NIP-17 UI for 'oauth' and 'webauthn'. Enabling contact_nip17 for a non-'nostr' account is rejected.
  contact_nip17: boolean;
  contact_email: boolean;
  country_code?: string; // ISO 3166-1 alpha-3 country code
  name?: string;
  address_1?: string;
  address_2?: string;
  city?: string;
  state?: string;
  postcode?: string;
  tax_id?: string;
  // Note: NWC wallets are no longer stored on the account. Add one via
  // POST /api/v1/payment-methods (see "Saved Payment Methods").
  tax?: AccountTaxInfo[]; // Read-only, GET only: tax (VAT) applied to payments, per seller company. Ignored on PATCH.
}

interface AccountTaxInfo {
  company_id: number;
  company_name: string;
  rate: number; // VAT rate as a percentage, e.g. 23.0 for 23%
  country_code?: string; // Place-of-supply country (ISO 3166-1 alpha-3), if determined
  treatment: string; // "domestic" | "oss_b2c" | "reverse_charge" | "out_of_scope" | "undetermined_default"
}
```

### VM Status

```typescript
interface VmStatus {
  id: number;
  created: string; // ISO 8601 datetime
  expires?: string; // ISO 8601 datetime — null/omitted for VMs not yet paid
  mac_address: string;
  image: VmOsImage;
  template: VmTemplate;
  ssh_key: UserSshKey;
  ip_assignments: VmIpAssignment[];
  status: VmRunningState; // Full running state with metrics; check status.state for the current lifecycle state
  auto_renewal_enabled: boolean; // Whether automatic renewal via NWC is enabled for this VM
  deleting_on?: string; // ISO 8601 datetime — date the VM will be deleted if not renewed (expiry + dynamic grace period); null/omitted for VMs not yet paid
  subscription_id?: number; // The subscription this VM is billed under; renew via /api/v1/subscriptions/{id}/renew. null/omitted if never paid
  host_sunset_date?: string; // ISO 8601 datetime — set when the VM's host is being decommissioned; migrate before this date. Renewals are blocked once expires reaches it. Omitted when the host is not being sunset
  max_prepay_days: number; // Max days this VM may be prepaid/renewed in advance. A renewal is rejected once it would push `expires` beyond now + max_prepay_days; cap the renewal interval selector accordingly
  cpu_arch?: string; // CPU architecture of the host this VM runs on ("x86_64" | "arm64"), from the host record. Unlike template.cpu_arch (an optional constraint) this is present whenever the host arch is known; use it to always pass ?arch= when listing OS images for a reinstall. Omitted when unknown
}

interface VmRunningState {
  timestamp: number;  // Unix timestamp when state was collected
  state: VmRunningStateKind;
  cpu_usage: number;  // CPU usage percentage (0.0–100.0)
  mem_usage: number;  // Memory usage percentage (0.0–100.0)
  uptime: number;     // Uptime in seconds
  net_in: number;     // Network bytes received
  net_out: number;    // Network bytes transmitted
  disk_write: number; // Disk bytes written
  disk_read: number;  // Disk bytes read
}

// state field values:
// "unknown"  — State not yet known (default before first poll)
// "running"  — VM is running normally
// "stopped"  — VM is shut down
// "creating" — First payment received; VM is being provisioned on the host for the first time
type VmRunningStateKind = 'unknown' | 'running' | 'stopped' | 'creating';
```

### VM Template

```typescript
interface VmTemplate {
  id: number;
  name: string;
  created: string; // ISO 8601 datetime
  expires?: string; // ISO 8601 datetime
  cpu: number; // Number of CPU cores
  cpu_mfg?: string; // CPU manufacturer (e.g. "intel", "amd"; omitted if unknown)
  cpu_arch?: string; // CPU architecture (e.g. "x86_64", "arm64"; omitted if unknown)
  cpu_features?: string[]; // Required CPU features (e.g. ["AVX2", "AES"]; omitted if empty)
  memory: number; // Memory in bytes
  disk_size: number; // Disk size in bytes
  disk_type: 'hdd' | 'ssd';
  disk_interface: 'sata' | 'scsi' | 'pcie';
  cost_plan: VmCostPlan;
  region: VmHostRegion;
}

interface VmCostPlan {
  id: number;
  name: string;
  currency: 'BTC' | 'EUR' | 'USD';
  amount: number; // Price amount in smallest currency units (cents for fiat, millisats for BTC)
  other_price: Price[]; // Alternative currency prices
  interval_amount: number;
  interval_type: 'day' | 'month' | 'year';
}

interface Price {
  currency: 'BTC' | 'EUR' | 'USD';
  amount: number; // Amount in smallest currency units (cents for fiat, millisats for BTC)
}

interface CustomVmPrice {
  currency: 'BTC' | 'EUR' | 'USD';
  amount: number; // Base price in smallest currency units
  other_price: Price[]; // The same price converted to other supported currencies
}

interface VmHostRegion {
  id: number;
  name: string;
  company_id: number; // Seller company id; match against account.tax[].company_id for the applicable VAT rate
}
```

### Custom VM Configuration

```typescript
interface CustomVmRequest {
  pricing_id: number;
  cpu: number; // Number of CPU cores
  memory: number; // Memory in bytes
  disk: number; // Disk size in bytes
  disk_type: 'hdd' | 'ssd';
  disk_interface: 'sata' | 'scsi' | 'pcie';
}

interface CustomVmOrder extends CustomVmRequest {
  image_id: number;
  ssh_key_id: number;
  ref_code?: string;
}

interface CustomTemplateParams {
  id: number;
  name: string;
  region: VmHostRegion;
  cpu_mfg?: string; // CPU manufacturer (e.g. "intel", "amd"; omitted if unknown)
  cpu_arch?: string; // CPU architecture (e.g. "x86_64", "arm64"; omitted if unknown)
  cpu_features?: string[]; // Required CPU features (e.g. ["AVX2", "AES"]; omitted if empty)
  max_cpu: number;
  min_cpu: number;
  min_memory: number; // In bytes
  max_memory: number; // In bytes
  disks: CustomTemplateDiskParam[];
}

interface CustomTemplateDiskParam {
  min_disk: number; // In bytes
  max_disk: number; // In bytes
  disk_type: 'hdd' | 'ssd';
  disk_interface: 'sata' | 'scsi' | 'pcie';
}
```

### OS Images and SSH Keys

```typescript
interface VmOsImage {
  id: number;
  distribution: 'ubuntu' | 'debian' | 'centos' | 'fedora' | 'freebsd' | 'opensuse' | 'archlinux' | 'redhatenterprise' | 'almalinux' | 'rockylinux' | 'alpine' | 'nixos' | 'openbsd' | 'netbsd' | 'gentoo' | 'voidlinux';
  flavour: string;
  version: string;
  release_date: string; // ISO 8601 datetime
  cpu_arch?: string; // CPU architecture (e.g. "x86_64", "arm64"; omitted if unspecified)
  default_username?: string;
  popularity: number; // fraction (0.0–1.0) of active VMs using this image
}

interface UserSshKey {
  id: number;
  name: string;
  created: string; // ISO 8601 datetime
}

interface CreateSshKey {
  name: string;
  key_data: string; // SSH public key content
}
```

### IP Assignments and Networking

```typescript
interface VmIpAssignment {
  id: number;
  ip: string; // IP address with CIDR notation
  gateway: string;
  forward_dns?: string;
  reverse_dns?: string;
}
```

### Payments

```typescript
interface VmPayment {
  id: string; // Hex-encoded payment ID
  vm_id: number;
  created: string; // ISO 8601 datetime
  expires: string; // ISO 8601 datetime
  amount: number; // Amount in smallest currency unit (cents for fiat, millisats for BTC)
  tax: number; // Tax amount in smallest currency unit (cents for fiat, millisats for BTC)
  processing_fee: number; // Processing fee in smallest currency unit (cents for fiat, millisats for BTC)
  currency: string;
  is_paid: boolean;
  paid_at?: string; // ISO 8601 datetime when payment was completed (only present when is_paid is true)
  data: PaymentData;
  time: number; // Seconds this payment adds to VM expiry
  is_upgrade: boolean;
  upgrade_params?: string; // JSON-encoded upgrade parameters (only present for upgrade payments)
}

type PaymentData = 
  | { lightning: string } // Lightning Network invoice
  | { onchain: { address: string; outpoint?: string } } // On-chain Bitcoin receive address (BTC only). `outpoint` ("{txid}:{vout}") is set as soon as a deposit is seen in the mempool (0-conf), before it confirms, so the UI can show "received, waiting for confirmation"; absent until a deposit is detected. Confirmed once is_paid is true
  | { revolut: { token: string } } // Revolut payment token
  | { stripe: { session_id: string } }; // Stripe checkout session

interface PaymentType {
  type: 'new' | 'renew' | 'upgrade';
}

interface PaymentMethod {
  name: 'lightning' | 'onchain' | 'revolut' | 'paypal' | 'stripe' | 'nwc' | 'lnurl';
  metadata: Record<string, string>;
  currencies: ('BTC' | 'EUR' | 'USD')[];
  processing_fee_rate?: number; // Percentage rate (e.g., 1.0 for 1%)
  processing_fee_base?: number; // Base amount in smallest currency units (cents for fiat, millisats for BTC)
  processing_fee_currency?: string; // Currency for the base fee (e.g., "EUR")
  min_amount?: number; // Minimum processable amount in smallest currency units; payments below this are rejected for this method
  min_amount_currency?: string; // Currency for min_amount (e.g., "EUR")
}
```

### Subscriptions

```typescript
interface Subscription {
  id: number;
  name: string;
  description?: string;
  created: string; // ISO 8601 datetime
  expires?: string; // ISO 8601 datetime
  is_active: boolean;
  auto_renewal_enabled: boolean;
  line_items: SubscriptionLineItem[]; // Services included in this subscription
}

interface SubscriptionLineItem {
  id: number;
  subscription_id: number;
  name: string;
  description?: string;
  price: Price; // Recurring cost per billing cycle
  setup_fee: Price; // One-time setup fee
  configuration?: object; // Raw upgrade bookkeeping only (e.g. new_cpu/new_memory/new_disk); NOT a resource link
  resource?: SubscriptionLineItemResource; // Linked resource, resolved from the line item's subscription type
}

// Typed reference to the resource this line item bills for, resolved server-side
// from the line item's subscription type (null when there is no linked resource).
// Tagged union discriminated by the "type" field.
type SubscriptionLineItemResource =
  | { type: "vps"; vm_id: number }
  | { type: "ip_range"; ip_range_subscription_id: number };

interface SubscriptionPayment {
  id: string; // Hex-encoded payment ID
  subscription_id: number;
  created: string; // ISO 8601 datetime
  expires: string; // ISO 8601 datetime
  amount: Price; // Total payment amount
  payment_method: 'lightning' | 'onchain' | 'revolut' | 'paypal' | 'stripe' | 'nwc' | 'lnurl';
  payment_type: 'Purchase' | 'Renewal' | 'Upgrade';
  is_paid: boolean;
  paid_at?: string; // ISO 8601 datetime when payment was completed (only present when is_paid is true)
  tax: Price; // Tax amount
  processing_fee: Price; // Processing fee in the payment currency
}
```

### VM History

```typescript
interface VmHistory {
  id: number;
  vm_id: number;
  action_type: string;
  timestamp: string; // ISO 8601 datetime
  initiated_by: 'owner' | 'system' | 'other'; // Who initiated the action
  previous_state?: string; // JSON string
  new_state?: string; // JSON string
  metadata?: string; // JSON string
  description?: string;
}
```

### VM Operations

```typescript
interface VmPatchRequest {
  ssh_key_id?: number;
  reverse_dns?: string;
  auto_renewal_enabled?: boolean; // Enable/disable automatic renewal via NWC for this VM
}

interface CreateVmRequest {
  template_id: number;
  image_id: number;
  ssh_key_id: number;
  ref_code?: string;
}
```

### VM Upgrades

```typescript
interface VmUpgradeRequest {
  cpu?: number; // New CPU core count (must be >= current)
  memory?: number; // New memory in bytes (must be >= current)
  disk?: number; // New disk size in bytes (must be >= current)
}

interface VmUpgradeQuote {
  cost_difference: Price; // Net pro-rated cost for remaining VM time (before tax)
  new_renewal_cost: Price; // Monthly renewal cost after upgrade
  discount: Price; // Amount discounted for remaining time on the old rate
  tax: Price; // VAT charged on the upgrade cost
  processing_fee: Price; // Payment processing fee added on top (zero for Lightning)
}
```

## API Endpoints

### Passkey (WebAuthn) Authentication

Unauthenticated `fetch` endpoints (JSON in/out) for passwordless passkey login.
See [Authentication](#authentication-types) for the full flow and browser
examples. Each ceremony is a `start` then `finish` pair; the opaque signed
`state` from `start` must be posted back to `finish` unchanged.

#### Register Start
- **POST** `/api/v1/webauthn/register/start`
- **Auth**: None
- **Body**: `{ name?: string }` (optional device label)
- **Response**: `{ challenge: PublicKeyCredentialCreationOptions, state: string }`

#### Register Finish
- **POST** `/api/v1/webauthn/register/finish`
- **Auth**: None
- **Body**: `{ state: string, credential: RegisterPublicKeyCredential, name?: string }`
- **Response**: `{ token: string, token_type: "Bearer", expires_in: number }` (creates the account)

#### Login Start
- **POST** `/api/v1/webauthn/login/start`
- **Auth**: None
- **Body**: none (usernameless / discoverable)
- **Response**: `{ challenge: PublicKeyCredentialRequestOptions, state: string }`

#### Login Finish
- **POST** `/api/v1/webauthn/login/finish`
- **Auth**: None
- **Body**: `{ state: string, credential: PublicKeyCredential }`
- **Response**: `{ token: string, token_type: "Bearer", expires_in: number }`

#### Manage passkeys on the current account

These endpoints are **authenticated** (any scheme — a Nostr, OAuth or passkey
user can add passkeys to their own account). A passkey added here is stored
against the current account, so a later discoverable login with it resolves back
to that same account (its session token then carries the account's real
identity — e.g. a Nostr user's npub still works).

- **GET** `/api/v1/webauthn/credentials` — list this account's passkeys.
  Response: `Array<{ id: number, name?: string, created: string, last_used?: string }>`
- **POST** `/api/v1/webauthn/credentials/start` — begin adding a passkey.
  Body `{ name?: string }`; Response `{ challenge, state }` (already excludes
  credentials registered to this account). Run `startRegistration(...)` then:
- **POST** `/api/v1/webauthn/credentials/finish` — Body
  `{ state, credential, name? }`; Response is the created
  `{ id, name?, created, last_used? }` (no session token — you are already
  logged in).
- **DELETE** `/api/v1/webauthn/credentials/{id}` — remove a passkey. A pure
  passkey account (`account_type: "webauthn"`) cannot delete its **only**
  credential (that would lock the account out).

### OAuth Authentication

These endpoints are **unauthenticated** and drive full-page browser navigation
(not `fetch`/XHR). See [Authentication](#authentication-types) for the full flow
and React example. `{provider}` is one of the enabled tags (`google`, `github`,
`facebook`, `apple`).

#### Start Login
- **GET** `/api/v1/oauth/{provider}/login`
- **Auth**: None
- **Query**: `redirect` (optional) — per-request post-login return URL,
  overriding the configured `success-redirect` for this login only. Validated
  against the allowlist (`localhost` host always allowed; otherwise must match
  `success-redirect` or an `allowed-redirects` entry exactly or at a path
  boundary). Rejected with `400` if not allowed. The validated value is signed
  into `state`, so it cannot be tampered with.
- **Behavior**: 302 redirect to the provider's consent screen. Navigate the
  browser here (e.g. `window.location.href = ...`).

#### Login Callback
- **GET/POST** `/api/v1/oauth/{provider}/callback`
- **Auth**: None
- **Behavior**: Handled by the provider redirect (POST for Apple `form_post`).
  On success, either 302-redirects to the server's configured `success-redirect`
  with the token in the URL fragment (`#token=<jwt>`), or \u2014 if no redirect is
  configured \u2014 returns `{ "data": { "token": string, "token_type": "Bearer",
  "expires_in": number } }`. The frontend does not call this directly.

### Account Management

#### Get Account Information
- **GET** `/api/v1/account`
- **Auth**: Required
- **Response**: `AccountInfo`
- **Notes**: The `tax` field lists the VAT rate that will currently be charged to the user for each seller company, determined from the user's billing info (VAT number, declared country, IP-derived country). Use it to show expected tax up-front; the authoritative amount is still computed per payment.

#### Update Account Information
- **PATCH** `/api/v1/account`
- **Auth**: Required
- **Body**: `AccountInfo`
- **Notes**:
  - Setting `contact_email: true` requires an email address to be present
  - When email is changed, a verification email is sent and `email_verified` is reset to `false`
- **Response**: `null`

#### Verify Email Address
- **GET** `/api/v1/account/verify-email?token=<token>`
- **Auth**: Not required
- **Query**: `token` — the verification token from the verification email
- **Response**: `null`

#### List Configured Notification Channels
- **GET** `/api/v1/notification/channels`
- **Auth**: Not required
- **Notes**: Indicates which notification channels are configured on the server so the UI can show/hide the relevant contact inputs.
- **Response**: `{ "nip17": boolean, "email": boolean, "telegram": boolean, "whatsapp": boolean }`

#### Link Telegram
- **POST** `/api/v1/account/telegram/link`
- **Auth**: Required
- **Notes**: Generates a fresh one-time token and returns a Telegram deep link. Linking completes when the user opens the URL and presses **Start** in the bot. Returns an error if Telegram notifications are not enabled on the server.
- **Response**: `{ "url": string, "token": string }` — e.g. `{ "url": "https://t.me/MyBot?start=<token>", "token": "<token>" }`

#### Unlink Telegram
- **DELETE** `/api/v1/account/telegram/link`
- **Auth**: Required
- **Notes**: Clears the linked chat and link token and sets `contact_telegram` to `false`.
- **Response**: `null`

#### Start WhatsApp Verification
- **POST** `/api/v1/account/whatsapp/verify`
- **Auth**: Required
- **Body**: `{ "number": string }` — phone number in E.164 format, e.g. `+15551234567`
- **Notes**: Stores the number, generates a 6-digit code and sends it via the configured WhatsApp verification template. Returns an error if WhatsApp notifications are not enabled on the server, if the number is invalid, or if the message fails to send.
- **Response**: `null`

#### Confirm WhatsApp Verification
- **POST** `/api/v1/account/whatsapp/confirm`
- **Auth**: Required
- **Body**: `{ "code": string }` — the 6-digit code received via WhatsApp
- **Notes**: On a correct code, marks the number verified and sets `contact_whatsapp` to `true`. Returns an error for an invalid or expired code.
- **Response**: `null`

#### Unlink WhatsApp
- **DELETE** `/api/v1/account/whatsapp/verify`
- **Auth**: Required
- **Notes**: Removes the stored number, clears verification state and sets `contact_whatsapp` to `false`.
- **Response**: `null`

### Automatic Renewal with Nostr Wallet Connect

The LNVPS platform supports automatic VM renewal using Nostr Wallet Connect (NWC). This feature allows users to set up their Lightning wallets to automatically pay for VM renewals before expiration.

#### How It Works

1. **User Setup**: Configure your NWC connection string in your account settings
2. **Per-VM Control**: Enable automatic renewal for specific VMs you want to auto-renew
3. **Automatic Processing**: The system attempts renewal 1 day before VM expiration
4. **Dual Requirements**: Auto-renewal only works when BOTH conditions are met:
   - User has a valid NWC connection string configured
   - VM has `auto_renewal_enabled` set to `true`

#### Setup Process

1. **Configure NWC Connection**: Add your NWC connection string as a saved payment method via `POST /api/v1/payment-methods` (see [Saved Payment Methods](#saved-payment-methods) below)
2. **Enable Per-VM**: Use the VM PATCH endpoint to set `auto_renewal_enabled: true` for desired VMs
3. **Monitor Status**: Check VM details to see current auto-renewal status

#### NWC Connection String Format

The `nwc_connection_string` should be a valid Nostr Wallet Connect URI in the format:
```
nostr+walletconnect://relay_url?relay=ws://...&secret=...&pubkey=...
```

#### Important Notes

- **Safety First**: New VMs default to `auto_renewal_enabled: false` - you must explicitly enable it
- **Cost Control**: Only enable auto-renewal for VMs you definitely want to keep running
- **Fallback**: If auto-renewal fails, you'll receive the standard expiration notification
- **Validation**: The system validates NWC connection strings when you set them
- **Encryption**: NWC connection strings are encrypted in the database for security

#### Example Usage

```typescript
// 1. Add an NWC connection as a saved payment method
const addNwc = {
  nwc_connection_string: "nostr+walletconnect://relay.damus.io?relay=wss://relay.damus.io&secret=...",
  name: "My wallet"
};
await api.post('/api/v1/payment-methods', addNwc);

// 2. Enable auto-renewal for a specific VM
const vmUpdate = {
  auto_renewal_enabled: true
};
await api.patch('/api/v1/vm/123', vmUpdate);

// 3. Check VM auto-renewal status
const vmStatus = await api.get('/api/v1/vm/123');
console.log('Auto-renewal enabled:', vmStatus.data.auto_renewal_enabled);
```

### Saved Payment Methods

Saved payment methods are the wallets/cards used for automatic renewals and for referral payouts (NWC). The underlying provider tokens / NWC connection strings are **never** returned by the API. The two supported providers are `nwc` (Nostr Wallet Connect, added by the user) and `revolut` (a saved card, created during an interactive card payment).

#### List Saved Payment Methods
- **GET** `/api/v1/payment-methods`
- **Auth**: Required
- **Response**: `PaymentMethodResponse[]`

#### Add NWC Payment Method
- **POST** `/api/v1/payment-methods`
- **Auth**: Required
- **Body**: `AddNwcPaymentMethodRequest`
- **Response**: `PaymentMethodResponse`
- **Notes**: The NWC connection is validated (it must expose `pay_invoice`). The first method a user adds becomes their default.
- **Error**: Returns an error if the connection string is empty, cannot be parsed, or does not allow `pay_invoice`.

#### Update Saved Payment Method
- **PATCH** `/api/v1/payment-methods/{id}`
- **Auth**: Required
- **Body**: `PatchPaymentMethodRequest`
- **Response**: `PaymentMethodResponse`
- **Notes**: Setting `is_default: true` clears the default flag on the user's other methods (only one default at a time).

#### Delete Saved Payment Method
- **DELETE** `/api/v1/payment-methods/{id}`
- **Auth**: Required
- **Response**: `null`

**Types:**
```typescript
interface PaymentMethodResponse {
  id: number;
  provider: "nwc" | "revolut"; // Payment processor
  name?: string;               // Optional user-defined label
  created: string;             // ISO 8601 datetime
  card_brand?: string;         // Card brand (revolut only)
  card_last_four?: string;     // Last 4 digits (revolut only)
  exp_month?: number;          // Card expiry month (revolut only)
  exp_year?: number;           // Card expiry year (revolut only)
  is_default: boolean;         // Whether this is the default method
  enabled: boolean;            // Whether this method is usable
}

interface AddNwcPaymentMethodRequest {
  nwc_connection_string: string; // NWC URI (nostr+walletconnect://...)
  name?: string;                 // Optional user-defined label
}

interface PatchPaymentMethodRequest {
  is_default?: boolean;          // Set/unset as the default method
  enabled?: boolean;             // Enable/disable this method
  name?: string | null;          // Set (string) or clear (null) the label; omit to leave unchanged
}
```

### SSH Key Management

#### List SSH Keys
- **GET** `/api/v1/ssh-key`
- **Auth**: Required
- **Response**: `UserSshKey[]`

#### Add SSH Key
- **POST** `/api/v1/ssh-key`
- **Auth**: Required
- **Body**: `CreateSshKey`
- **Response**: `UserSshKey`

### VM Management

#### List User VMs
- **GET** `/api/v1/vm`
- **Auth**: Required
- **Response**: `VmStatus[]`

#### Get VM Details
- **GET** `/api/v1/vm/{id}`
- **Auth**: Required
- **Response**: `VmStatus`

#### Update VM Configuration
- **PATCH** `/api/v1/vm/{id}`
- **Auth**: Required
- **Body**: `VmPatchRequest`
- **Response**: `null`
- **Description**: Updates VM settings including SSH key, reverse DNS, and automatic renewal preferences

#### Create Standard VM Order
- **POST** `/api/v1/vm`
- **Auth**: Required
- **Body**: `CreateVmRequest`
- **Response**: `VmStatus`

#### Create Custom VM Order
- **POST** `/api/v1/vm/custom-template`
- **Auth**: Required
- **Body**: `CustomVmOrder`
- **Response**: `VmStatus`

#### Get VM Upgrade Quote
- **POST** `/api/v1/vm/{id}/upgrade/quote?method={payment_method}`
- **Auth**: Required
- **Query Params**: 
  - `method`: Optional payment method ('lightning' | 'revolut' | 'paypal'). Defaults to 'lightning'
- **Body**: `VmUpgradeRequest`
- **Response**: `VmUpgradeQuote`
- **Description**: Calculate the pro-rated upgrade cost for remaining VM time and the new monthly renewal cost after upgrade. Available for both standard template VMs and custom template VMs. Cost is calculated in the currency appropriate for the selected payment method. The response includes the upgrade cost (cost_difference), new renewal cost, and the discount amount representing the value of remaining time at the old pricing rate.

#### Create VM Upgrade Payment
- **POST** `/api/v1/vm/{id}/upgrade?method={payment_method}`
- **Auth**: Required
- **Query Params**: 
  - `method`: Optional payment method ('lightning' | 'revolut' | 'nwc' | 'saved'). Defaults to 'lightning'
  - `payment_method_id`: Optional; for `method=saved`, the specific saved card to charge (omit to use the default saved card)
- **Body**: `VmUpgradeRequest`
- **Response**: `VmPayment`
- **Description**: Create a payment for upgrading VM specifications. The upgrade is applied after payment confirmation. Payment method determines the currency and payment provider used. Saved methods are collected on the spot the same way as renewals: `method=nwc` pays via the user's saved Nostr Wallet Connect wallet, and `method=saved` charges a saved Revolut card off-session (merchant-initiated). For these off-session methods the request briefly waits for settlement — the returned `VmPayment` is already `is_paid: true` if it settled within ~10s, otherwise it is returned pending and settles asynchronously. **Important: Running VMs will be automatically stopped and restarted during the upgrade process to apply hardware changes.**

### VM Operations

#### Start VM
- **PATCH** `/api/v1/vm/{id}/start`
- **Auth**: Required
- **Response**: `null`

#### Stop VM
- **PATCH** `/api/v1/vm/{id}/stop`
- **Auth**: Required
- **Response**: `null`

#### Restart VM
- **PATCH** `/api/v1/vm/{id}/restart`
- **Auth**: Required
- **Response**: `null`

#### Reinstall VM
- **PATCH** `/api/v1/vm/{id}/re-install`
- **Auth**: Required
- **Body** (optional): `{ "image_id": number }` — switch the VM to a different OS image as part of the re-install. When omitted, the VM is reinstalled with its current image.
- **Response**: `null`
- **Errors**: `402 Payment Required` if the VM is expired (renew it first); `403 Forbidden` if the VM is not yours or the chosen image is not available; `404 Not Found` if the VM or image does not exist.

#### VM Serial Console (WebSocket)
- **WebSocket** `/api/v1/vm/{id}/console`
- **Auth**: Query parameter `?auth=<base64_nip98_event>` (same base64-encoded NIP-98 event as the `Authorization` header)
- **Protocol**: WebSocket upgrade — bidirectional relay between the client and the VM's serial console
- **Description**: Opens a WebSocket connection to the VM's serial terminal. Raw bytes in either direction are forwarded to/from the VM's serial port on the host. The connection is closed when either side disconnects or an error occurs.

### VM Firewall

Basic per-VM firewall rules. User-defined ACCEPT/DROP/REJECT rules are evaluated
in `priority` order (lower first) before the default policy. The default policy
per direction is configurable per-VM (`accept`/`drop`/`reject`); when unset it
inherits the host default, which is allow-all inbound and outbound (no change
from prior behaviour). Anti-spoofing (IP filter) protection is always enforced
by the host regardless of user rules.

The maximum number of rules per VM is configurable at the template level and
defaults to **20**. Any change to the rules queues an asynchronous re-apply of
the full firewall ruleset on the host.

**`FirewallRule` type**
```typescript
{
  id: number;
  priority: number;                       // evaluation order, lower first
  direction: "inbound" | "outbound";
  protocol: "any" | "tcp" | "udp" | "icmp";
  action: "accept" | "drop" | "reject";
  src_cidr?: string | null;               // optional source CIDR, null = any
  dst_port_start?: number | null;         // optional inclusive port range start, null = any
  dst_port_end?: number | null;           // optional inclusive port range end, null = single port
  enabled: boolean;
}
```

#### List Firewall Rules
- **GET** `/api/v1/vm/{id}/firewall`
- **Auth**: Required
- **Response**: `FirewallRule[]`

#### Create Firewall Rule
- **POST** `/api/v1/vm/{id}/firewall`
- **Auth**: Required
- **Body**: `{ priority?: number, direction, protocol, action, src_cidr?, dst_port_start?, dst_port_end?, enabled? }`
- **Response**: `FirewallRule`
- **Description**: Creates a rule and queues a firewall re-apply. Fails if the per-VM rule limit is reached, or if `src_cidr`/port range are invalid (ports 1–65535, `dst_port_start <= dst_port_end`).

#### Update Firewall Rule
- **PATCH** `/api/v1/vm/{id}/firewall/{rule_id}`
- **Auth**: Required
- **Body**: Partial `FirewallRule` fields (all optional). Send `src_cidr: null` / `dst_port_*: null` to clear a field to "any".
- **Response**: `FirewallRule`

#### Delete Firewall Rule
- **DELETE** `/api/v1/vm/{id}/firewall/{rule_id}`
- **Auth**: Required
- **Response**: `null`

**`FirewallPolicy` type**
```typescript
{
  policy_in?: "accept" | "drop" | "reject" | null;   // null = inherit host default (allow-all)
  policy_out?: "accept" | "drop" | "reject" | null;  // null = inherit host default (allow-all)
}
```

#### Get Firewall Policy
- **GET** `/api/v1/vm/{id}/firewall/policy`
- **Auth**: Required
- **Response**: `FirewallPolicy`

#### Update Firewall Policy
- **PATCH** `/api/v1/vm/{id}/firewall/policy`
- **Auth**: Required
- **Body**: `{ policy_in?, policy_out? }`. Omit a field to leave it unchanged, send `null` to reset it to the host default, or a value (`"accept"|"drop"|"reject"`) to set it explicitly.
- **Response**: `FirewallPolicy`
- **Description**: Sets the VM's default inbound/outbound policy and queues a firewall re-apply.

### Templates and Images

#### List VM Templates
- **GET** `/api/v1/vm/templates`
- **Auth**: None
- **Response**: 
```typescript
{
  templates: VmTemplate[];
  custom_template?: CustomTemplateParams[];
}
```

#### List OS Images
- **GET** `/api/v1/image`
- **Auth**: None
- **Query Params**:
  - `arch`: Optional CPU architecture filter (`x86_64`/`amd64`, `arm64`/`aarch64`). When set, only images of that architecture — plus architecture-agnostic images — are returned. An unrecognised value returns `400`.
- **Response**: `VmOsImage[]`

#### Calculate Custom VM Price
- **POST** `/api/v1/vm/custom-template/price`
- **Auth**: None
- **Body**: `CustomVmRequest`
- **Response**: `CustomVmPrice` (base `{ currency, amount }` plus `other_price[]` with the same quote converted to the other supported currencies)

### Payment Management

#### Get Available Payment Methods
- **GET** `/api/v1/payment/methods`
- **Auth**: None
- **Response**: `PaymentMethod[]`

#### Renew/Extend VM
- **GET** `/api/v1/vm/{id}/renew?method={payment_method}&intervals={count}`
- **Auth**: Required
- **Query Params**: 
  - `method`: Optional payment method ('lightning' | 'onchain' | 'revolut' | 'paypal' | 'nwc')
  - `intervals`: Optional number of billing intervals to renew (default: 1). For example, if the VM has a monthly billing cycle, `intervals=3` would generate a payment for 3 months.
- **Response**: `VmPayment`
- **Description**: Generates a payment invoice to extend the VM's expiration. The payment amount is calculated based on the VM's cost plan and the number of intervals requested. If `method=nwc` is specified and the user has a valid NWC connection string configured, the payment will be automatically processed via Nostr Wallet Connect. A renewal is **rejected** if it would push the VM's expiry beyond `now + max_prepay_days` (see `VmStatus.max_prepay_days`) or beyond the host's sunset date (see `VmStatus.host_sunset_date`); cap the `intervals` selector to what fits.

#### Get Payment Status
- **GET** `/api/v1/payment/{payment_id}`
- **Auth**: Required
- **Response**: `VmPayment`

#### Get Payment History
- **GET** `/api/v1/vm/{id}/payments?limit={limit}&offset={offset}`
- **Auth**: Required
- **Query Params**:
  - `limit`: Optional (default: 50, max: 100)
  - `offset`: Optional (default: 0)
- **Response**: Paginated list of VM payments
```typescript
// Returns: PaginatedResponse<VmPayment>
```

#### Get Payment Invoice (PDF)
- **GET** `/api/v1/payment/{payment_id}/invoice?auth={base64_auth}`
- **Auth**: Query parameter
- **Response**: PDF file (Content-Type: text/html)

### Subscription Management

#### List User Subscriptions
- **GET** `/api/v1/subscriptions?limit={limit}&offset={offset}`
- **Auth**: Required
- **Query Params**:
  - `limit`: Optional (default: 50, max: 100)
  - `offset`: Optional (default: 0)
- **Response**: Paginated list of subscriptions with embedded line items
```typescript
interface PaginatedResponse<T> {
  data: T[];
  total: number;
  limit: number;
  offset: number;
}
// Returns: PaginatedResponse<Subscription>
```

#### Create Subscription
- **POST** `/api/v1/subscriptions`
- **Auth**: Required
- **Body**: `CreateSubscriptionRequest`
- **Response**: `Subscription`
- **Description**: Creates a new subscription with one or more line items. The subscription is created in an **inactive** state. Resources (IP ranges, ASNs, etc.) are **not allocated** until the first payment is made via the renewal endpoint. After payment confirmation, resources are allocated and the subscription becomes active.

```typescript
interface CreateSubscriptionRequest {
  name?: string; // Display name for the subscription
  description?: string; // Optional description
  currency?: string; // Currency code (default: 'USD'): 'USD', 'EUR', 'BTC', etc.
  auto_renewal_enabled?: boolean; // Enable auto-renewal (default: true)
  line_items: CreateSubscriptionLineItemRequest[]; // At least one required
}

// Line item request - tagged union based on service type
type CreateSubscriptionLineItemRequest = 
  | { type: 'ip_range'; ip_space_pricing_id: number }
  | { type: 'asn_sponsoring'; asn: number } // Not yet implemented
  | { type: 'dns_hosting'; domain: string }; // Not yet implemented
```

**Workflow:**
1. User creates subscription with line items (this endpoint)
2. User generates payment via `GET /api/v1/subscriptions/{id}/renew`
3. User completes payment (Lightning, Revolut, etc.)
4. Payment handler allocates resources and activates subscription
5. Resources remain active while subscription is paid

**Example Request:**
```typescript
const request: CreateSubscriptionRequest = {
  name: "My IP Block Subscription",
  description: "IPv4 /24 block from RIPE",
  currency: "USD",
  auto_renewal_enabled: true,
  line_items: [
    { type: "ip_range", ip_space_pricing_id: 5 }
  ]
};

const response = await fetch('/api/v1/subscriptions', {
  method: 'POST',
  headers: {
    'Authorization': nip98AuthHeader,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify(request)
});

const result: ApiResponse<Subscription> = await response.json();
// result.data.is_active will be false until payment is made
```

#### Get Subscription Details
- **GET** `/api/v1/subscriptions/{id}`
- **Auth**: Required
- **Response**: `Subscription` (includes all line items)

#### Update Subscription
- **PATCH** `/api/v1/subscriptions/{id}`
- **Auth**: Required (must own the subscription)
- **Body**:
  - `auto_renewal_enabled`: Optional boolean — enable/disable automatic renewal
- **Response**: Updated `Subscription`
- **Description**: Modifies user-editable fields on an existing subscription. Only fields present in the body are changed. Currently limited to toggling `auto_renewal_enabled`.

#### Renew Subscription
- **GET** `/api/v1/subscriptions/{id}/renew?method={payment_method}`
- **Auth**: Required
- **Query Params**:
  - `method`: Optional payment method (`'lightning'` | `'revolut'` | `'paypal'` | `'stripe'`). Defaults to `'lightning'`
- **Response**: `SubscriptionPayment`
- **Description**: Generates a payment invoice to renew/extend the subscription. For the first payment, the amount includes setup fees plus the monthly recurring cost. For subsequent renewals, only the monthly recurring cost is charged. After payment is confirmed, resources (IP ranges, etc.) are allocated and the subscription is activated.

#### List Subscription Payments
- **GET** `/api/v1/subscriptions/{subscription_id}/payments?limit={limit}&offset={offset}`
- **Auth**: Required
- **Query Params**:
  - `limit`: Optional (default: 50, max: 100)
  - `offset`: Optional (default: 0)
- **Response**: Paginated list of payments for a specific subscription
```typescript
// Returns: PaginatedResponse<SubscriptionPayment>
```

### IP Space (Public)

Browse the additional IP space (extra subnets) available for purchase, with pricing. These endpoints are **public** (no auth) and only return spaces that are available and not reserved.

#### List Available IP Space
- **GET** `/api/v1/ip_space?limit={limit}&offset={offset}`
- **Auth**: None
- **Query Params**: `limit` (optional, default 50, max 100), `offset` (optional, default 0)
- **Response**: `PaginatedResponse<AvailableIpSpace>`

#### Get IP Space Details
- **GET** `/api/v1/ip_space/{id}`
- **Auth**: None
- **Response**: `AvailableIpSpace`
- **Error**: Returns an error if the space is not available or is reserved.

**Types:**
```typescript
interface AvailableIpSpace {
  id: number;
  min_prefix_size: number;         // Smallest allocatable prefix (e.g. 29)
  max_prefix_size: number;         // Largest allocatable prefix (e.g. 24)
  registry: "ARIN" | "RIPE" | "APNIC" | "LACNIC" | "AFRINIC";
  ip_version: "ipv4" | "ipv6";
  pricing: IpSpacePricing[];        // Pricing per allocatable prefix size
}

interface IpSpacePricing {
  id: number;
  prefix_size: number;
  price: Price;                     // Recurring price in the base currency
  setup_fee: Price;                 // One-time setup fee in the base currency
  other_price: Price[];             // Same recurring price in alternative currencies
  other_setup_fee: Price[];         // Same setup fee in alternative currencies
}
```

### Referral Program

Users can enroll in the referral program to earn payouts when others sign up using their code.

**Commission rate fields — how they relate**

The referral program pays a commission = a percentage of each referred VM's **first** payment. Three separate rate fields appear across these endpoints; they are easy to confuse, so read this first:

| Field | Where | Meaning |
|---|---|---|
| `referral_rate` | `Referral` | The **per-referrer override**, whole %. This is **admin-controlled** and is `null` for most referrers. `null` means “no override — fall back to the company default”. It is **not** the rate you earn on its own. |
| `effective_referral_rate` | `Referral` | The rate that **currently applies to you** for display, whole %: the `referral_rate` override when set, otherwise the default (primary) company's rate. Use this to show “your commission rate”. |
| `effective_rate` | `ReferralUsage` (per VM) | The rate that was **actually applied to one referred VM's** first payment, whole %. Resolved against that VM's own company, so it can differ per referred VM. |

> `effective_referral_rate` is a headline/default for the UI. The amount actually earned on a given referral is always computed per referred VM (`ReferralUsage.effective_rate`), because each referred VM may belong to a different company with its own default rate.

#### Sign Up for Referral Program
- **POST** `/api/v1/referral`
- **Auth**: Required
- **Body**:
```typescript
interface ReferralSignupRequest {
  address?: string; // Payout target; its type depends on mode: a Lightning address (required when mode is "lightning_address") or an on-chain Bitcoin address (required when mode is "on_chain", mainnet; regtest also accepted in debug builds). Not needed for "nwc".
  mode?: "lightning_address" | "nwc" | "on_chain"; // Payout method; defaults to "lightning_address"
  payout_threshold?: number; // Optional minimum accrued commission (in satoshis) before an automated payout is made. Raise it to avoid many tiny payouts (useful for on-chain). Must be at least the system minimum; omit to use the system minimum.
}
```
- **Response**: `Referral`
- **Error**: Returns error if already enrolled; if `mode` is `lightning_address` (or omitted) without a resolvable Lightning `address`; if `mode` is `nwc` but no NWC connection is configured on the account; if `mode` is `on_chain` without a valid Bitcoin `address`; or if `payout_threshold` is below the system minimum. `account_credit` is a defined-but-unimplemented mode and is rejected.

> **On-chain payouts** are paid by an automated worker that **batches every eligible on-chain referrer into a single send-many transaction**, gated by a minimum threshold (`min-onchain-payout-sats`, default 1000 sats). The **network fee is charged to you**: the transaction fee is split across the batch in proportion to each payout and debited from your balance (along with the amount), so `ReferralPayout.fee` records your share and the running balance may go negative — recovered from future referrals. Before broadcasting, the current next-block fee rate is fetched from mempool.space and the batch is **deferred if it exceeds the operator's cap** (`max-onchain-fee-per-vbyte`, default 50), so payouts wait for cheaper fees. Balances below the threshold accrue until a later run. You can also raise your own **`payout_threshold`** (satoshis) to batch up to a larger amount and avoid many tiny payouts — the effective threshold is `max(system minimum, your payout_threshold)`. Commission always accrues and can also be paid manually by admins.

#### Get Referral State
- **GET** `/api/v1/referral`
- **Auth**: Required
- **Response**: `ReferralState`
- **Error**: `404` if not enrolled

#### Update Referral Payout Options
- **PATCH** `/api/v1/referral`
- **Auth**: Required
- **Body**:
```typescript
interface ReferralPatchRequest {
  address?: string | null;  // Set (string) or clear (null) the payout target; validated against the effective mode (Lightning address for "lightning_address", Bitcoin address for "on_chain"). Omit to leave unchanged.
  mode?: "lightning_address" | "nwc" | "on_chain"; // Change payout method; omit to leave unchanged
  payout_threshold?: number | null; // Set (number, satoshis) or clear (null) your minimum-payout threshold; when set it must be at least the system minimum. Omit to leave unchanged.
}
```
- **Response**: `Referral`
- **Note**: `referral_rate` (the commission override) is **admin-controlled** and cannot be set through this endpoint.

#### Leave Referral Program
- **DELETE** `/api/v1/referral`
- **Auth**: Required
- **Response**: empty (`null` data)
- **Error**: `409` while a payout is still pending, or when paid payout history exists (retained for accounting).

#### Get Per-VM Referral Usage
- **GET** `/api/v1/referral/usage?limit={limit}&offset={offset}`
- **Auth**: Required
- **Query Params**: `limit` (optional, default 50, max 100), `offset` (optional, default 0)
- **Response**: `PaginatedResponse<ReferralUsage>` — one row per referred VM that made a first payment (most recent first)
- **Error**: `404` if not enrolled

**Response Types:**
```typescript
interface Referral {
  code: string;                    // 8-character base63 referral code to share
  lightning_address?: string;      // Lightning address for payouts (used when mode is "lightning_address")
  onchain_address?: string;        // On-chain Bitcoin address for payouts (used when mode is "on_chain")
  mode: "lightning_address" | "nwc" | "account_credit" | "on_chain"; // Payout method
  referral_rate: number | null;    // Per-referrer commission override (whole %), admin-controlled; null = no override, use company default. NOT the rate you earn by itself.
  effective_referral_rate: number; // The commission rate that currently applies to you (whole %): the override if set, else the default company's rate. Use this for display.
  created: string;                 // ISO 8601 datetime
}

interface ReferralEarning {
  currency: string;   // Currency code (e.g. "EUR", "BTC")
  amount: number;     // Total commission earned in this currency (smallest currency unit) = sum over referred VMs of (first payment * effective_rate%)
}

interface ReferralPayout {
  id: number;
  amount: number;     // Commission paid out (smallest currency unit)
  fee: number;        // Network/routing fee charged to you for this payout (smallest currency unit), debited from your balance alongside `amount`. On-chain payout batches split the transaction fee across referrers in proportion to their amount; fees may make the running balance negative, recovered from future referrals.
  currency: string;
  created: string;    // ISO 8601 datetime
  is_paid: boolean;
  mode: "lightning_address" | "nwc" | "on_chain"; // How this payout was made; tells you how to interpret `output`
  output?: string;    // Payout output reference: a BOLT11 invoice for a Lightning payout, or the on-chain outpoint "{txid}:{vout}" for an on-chain payout. On-chain payouts are batched into one transaction, so rows share the txid but carry distinct vouts.
  pre_image?: string; // Payment preimage (hex), present once a Lightning payout has settled
}

interface ReferralUsage {
  // Note: the referred VM's id is intentionally NOT exposed, so a referrer
  // cannot map commission back to specific customers' VMs.
  created: string;       // ISO 8601 datetime of that VM's first paid payment
  amount: number;        // The referred VM's first payment amount (smallest currency unit)
  currency: string;      // Currency of the payment / commission
  effective_rate: number;// Rate actually applied to THIS referred VM (whole %); resolved against the VM's own company
  commission: number;    // Commission earned from this VM = amount * effective_rate% (smallest currency unit)
}

interface ReferralState extends Referral {
  earned: ReferralEarning[];     // Per-currency breakdown of commission earned
  payouts: ReferralPayout[];     // Complete payout history (most recent first)
  referrals_success: number;     // Number of referred VMs that made at least one payment
  referrals_failed: number;      // Number of referred VMs that never paid
}
```

### Managed Apps

Browse the catalog of predefined apps (e.g. Nostr relay, Blossom), order your own deployments, and manage their lifecycle.

#### Order a Deployment
- **POST** `/api/v1/app-deployments`
- **Auth**: Required
- **Body**:
```typescript
interface CreateAppDeploymentRequest {
  app_id: number;                        // catalog app to deploy
  name: string;                          // DNS-safe label (lowercase letters/digits/hyphens, ≤40), becomes the subdomain
  region_id: number;                     // region to deploy in; a cluster there with capacity is chosen
  config?: { [field: string]: string };  // values for the app's `config` fields
}
```
- **Response**: `AppDeployment` — created in `pending` state with a billing subscription; **pay the subscription** (`GET /api/v1/subscriptions/{subscription_id}/renew`) to activate it. The operator starts the workload once paid.
- **Errors**: `400` for an invalid `name`, missing required / unknown `config` fields, or when no cluster in the region has enough capacity; `404` if the app doesn't exist or isn't offered.

#### Stop / Start a Deployment
- **PATCH** `/api/v1/app-deployments/{id}/stop` — scale to 0 (data retained)
- **PATCH** `/api/v1/app-deployments/{id}/start` — resume
- **Auth**: Required
- **Response**: `AppDeployment`
- **Error**: `404` if not found or not owned by you

#### Delete a Deployment
- **DELETE** `/api/v1/app-deployments/{id}`
- **Auth**: Required
- **Response**: `true` — stops billing (deactivates the subscription) and tears the deployment down (namespace + volumes removed).
- **Error**: `404` if not found or not owned by you

The catalog + read endpoints below are unauthenticated-safe views of what you can deploy and what you're running.

#### List Catalog Apps
- **GET** `/api/v1/apps`
- **Auth**: None (public, like `GET /api/v1/vm/templates`)
- **Response**: `App[]` — all currently offered apps

#### Get Catalog App
- **GET** `/api/v1/apps/{id}`
- **Auth**: None (public)
- **Response**: `App`
- **Error**: `404` if the app doesn't exist or isn't currently offered

#### List Deployable Regions for an App
- **GET** `/api/v1/apps/{id}/regions`
- **Auth**: None (public)
- **Response**: `{ id: number, name: string, available: boolean }[]` — every region
  with an enabled app cluster. `available` is `true` when a cluster there
  currently has enough free capacity for this app; `false` regions can be
  shown-but-disabled in a deploy-form region picker. Use one of these `id`s as
  `region_id` when ordering.
- **Error**: `404` if the app doesn't exist or isn't currently offered

#### List Your Deployments
- **GET** `/api/v1/app-deployments`
- **Auth**: Required
- **Response**: `AppDeployment[]` — your deployments (most recent first)

#### Get Your Deployment
- **GET** `/api/v1/app-deployments/{id}`
- **Auth**: Required
- **Response**: `AppDeployment`
- **Error**: `404` if not found or not owned by you

**Response Types:**
```typescript
interface App {
  id: number;
  name: string;              // URL/DNS-safe slug
  display_name: string;
  description?: string;
  icon?: string;
  compose: string;           // docker-compose-style YAML; render the config form (ports/env) from this
  amount: number;            // recurring price in smallest currency units (cents / millisats)
  currency: string;
  interval_amount: number;
  interval_type: "day" | "month" | "year";
  setup_amount: number;      // one-off setup fee in smallest currency units (0 = none)
}

interface AppDeployment {
  id: number;
  app_id: number;            // catalog app being run
  name: string;              // your instance name
  hostname?: string;         // public endpoint host once assigned (null until reconciled, or for apps with no ingress port)
  desired_state: "running" | "stopped";
  status: "pending" | "running" | "stopped" | "error" | "deleting";
  status_message?: string;   // operator status/error detail when present
  subscription_id?: number;  // subscription this deployment is billed under (renew via the subscription endpoints)
  created: string;           // ISO 8601 datetime
}
```

### Monitoring and History

#### Get VM Time Series Data
- **GET** `/api/v1/vm/{id}/time-series`
- **Auth**: Required
- **Response**: `TimeSeriesData[]`

#### Get VM History
- **GET** `/api/v1/vm/{id}/history?limit={limit}&offset={offset}`
- **Auth**: Required
- **Query Params**:
  - `limit`: Optional number of records to return
  - `offset`: Optional offset for pagination
- **Response**: `VmHistory[]`

### LNURL Support

#### LNURL Pay for VM Extension
- **GET** `/.well-known/lnurlp/{vm_id}`
- **Auth**: None
- **Response**: LNURL PayResponse

#### LNURL Pay Invoice Generation
- **GET** `/api/v1/vm/{id}/renew-lnurlp?amount={millisats}`
- **Auth**: None
- **Query Params**:
  - `amount`: Amount in millisatoshis (minimum 1000)
- **Response**: Lightning Network invoice

### Nostr Domains (NIP-05)

Manage NIP-05 identity domains and their handles. All endpoints require NIP-98 authentication and only operate on domains owned by the caller.

Data types:

```typescript
interface NostrDomain {
  id: number;
  name: string;          // domain name, e.g. "example.com"
  enabled: boolean;      // activated by an operator after DNS is configured
  handles: number;       // number of handles registered under this domain
  created: string;       // ISO 8601 timestamp
  relays: string[];      // relay hints advertised for the domain
}

interface NostrDomainHandle {
  id: number;
  domain_id: number;
  handle: string;        // the local part, e.g. "alice" for alice@example.com
  pubkey: string;        // 32-byte public key, hex-encoded
  created: string;       // ISO 8601 timestamp
  relays: string[];      // relay hints for this handle
}
```

#### List Nostr Domains
- **GET** `/api/v1/nostr/domain`
- **Auth**: NIP-98
- **Response**: `{ "domains": NostrDomain[], "cname": string }` — `cname` is the target hostname to point domain DNS records at.

#### Create Nostr Domain
- **POST** `/api/v1/nostr/domain`
- **Auth**: NIP-98
- **Body**: `{ "name": string }` — the domain name to register
- **Notes**: The domain is created disabled with an activation hash; an operator enables it once DNS/CNAME is configured.
- **Response**: `NostrDomain`

#### List Domain Handles
- **GET** `/api/v1/nostr/domain/{dom}/handle`
- **Auth**: NIP-98
- **Path Params**: `dom` — the domain id
- **Notes**: Returns an error if the domain is not owned by the caller.
- **Response**: `NostrDomainHandle[]`

#### Create Domain Handle
- **POST** `/api/v1/nostr/domain/{dom}/handle`
- **Auth**: NIP-98
- **Path Params**: `dom` — the domain id
- **Body**: `{ "name": string, "pubkey": string }` — `name` is the handle (local part); `pubkey` is a 32-byte public key, hex-encoded
- **Notes**: Returns an error if the domain is not owned by the caller or if the public key is not valid 32-byte hex.
- **Response**: `NostrDomainHandle`

#### Delete Domain Handle
- **DELETE** `/api/v1/nostr/domain/{dom}/handle/{handle}`
- **Auth**: NIP-98
- **Path Params**: `dom` — the domain id; `handle` — the handle id
- **Notes**: Returns an error if the domain is not owned by the caller.
- **Response**: `null`

### Legal Documents

#### Generate Unsigned Sponsoring LIR Agreement
- **GET** `/api/v1/legal/sponsoring-lir-agreement?data={base64url_json}`
- **Auth**: None
- **Query Params**:
  - `data`: base64url-encoded JSON of the agreement data
- **Response**: Rendered HTML agreement document
- **Notes**: Rejects data that includes a cryptographic proof (use the signed endpoint for that)

#### Generate Signed Sponsoring LIR Agreement from Subscription
- **GET** `/api/v1/legal/sponsoring-lir-agreement/from-subscription/{subscription_id}`
- **Auth**: NIP-98
- **Response**: `SignedAgreementUrlResponse` — a cryptographically signed LIR agreement for one of the caller's own subscriptions. Provider/end-user details are populated from company and user billing data. Returns an error if the subscription does not belong to the caller.

## Error Handling

All endpoints return errors in the following format:
```typescript
interface ApiError {
  error: string;
}
```

Common HTTP status codes:
- `200`: Success
- `400`: Bad Request (validation errors)
- `401`: Unauthorized (invalid or missing authentication)
- `402`: Payment Required (e.g. acting on an expired VM that must be renewed first)
- `403`: Forbidden (accessing a resource you don't own, or insufficient permissions)
- `404`: Not Found (missing resource, or a nested resource that doesn't belong to the parent in the path)
- `409`: Conflict (the resource's current state conflicts with the request, e.g. an already-deleted VM or an already-completed payment)
- `500`: Internal Server Error
- `501`: Not Implemented (feature not yet available)

## Rate Limiting

Rate limiting information is not specified in the current API. Implement appropriate client-side throttling based on usage patterns.

## TypeScript Utility Types

```typescript
// API response wrapper
interface ApiResponse<T> {
  data: T;
}

interface ApiError {
  error: string;
}

// Helper for API calls
type ApiResult<T> = ApiResponse<T> | ApiError;

// Type guard for error responses
function isApiError(response: any): response is ApiError {
  return 'error' in response;
}

// Type guard for success responses
function isApiSuccess<T>(response: ApiResult<T>): response is ApiResponse<T> {
  return 'data' in response;
}
```

## Development Notes

1. **Authentication**: All authenticated endpoints require NIP-98 Nostr event authentication
2. **Date Formats**: All dates are in ISO 8601 format
3. **Currency Units**: Amounts are returned as `Price` objects with `currency` and `amount` fields. The `amount` is a `u64` integer in the **smallest currency unit** (e.g., cents for EUR/USD, millisats for BTC). To display human-readable values, divide by the currency's decimal factor (100 for most fiat, 1000 for BTC millisats to sats)
4. **Memory/Disk Units**: All memory and disk sizes are in bytes
5. **VM States**: VM states are string enums representing current operational status
6. **Error Handling**: Always check for error responses before accessing data
7. **Pagination**: Some endpoints support optional pagination with `limit` and `offset` parameters
8. **Subscriptions**: Subscription responses include all line items embedded. Subscriptions are created inactive and only become active after the first payment is completed.
9. **Subscription Billing**: Subscriptions use monthly billing cycles. The first payment includes setup fees plus the monthly recurring cost. Subsequent renewals only charge the monthly recurring cost.
10. **Setup Fees**: Individual line items can have one-time setup fees that are charged only on initial purchase.

### VM Upgrade Process

11. **Upgrade Eligibility**: All VMs can be upgraded, including both standard template VMs and custom template VMs. For standard template VMs, upgrades transition them to custom templates. For custom template VMs, upgrades modify the existing custom template specifications.
12. **Pro-rated Billing**: Upgrade costs are calculated based on the remaining time until VM expiration. The cost represents the difference between current and new specifications, pro-rated for the remaining billing period. The system calculates: (new_rate_per_second * seconds_remaining) - (old_rate_per_second * seconds_remaining). The discount field shows the value of remaining time at the old rate. The system respects the actual billing interval of the cost plan (daily, monthly, yearly) rather than assuming monthly billing.
13. **Billing Interval Handling**: 
    - Standard template VMs: Use their cost plan's actual interval (interval_type and interval_amount)
    - Custom template VMs: Always use monthly billing for pro-rating calculations
    - Examples: A cost plan with interval_type="day" and interval_amount=7 bills every 7 days
14. **Upgrade Payment Flow**: 
    - First, get a quote using `/api/v1/vm/{id}/upgrade/quote`
    - Then, create an upgrade payment using `/api/v1/vm/{id}/upgrade`
    - Complete the payment (Lightning Network, Revolut, PayPal, or Stripe)
    - The upgrade is automatically applied after payment confirmation
    - **VM Restart**: Running VMs are automatically stopped, upgraded, and restarted to apply hardware changes
15. **Specification Requirements**: All upgrade values must be greater than or equal to current values (no downgrades allowed)
16. **Minimum Billing**: Even very short upgrade periods (e.g., VMs expiring soon) have a minimum billing of 1 hour
17. **Payment Method Support**: Upgrades support multiple payment methods (Lightning Network, Revolut, PayPal, Stripe) specified via the optional `method` query parameter

### Example: VM Upgrade Flow

```typescript
// Step 1: Get upgrade quote
const upgradeRequest: VmUpgradeRequest = {
  cpu: 4,      // Upgrade from 2 to 4 CPUs
  memory: 4 * 1024 * 1024 * 1024, // 4GB in bytes
  disk: 120 * 1024 * 1024 * 1024  // 120GB in bytes
};

// Optional: specify payment method (defaults to 'lightning')
const paymentMethod = 'revolut'; // or 'lightning' or 'paypal'

const quoteResponse = await fetch(`/api/v1/vm/123/upgrade/quote?method=${paymentMethod}`, {
  method: 'POST',
  headers: authHeaders, // NIP-98 authentication
  body: JSON.stringify(upgradeRequest)
});

const quote: ApiResponse<VmUpgradeQuote> = await quoteResponse.json();
console.log(`Upgrade cost: ${quote.data.cost_difference.amount} ${quote.data.cost_difference.currency}`);
console.log(`New monthly cost: ${quote.data.new_renewal_cost.amount} ${quote.data.new_renewal_cost.currency}`);
console.log(`Discount applied: ${quote.data.discount.amount} ${quote.data.discount.currency}`);

// Step 2: Create upgrade payment if user accepts the quote (using same payment method)
// Note: The VM will be restarted automatically after payment to apply hardware changes
const paymentResponse = await fetch(`/api/v1/vm/123/upgrade?method=${paymentMethod}`, {
  method: 'POST',
  headers: authHeaders,
  body: JSON.stringify(upgradeRequest)
});

const payment: ApiResponse<VmPayment> = await paymentResponse.json();

// Step 3: Complete payment based on method
// For Lightning Network: payment.data.data.lightning contains the invoice string
// For Revolut: payment.data.data.revolut.token contains the payment token
// After payment confirmation, the upgrade is automatically applied
```

---

## Contact Form Submission

### Endpoint: `POST /api/v1/contact`

**Authentication**: None (Public endpoint)

**Description**: Submit a contact form message to the administrators. This endpoint is rate-limited and requires Cloudflare Turnstile verification.

**Request Body**:

```typescript
interface ContactFormRequest {
  subject: string;           // Required: Message subject
  message: string;           // Required: Message content
  email: string;             // Required: Sender's email address
  name: string;              // Required: Sender's name
  user_pubkey?: string;      // Optional: User's Nostr public key (npub or hex)
  timestamp: string;         // Required: ISO 8601 timestamp of submission
  turnstile_token: string;   // Required: Cloudflare Turnstile verification token
}
```

**Response**:

```typescript
interface ContactFormResponse {
  data: null;
}
```

**Error Responses**:

- `"Subject is required"` - Subject field is empty
- `"Message is required"` - Message field is empty
- `"Name is required"` - Name field is empty
- `"Email is required"` - Email field is empty
- `"Invalid email address"` - Email format is invalid
- `"Captcha verification failed"` - Turnstile token is invalid or expired
- `"Failed to verify captcha"` - Server error during Turnstile verification
- `"Captcha not configured"` - Server is not configured with Turnstile
- `"Email notifications are not configured"` - Server SMTP is not configured
- `"Admin notifications are not configured"` - No admin user configured
- `"Failed to send notification"` - Failed to queue the notification

**Example Request**:

```typescript
const contactForm: ContactFormRequest = {
  subject: "Question about VM hosting",
  message: "I would like to know more about your VM hosting plans...",
  email: "user@example.com",
  name: "John Doe",
  user_pubkey: "npub1xyz...",  // Optional
  timestamp: new Date().toISOString(),
  turnstile_token: "0.ABC123..."  // From Cloudflare Turnstile widget
};

const response = await fetch('/api/v1/contact', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify(contactForm)
});

const result: ApiResponse<null> = await response.json();

if (result.error) {
  console.error('Contact form submission failed:', result.error);
} else {
  console.log('Contact form submitted successfully');
}
```

**Notes**:

1. This endpoint does not require authentication, making it accessible to all users
2. All fields except `user_pubkey` are required and will be validated
3. The Turnstile token must be obtained from the Cloudflare Turnstile widget on the frontend
4. The message will be sent to the configured admin email address
5. Email addresses are validated with basic format checking (contains @ and .)
6. The admin will receive an email containing all the form data including a reply-to address

---

## IP Space Management

IP Space management allows users to browse and purchase IP address blocks. For security reasons, 
the actual CIDR blocks are not exposed in the public API until after purchase.

### Data Types

```typescript
type InternetRegistry = 'arin' | 'ripe' | 'apnic' | 'lacnic' | 'afrinic';

interface AvailableIpSpace {
  id: number;
  min_prefix_size: number; // e.g., 24 (smallest allocation)
  max_prefix_size: number; // e.g., 22 (largest allocation)
  registry: InternetRegistry;
  ip_version: 'ipv4' | 'ipv6'; // IP version of this block
  pricing: IpSpacePricing[];
}

interface IpSpacePricing {
  id: number;
  prefix_size: number; // e.g., 24 for /24
  price: Price; // Base price in original currency
  setup_fee: Price; // Setup fee in original currency
  other_price: Price[]; // Prices converted to alternative currencies
  other_setup_fee: Price[]; // Setup fees converted to alternative currencies
}

// Note: uses the same Price type as the rest of the API (smallest currency units, uppercase currency codes)

interface IpRangeSubscription {
  id: number;
  cidr: string; // The allocated IP range e.g., "192.168.1.0/24"
  is_active: boolean;
  started_at: string; // ISO 8601 datetime
  ended_at?: string; // ISO 8601 datetime
  parent_cidr: string; // The IP space block this was allocated from
}

interface AddIpRangeToSubscriptionRequest {
  ip_space_pricing_id: number; // The pricing tier to use
}
```

### List Available IP Spaces

Browse available IP address blocks for purchase.

**Endpoint**: `GET /api/v1/ip_space`

**Authentication**: Not required (public endpoint)

**Query Parameters**:
- `limit` (optional, number): Maximum number of items to return (default: 50, max: 100)
- `offset` (optional, number): Number of items to skip (default: 0)

**Response**: `ApiPaginatedResponse<AvailableIpSpace>`

**Example Request**:

```typescript
const response = await fetch('/api/v1/ip_space?limit=20&offset=0');
const result: ApiPaginatedResponse<AvailableIpSpace> = await response.json();

if (!result.error) {
  result.data.forEach(space => {
    console.log(`${space.ip_version.toUpperCase()} block from ${space.registry.toUpperCase()}`);
    space.pricing.forEach(price => {
      console.log(`  /${price.prefix_size}: ${price.price.currency} ${price.price.amount}/month`);
      if (price.other_price.length > 0) {
        console.log(`    Also available in: ${price.other_price.map(p => p.currency).join(', ')}`);
      }
    });
  });
}
```

**Notes**:
1. Only shows IP spaces that are available and not reserved
2. The actual CIDR blocks are not exposed in the public API - use `ip_version` to determine IPv4 or IPv6
3. Each IP space includes all available pricing tiers with alternative currency conversions
4. Base pricing uses the `price` and `setup_fee` fields
5. Alternative currencies are available in `other_price` and `other_setup_fee` arrays
6. Different prefix sizes within the same block can have different prices

### Get IP Space Details

Get detailed information about a specific IP space block.

**Endpoint**: `GET /api/v1/ip_space/{id}`

**Authentication**: Not required (public endpoint)

**Path Parameters**:
- `id` (number): The IP space ID

**Response**: `ApiResponse<AvailableIpSpace>`

**Error Responses**:
- `"IP space not available"` (`400 Bad Request`) - IP space is not available for purchase
- `404 Not Found` - IP space ID does not exist

**Example Request**:

```typescript
const response = await fetch('/api/v1/ip_space/1');
const result: ApiResponse<AvailableIpSpace> = await response.json();

if (!result.error) {
  console.log(`${result.data.ip_version} block from ${result.data.registry}`);
  console.log(`Prefix sizes: /${result.data.min_prefix_size} to /${result.data.max_prefix_size}`);
}
```

### List Subscription IP Ranges

List all IP ranges allocated to a specific subscription.

**Endpoint**: `GET /api/v1/subscriptions/{subscription_id}/ip_ranges`

**Authentication**: Required (NIP-98)

**Path Parameters**:
- `subscription_id` (number): The subscription ID

**Query Parameters**:
- `limit` (optional, number): Maximum number of items to return (default: 50, max: 100)
- `offset` (optional, number): Number of items to skip (default: 0)

**Response**: `ApiPaginatedResponse<IpRangeSubscription>`

**Error Responses**:
- `"Access denied: not your subscription"` (`403 Forbidden`) - User doesn't own this subscription

**Example Request**:

```typescript
const response = await fetch('/api/v1/subscriptions/123/ip_ranges', {
  headers: {
    'Authorization': nip98AuthHeader,
    'Content-Type': 'application/json'
  }
});

const result: ApiPaginatedResponse<IpRangeSubscription> = await response.json();

if (!result.error) {
  result.data.forEach(ipRange => {
    console.log(`${ipRange.cidr} (from ${ipRange.parent_cidr})`);
    console.log(`Active: ${ipRange.is_active}`);
  });
}
```

### Add IP Range to Subscription

Purchase an IP range and add it to an existing subscription.

**Endpoint**: `POST /api/v1/subscriptions/{subscription_id}/ip_ranges`

**Authentication**: Required (NIP-98)

**Path Parameters**:
- `subscription_id` (number): The subscription ID

**Request Body**: `AddIpRangeToSubscriptionRequest`

```typescript
interface AddIpRangeToSubscriptionRequest {
  ip_space_pricing_id: number; // ID of the pricing tier to purchase
}
```

**Response**: `ApiResponse<IpRangeSubscription>`

**Error Responses**:
- `"Access denied: not your subscription"` (`403 Forbidden`) - User doesn't own this subscription
- `"IP space is not available for allocation"` - IP space is no longer available
- `"IP range allocation not yet implemented - please contact support to manually allocate IP ranges"` - Feature not yet complete (current status)

**Example Request**:

```typescript
const request: AddIpRangeToSubscriptionRequest = {
  ip_space_pricing_id: 5 // ID from the pricing list
};

const response = await fetch('/api/v1/subscriptions/123/ip_ranges', {
  method: 'POST',
  headers: {
    'Authorization': nip98AuthHeader,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify(request)
});

const result: ApiResponse<IpRangeSubscription> = await response.json();

if (!result.error) {
  console.log(`Allocated: ${result.data.cidr}`);
  console.log(`Started: ${result.data.started_at}`);
}
```

**Notes**:
1. IP allocation logic is not yet implemented - this endpoint currently returns an error
2. When implemented, the system will:
   - Find an available subnet of the requested prefix size
   - Check for conflicts with existing allocations
   - Create a subscription line item with the monthly and setup fees
   - Create the IP range subscription record
   - Return the allocated CIDR
3. The allocated IP range will be added as a line item to the subscription with recurring billing
4. Setup fees are charged once, monthly fees recur with the subscription billing cycle

---

## IP Space Administration (Admin API)

These endpoints are only available to administrators with appropriate permissions.

### List IP Spaces (Admin)

**Endpoint**: `GET /api/admin/v1/ip_space`

**Authentication**: Required (Admin with `ip_space::view` permission)

**Query Parameters**:
- `limit` (optional, number): Maximum items to return (default: 50, max: 100)
- `offset` (optional, number): Items to skip (default: 0)
- `is_available` (optional, boolean): Filter by availability status
- `registry` (optional, number): Filter by registry (0=ARIN, 1=RIPE, 2=APNIC, 3=LACNIC, 4=AFRINIC)

### Create IP Space (Admin)

**Endpoint**: `POST /api/admin/v1/ip_space`

**Authentication**: Required (Admin with `ip_space::create` permission)

**Request Body**:
```typescript
interface CreateAvailableIpSpaceRequest {
  cidr: string;
  min_prefix_size: number;
  max_prefix_size: number;
  registry: number; // 0=ARIN, 1=RIPE, 2=APNIC, 3=LACNIC, 4=AFRINIC
  external_id?: string; // RIR allocation ID
  is_available?: boolean; // Default: true
  is_reserved?: boolean; // Default: false
  metadata?: object; // JSON metadata (routing requirements, etc.)
}
```

### Update IP Space (Admin)

**Endpoint**: `PATCH /api/admin/v1/ip_space/{id}`

**Authentication**: Required (Admin with `ip_space::update` permission)

### Delete IP Space (Admin)

**Endpoint**: `DELETE /api/admin/v1/ip_space/{id}`

**Authentication**: Required (Admin with `ip_space::delete` permission)

**Error**: Returns error if there are active subscriptions using this IP space

### Manage IP Space Pricing (Admin)

**List Pricing**: `GET /api/admin/v1/ip_space/{id}/pricing`

**Create Pricing**: `POST /api/admin/v1/ip_space/{id}/pricing`

**Update Pricing**: `PATCH /api/admin/v1/ip_space/{space_id}/pricing/{pricing_id}`

**Delete Pricing**: `DELETE /api/admin/v1/ip_space/{space_id}/pricing/{pricing_id}`

**Request Body** (Create):
```typescript
interface CreateIpSpacePricingRequest {
  prefix_size: number; // e.g., 24 for /24
  price_per_month: number; // In cents/millisats
  currency?: string; // Default: "USD"
  setup_fee?: number; // Default: 0
}
```

### List IP Space Subscriptions (Admin)

View all subscriptions for a specific IP space.

**Endpoint**: `GET /api/admin/v1/ip_space/{id}/subscriptions`

**Authentication**: Required (Admin with `subscriptions::view` permission)

**Query Parameters**:
- `limit`, `offset`: Pagination
- `user_id` (optional): Filter by user
- `is_active` (optional): Filter by active status



This documentation is optimized for LLM code generation and provides all necessary type definitions and endpoint specifications for building TypeScript frontend applications.