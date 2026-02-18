# LNVPS API Documentation for TypeScript Frontend Development

This document provides comprehensive API specifications for generating TypeScript frontend code that interacts with the LNVPS Lightning Network VPS service.

## Base Configuration

- **Base URL**: `https://api.lnvps.com` (replace with actual production URL)
- **Authentication**: NIP-98 (Nostr) authentication required for all authenticated endpoints
- **Content Type**: `application/json`
- **Error Response Format**: `{ "error": "Error message" }`
- **Success Response Format**: `{ "data": <response_data> }`

## Authentication Types

```typescript
// All authenticated endpoints require NIP-98 authentication headers
interface AuthHeaders {
  'Authorization': string; // Base64 encoded NIP-98 event
  'Content-Type': 'application/json';
}
```

## Core Data Types

### User Account

```typescript
interface AccountInfo {
  email?: string;
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
  nwc_connection_string?: string; // Nostr Wallet Connect URI for automatic renewals
}
```

### VM Status

```typescript
interface VmStatus {
  id: number;
  created: string; // ISO 8601 datetime
  expires: string; // ISO 8601 datetime
  mac_address: string;
  image: VmOsImage;
  template: VmTemplate;
  ssh_key: UserSshKey;
  ip_assignments: VmIpAssignment[];
  status: VmState;
  auto_renewal_enabled: boolean; // Whether automatic renewal via NWC is enabled for this VM
}

type VmState = 'running' | 'stopped' | 'pending' | 'error' | 'unknown';
```

### VM Template

```typescript
interface VmTemplate {
  id: number;
  name: string;
  created: string; // ISO 8601 datetime
  expires?: string; // ISO 8601 datetime
  cpu: number; // Number of CPU cores
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

interface VmHostRegion {
  id: number;
  name: string;
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
  distribution: 'ubuntu' | 'debian' | 'centos' | 'fedora' | 'freebsd' | 'opensuse' | 'archlinux' | 'redhatenterprise';
  flavour: string;
  version: string;
  release_date: string; // ISO 8601 datetime
  default_username?: string;
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
  data: PaymentData;
  time: number; // Seconds this payment adds to VM expiry
  is_upgrade: boolean;
  upgrade_params?: string; // JSON-encoded upgrade parameters (only present for upgrade payments)
}

type PaymentData = 
  | { lightning: string } // Lightning Network invoice
  | { revolut: { token: string } } // Revolut payment token
  | { stripe: { session_id: string } }; // Stripe checkout session

interface PaymentType {
  type: 'new' | 'renew' | 'upgrade';
}

interface PaymentMethod {
  name: 'lightning' | 'revolut' | 'paypal' | 'stripe' | 'nwc';
  metadata: Record<string, string>;
  currencies: ('BTC' | 'EUR' | 'USD')[];
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
  configuration?: any; // Service-specific configuration (JSON)
}

interface SubscriptionPayment {
  id: string; // Hex-encoded payment ID
  subscription_id: number;
  created: string; // ISO 8601 datetime
  expires: string; // ISO 8601 datetime
  amount: Price; // Total payment amount
  payment_method: 'lightning' | 'revolut' | 'paypal' | 'stripe';
  payment_type: 'Purchase' | 'Renewal';
  is_paid: boolean;
  tax: Price; // Tax amount
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
  cost_difference: Price; // Pro-rated cost for remaining VM time
  new_renewal_cost: Price; // Monthly renewal cost after upgrade
  discount: Price; // Amount discounted for remaining time on the old rate
}
```

## API Endpoints

### Account Management

#### Get Account Information
- **GET** `/api/v1/account`
- **Auth**: Required
- **Response**: `AccountInfo`

#### Update Account Information
- **PATCH** `/api/v1/account`
- **Auth**: Required
- **Body**: `AccountInfo`
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

1. **Configure NWC Connection**: Use the account PATCH endpoint to set your `nwc_connection_string`
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
// 1. Set up NWC connection string
const accountUpdate = {
  nwc_connection_string: "nostr+walletconnect://relay.damus.io?relay=wss://relay.damus.io&secret=..."
};
await api.patch('/api/v1/account', accountUpdate);

// 2. Enable auto-renewal for a specific VM
const vmUpdate = {
  auto_renewal_enabled: true
};
await api.patch('/api/v1/vm/123', vmUpdate);

// 3. Check VM auto-renewal status
const vmStatus = await api.get('/api/v1/vm/123');
console.log('Auto-renewal enabled:', vmStatus.data.auto_renewal_enabled);
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
  - `method`: Optional payment method ('lightning' | 'revolut' | 'paypal'). Defaults to 'lightning'
- **Body**: `VmUpgradeRequest`
- **Response**: `VmPayment`
- **Description**: Create a payment for upgrading VM specifications. The upgrade is applied after payment confirmation. Payment method determines the currency and payment provider used. **Important: Running VMs will be automatically stopped and restarted during the upgrade process to apply hardware changes.**

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
- **Response**: `null`

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
- **Response**: `VmOsImage[]`

#### Calculate Custom VM Price
- **POST** `/api/v1/vm/custom-template/price`
- **Auth**: None
- **Body**: `CustomVmRequest`
- **Response**: `Price`

### Payment Management

#### Get Available Payment Methods
- **GET** `/api/v1/payment/methods`
- **Auth**: None
- **Response**: `PaymentMethod[]`

#### Renew/Extend VM
- **GET** `/api/v1/vm/{id}/renew?method={payment_method}&intervals={count}`
- **Auth**: Required
- **Query Params**: 
  - `method`: Optional payment method ('lightning' | 'revolut' | 'paypal' | 'nwc')
  - `intervals`: Optional number of billing intervals to renew (default: 1). For example, if the VM has a monthly billing cycle, `intervals=3` would generate a payment for 3 months.
- **Response**: `VmPayment`
- **Description**: Generates a payment invoice to extend the VM's expiration. The payment amount is calculated based on the VM's cost plan and the number of intervals requested. If `method=nwc` is specified and the user has a valid NWC connection string configured, the payment will be automatically processed via Nostr Wallet Connect.

#### Get Payment Status
- **GET** `/api/v1/payment/{payment_id}`
- **Auth**: Required
- **Response**: `VmPayment`

#### Get Payment History
- **GET** `/api/v1/vm/{id}/payments`
- **Auth**: Required
- **Response**: `VmPayment[]`

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

#### Renew Subscription
- **GET** `/api/v1/subscriptions/{id}/renew?method={payment_method}`
- **Auth**: Required
- **Query Params**:
  - `method`: Optional payment method ('lightning' | 'revolut' | 'paypal' | 'stripe'). Defaults to 'lightning'
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
- `403`: Forbidden (insufficient permissions)
- `404`: Not Found
- `500`: Internal Server Error

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

interface Price {
  currency: 'usd' | 'eur' | 'btc' | 'gbp' | 'cad' | 'chf' | 'aud' | 'jpy';
  amount: number; // In decimal format (e.g., 10.00 for $10, 0.00011 for BTC)
}

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
- `"IP space not available"` - IP space is not available for purchase
- Not found error if ID doesn't exist

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
- `"Access denied: not your subscription"` - User doesn't own this subscription

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
- `"Access denied: not your subscription"` - User doesn't own this subscription
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