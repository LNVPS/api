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
  amount: number; // Price amount as float
  other_price: Price[]; // Alternative currency prices
  interval_amount: number;
  interval_type: 'day' | 'month' | 'year';
}

interface Price {
  currency: 'BTC' | 'EUR' | 'USD';
  amount: number;
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
  amount: number; // Amount in smallest currency unit
  tax: number; // Tax amount in smallest currency unit
  currency: string;
  is_paid: boolean;
  data: PaymentData;
  time: number; // Seconds this payment adds to VM expiry
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
  currency: 'BTC' | 'EUR' | 'USD' | 'GBP' | 'CAD' | 'CHF' | 'AUD' | 'JPY';
  interval_amount: number; // Billing cycle multiplier (e.g., 1 for monthly, 3 for quarterly)
  interval_type: 'day' | 'month' | 'year';
  setup_fee: number; // One-time setup fee in smallest currency unit (cents/millisats)
  auto_renewal_enabled: boolean;
  line_items: SubscriptionLineItem[]; // Services included in this subscription
}

interface SubscriptionLineItem {
  id: number;
  subscription_id: number;
  name: string;
  description?: string;
  amount: number; // Recurring cost per billing cycle in smallest currency unit (cents/millisats)
  setup_amount: number; // One-time setup fee in smallest currency unit (cents/millisats)
  configuration?: any; // Service-specific configuration (JSON)
}

interface SubscriptionPayment {
  id: string; // Hex-encoded payment ID
  subscription_id: number;
  created: string; // ISO 8601 datetime
  expires?: string; // ISO 8601 datetime
  amount: number; // Total amount in smallest currency unit (cents/millisats)
  currency: 'BTC' | 'EUR' | 'USD' | 'GBP' | 'CAD' | 'CHF' | 'AUD' | 'JPY';
  payment_method: 'lightning' | 'revolut' | 'paypal' | 'stripe';
  payment_type: 'purchase' | 'renewal'; // 0=Purchase, 1=Renewal
  is_paid: boolean;
  rate?: number; // Exchange rate if applicable
  time_value: number; // Duration purchased in seconds
  tax: number; // Tax amount in smallest currency unit (cents/millisats)
  external_id?: string; // External payment processor ID (e.g., Stripe, PayPal)
}

interface SubscriptionSummary {
  active_subscriptions: number; // Count of active subscriptions
  total_monthly_cost: number; // Total monthly cost across all active subscriptions
  currency: string; // Currency code
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
- **GET** `/api/v1/vm/{id}/renew?method={payment_method}`
- **Auth**: Required
- **Query Params**: 
  - `method`: Optional payment method ('lightning' | 'revolut' | 'paypal')
- **Response**: `VmPayment`

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

#### Get Subscription Details
- **GET** `/api/v1/subscriptions/{id}`
- **Auth**: Required
- **Response**: `Subscription` (includes all line items)

#### Get Subscription Summary
- **GET** `/api/v1/subscriptions/summary`
- **Auth**: Required
- **Response**: `SubscriptionSummary`
- **Description**: Returns aggregated statistics including active subscription count and total monthly cost across all active subscriptions

#### List Subscription Line Items
- **GET** `/api/v1/subscriptions/{subscription_id}/line_items`
- **Auth**: Required
- **Response**: `SubscriptionLineItem[]`
- **Note**: Line items are also included in subscription responses, so this endpoint is primarily for backward compatibility

#### Get Subscription Line Item
- **GET** `/api/v1/subscription_line_items/{id}`
- **Auth**: Required
- **Response**: `SubscriptionLineItem`

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

#### Get Subscription Payment
- **GET** `/api/v1/subscription_payments/{hex_id}`
- **Auth**: Required
- **Response**: `SubscriptionPayment`

#### List All User Subscription Payments
- **GET** `/api/v1/subscription_payments?limit={limit}&offset={offset}`
- **Auth**: Required
- **Query Params**:
  - `limit`: Optional (default: 50, max: 100)
  - `offset`: Optional (default: 0)
- **Response**: Paginated list of all subscription payments for the authenticated user
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
3. **Currency Units**: Amounts are in the smallest unit (satoshis for BTC, cents for fiat)
4. **Memory/Disk Units**: All memory and disk sizes are in bytes
5. **VM States**: VM states are string enums representing current operational status
6. **Error Handling**: Always check for error responses before accessing data
7. **Pagination**: Some endpoints support optional pagination with `limit` and `offset` parameters
8. **Subscriptions**: Subscription responses now include all line items embedded. The standalone line item endpoints are still available for backward compatibility.
9. **Billing Cycles**: Subscriptions have a single billing cycle (interval_amount + interval_type) that applies to all line items. Total recurring cost is the sum of all line item amounts.
10. **Setup Fees**: Both subscriptions and individual line items can have one-time setup fees that are charged only on initial purchase.

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


This documentation is optimized for LLM code generation and provides all necessary type definitions and endpoint specifications for building TypeScript frontend applications.