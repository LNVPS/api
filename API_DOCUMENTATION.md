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
  | { revolut: { token: string } }; // Revolut payment token

interface PaymentMethod {
  name: 'lightning' | 'revolut' | 'paypal';
  metadata: Record<string, string>;
  currencies: ('BTC' | 'EUR' | 'USD')[];
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
}

interface CreateVmRequest {
  template_id: number;
  image_id: number;
  ssh_key_id: number;
  ref_code?: string;
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

This documentation is optimized for LLM code generation and provides all necessary type definitions and endpoint specifications for building TypeScript frontend applications.