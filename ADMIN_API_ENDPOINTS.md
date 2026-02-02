# LNVPS Admin API Endpoints

Admin API request/response format reference for LLM consumption.

## Enums

**DiskType**: `"hdd"`, `"ssd"`
**DiskInterface**: `"sata"`, `"scsi"`, `"pcie"`
**VmRunningStates**: `"running"`, `"stopped"`, `"starting"`, `"deleting"`
**AdminVmHistoryActionType**: `"created"`, `"started"`, `"stopped"`, `"restarted"`, `"deleted"`, `"expired"`, `"renewed"`, `"reinstalled"`, `"state_changed"`, `"payment_received"`, `"configuration_changed"`
**AdminPaymentMethod**: `"lightning"`, `"revolut"`, `"paypal"`, `"stripe"`
**VmHostKind**: `"proxmox"`, `"libvirt"`
**CostPlanIntervalType**: `"day"`, `"month"`, `"year"`
**ApiOsDistribution**: `"ubuntu"`, `"debian"`, `"centos"`, `"fedora"`, `"freebsd"`, `"opensuse"`, `"archlinux"`, `"redhatenterprise"`
**IpRangeAllocationMode**: `"random"`, `"sequential"`, `"slaac_eui64"`
**NetworkAccessPolicyKind**: `"static_arp"`
**RouterKind**: `"mikrotik"`, `"ovh_additional_ip"`
**AdminUserRole**: `"super_admin"`, `"admin"`, `"read_only"`
**AdminUserStatus**: `"active"`, `"suspended"`, `"deleted"`
**SubscriptionPaymentType**: `"purchase"`, `"renewal"`
**SubscriptionType**: `"ip_range"`, `"asn_sponsoring"`, `"dns_hosting"`
**InternetRegistry**: `"arin"`, `"ripe"`, `"apnic"`, `"lacnic"`, `"afrinic"`

## Authentication
```
Authorization: Nostr <base64-encoded-event>
```

## Response Formats
**Single item**: `{"data": T}`
**Paginated list**: `{"data": T[], "total": number, "limit": number, "offset": number}`

## Endpoints

### User Management

#### List Users
```
GET /api/admin/v1/users
```
Query Parameters:
- `limit`: number (optional) - max 100, default 50
- `offset`: number (optional) - default 0
- `search`: string (optional) - user pubkey (hex format)

Required Permission: `users::view`

#### Get User Details
```
GET /api/admin/v1/users/{id}
```
Required Permission: `users::view`

Returns complete user information including VM count and admin status.

#### Update User
```
PATCH /api/admin/v1/users/{id}
```
Required Permission: `users::update`

#### Bulk Message Active Customers
```
POST /api/admin/v1/users/bulk-message
```
Dispatch a bulk message job to send messages to all active customers based on their contact preferences. The job is processed asynchronously by the worker system.

Request body:
```json
{
  "subject": "Message subject",
  "message": "Message content"
}
```

Response:
```json
{
  "data": {
    "job_dispatched": true,
    "job_id": "1234567890-bulk-message"
  }
}
```

**Note:** The endpoint dispatches a work job and returns immediately with the job ID. The admin user will receive a completion notification via their contact preferences when the job finishes with full delivery statistics.

**Active customers** are defined as users who:
- Have at least one non-deleted VM (`vm.deleted = false`)
- Have at least one contact method enabled (`contact_email = true` OR `contact_nip17 = true`)
- Have the necessary contact information (email address for email, pubkey for NIP-17)

**Message delivery priority:**
1. Email (if `contact_email = true` and email address exists and SMTP configured)
2. NIP-17 DM (if `contact_nip17 = true` and email failed/unavailable and Nostr configured)

Required Permission: `users::update`

Body (all optional):
```json
{
  "email": "string",
  "contact_nip17": boolean,
  "contact_email": boolean,
  "country_code": "string",
  "billing_name": "string",
  "billing_address_1": "string",
  "billing_address_2": "string",
  "billing_city": "string",
  "billing_state": "string",
  "billing_postcode": "string",
  "billing_tax_id": "string",
  "admin_role": "super_admin" // AdminUserRole enum or null
}
```

### VM Management

#### List VMs
```
GET /api/admin/v1/vms
```
Query Parameters:
- `limit`: number (optional) - max 100, default 50
- `offset`: number (optional) - default 0
- `user_id`: number (optional)
- `host_id`: number (optional)
- `pubkey`: string (optional) - hex format
- `region_id`: number (optional)
- `include_deleted`: boolean (optional) - default false

Required Permission: `virtual_machines::view`

Returns paginated list of VMs with complete host and region information. All VMs are guaranteed to have valid host and region associations - missing references will result in an error.

#### Get VM Details
```
GET /api/admin/v1/vms/{id}
```
Required Permission: `virtual_machines::view`

Returns detailed VM information with complete host and region data. The VM must have valid host and region associations.

#### Create VM for User
```
POST /api/admin/v1/vms
```
Required Permission: `virtual_machines::create`

Creates a VM for a specific user (admin action). The VM creation is processed asynchronously via the work job system.

Body:
```json
{
  "user_id": number,       // Required - Target user ID
  "template_id": number,   // Required - VM template ID
  "image_id": number,      // Required - OS image ID
  "ssh_key_id": number,    // Required - SSH key ID (must belong to user)
  "ref_code": "string",    // Optional - Referral code
  "reason": "string"       // Optional - Admin reason for audit trail
}
```

Response:
```json
{
  "data": {
    "job_id": "stream-id-12345"
  }
}
```

**Validation:**
- User must exist
- Template must exist  
- Image must exist
- SSH key must exist and belong to the specified user

**Asynchronous Processing:** This endpoint dispatches a `CreateVm` work job for distributed processing. The operation returns immediately with a job ID. The VM creation is handled by the provisioner and includes full audit logging with admin action metadata.

#### Start VM
```
POST /api/admin/v1/vms/{id}/start
```
Required Permission: `virtual_machines::update`

Response:
```json
{
  "data": {
    "job_id": "stream-id-12345"
  }
}
```

#### Stop VM
```
POST /api/admin/v1/vms/{id}/stop
```
Required Permission: `virtual_machines::update`

Response:
```json
{
  "data": {
    "job_id": "stream-id-12345"
  }
}
```

#### Delete VM
```
DELETE /api/admin/v1/vms/{id}
```
Required Permission: `virtual_machines::delete`

Body (optional):
```json
{
  "reason": "string"
}
```

Response:
```json
{
  "data": {
    "job_id": "stream-id-12345"
  }
}
```

#### Calculate VM Refund
```
GET /api/admin/v1/vms/{vm_id}/refund?method={payment_method}&from_date={unix_timestamp}
```
Required Permission: `virtual_machines::view`

Query Parameters:
- `method`: string (required) - Payment method: "lightning", "revolut", "paypal"
- `from_date`: number (optional) - Unix timestamp to calculate refund from (defaults to current time)

Returns calculated pro-rated refund amount for the VM based on remaining time from the specified date and payment method.

Response:
```json
{
  "data": {
    "amount": number,      // Refund amount in the currency
    "currency": "string",  // Currency code (USD, EUR, etc.)
    "rate": number         // Exchange rate used for calculation
  }
}
```

#### Process VM Refund
```
POST /api/admin/v1/vms/{vm_id}/refund
```
Required Permission: `virtual_machines::delete`

Initiates an automated refund process for a VM. This creates a work job that will be processed asynchronously by the worker system.

Body:
```json
{
  "payment_method": "lightning",                    // Required - "lightning", "revolut", "paypal"
  "refund_from_date": 1705312200,                  // Optional - Unix timestamp to calculate refund from (defaults to current time)
  "reason": "Customer requested cancellation",     // Optional - Reason for the refund
  "lightning_invoice": "lnbc..."                   // Required when payment_method is "lightning"
}
```

Response:
```json
{
  "data": {
    "job_dispatched": true,
    "job_id": "stream-id-12345"
  }
}
```

**Note:** The refund is processed asynchronously via work jobs. The admin will receive notifications about the refund status through their configured contact preferences.


#### Extend VM
```
PUT /api/admin/v1/vms/{id}/extend
```
Required Permission: `virtual_machines::update`

Body:
```json
{
  "days": 30,        // Required: 1-365
  "reason": "string" // Optional
}
```

#### List VM History
```
GET /api/admin/v1/vms/{vm_id}/history
```
Query Parameters:
- `limit`: number (optional) - max 100, default 50
- `offset`: number (optional) - default 0

Required Permission: `virtual_machines::view`

#### Get VM History Entry
```
GET /api/admin/v1/vms/{vm_id}/history/{history_id}
```
Required Permission: `virtual_machines::view`

#### List VM Payments
```
GET /api/admin/v1/vms/{vm_id}/payments
```
Query Parameters:
- `limit`: number (optional) - max 100, default 50
- `offset`: number (optional) - default 0

Required Permission: `payments::view`

#### Get VM Payment
```
GET /api/admin/v1/vms/{vm_id}/payments/{payment_id}
```
Required Permission: `payments::view`

### Subscription Management

#### List Subscriptions
```
GET /api/admin/v1/subscriptions
```
Query Parameters:
- `limit`: number (optional) - max 100, default 50
- `offset`: number (optional) - default 0
- `user_id`: number (optional) - filter by user ID

Required Permission: `subscriptions::view`

Returns paginated list of subscriptions with embedded line items and payment count.

#### Get Subscription Details
```
GET /api/admin/v1/subscriptions/{id}
```
Required Permission: `subscriptions::view`

Returns complete subscription information including all line items and payment count.

#### Create Subscription
```
POST /api/admin/v1/subscriptions
```
Required Permission: `subscriptions::create`

Request body:
```json
{
  "user_id": number,
  "name": string,
  "description": string (optional),
  "expires": string (optional, ISO 8601 datetime),
  "is_active": boolean,
  "currency": string, // "USD", "EUR", "BTC", etc.
  "interval_amount": number,
  "interval_type": "day" | "month" | "year",
  "setup_fee": number, // in cents/millisats
  "auto_renewal_enabled": boolean,
  "external_id": string (optional)
}
```

Response: Subscription with line items

#### Update Subscription
```
PATCH /api/admin/v1/subscriptions/{id}
```
Required Permission: `subscriptions::update`

Request body (all fields optional):
```json
{
  "name": string,
  "description": string,
  "expires": string (ISO 8601 datetime) or null,
  "is_active": boolean,
  "currency": string,
  "interval_amount": number,
  "interval_type": "day" | "month" | "year",
  "setup_fee": number,
  "auto_renewal_enabled": boolean,
  "external_id": string
}
```

Response: Updated subscription with line items

#### Delete Subscription
```
DELETE /api/admin/v1/subscriptions/{id}
```
Required Permission: `subscriptions::delete`

**Note:** Cannot delete subscriptions with paid payments. Returns error if paid payments exist.

Response:
```json
{
  "data": {
    "deleted": true
  }
}
```

#### List Subscription Line Items
```
GET /api/admin/v1/subscriptions/{subscription_id}/line_items
```
Required Permission: `subscription_line_items::view`

Returns all line items for a specific subscription. Note that line items are also included in subscription responses.

#### Get Subscription Line Item
```
GET /api/admin/v1/subscription_line_items/{id}
```
Required Permission: `subscription_line_items::view`

#### Create Subscription Line Item
```
POST /api/admin/v1/subscription_line_items
```
Required Permission: `subscription_line_items::create`

Request body:
```json
{
  "subscription_id": number,
  "name": string,
  "description": string (optional),
  "amount": number, // recurring cost in cents/millisats
  "setup_amount": number, // one-time setup fee in cents/millisats
  "configuration": object (optional) // service-specific JSON config
}
```

Response: Created line item

#### Update Subscription Line Item
```
PATCH /api/admin/v1/subscription_line_items/{id}
```
Required Permission: `subscription_line_items::update`

Request body (all fields optional):
```json
{
  "name": string,
  "description": string,
  "amount": number,
  "setup_amount": number,
  "configuration": object
}
```

Response: Updated line item

#### Delete Subscription Line Item
```
DELETE /api/admin/v1/subscription_line_items/{id}
```
Required Permission: `subscription_line_items::delete`

Response:
```json
{
  "data": {
    "deleted": true
  }
}
```

#### List Subscription Payments
```
GET /api/admin/v1/subscriptions/{subscription_id}/payments
```
Query Parameters:
- `limit`: number (optional) - max 100, default 50
- `offset`: number (optional) - default 0

Required Permission: `subscription_payments::view`

Returns paginated list of payments for a specific subscription.

#### Get Subscription Payment
```
GET /api/admin/v1/subscription_payments/{hex_id}
```
Required Permission: `subscription_payments::view`

Returns detailed payment information including company details if available.

### Role Management

#### List Roles
```
GET /api/admin/v1/roles
```
Query Parameters:
- `limit`: number (optional) - max 100, default 50
- `offset`: number (optional) - default 0

Required Permission: `roles::view`

#### Get Role Details
```
GET /api/admin/v1/roles/{id}
```
Required Permission: `roles::view`

#### Create Role
```
POST /api/admin/v1/roles
```
Required Permission: `roles::create`

Body:
```json
{
  "name": "string",
  "description": "string (optional)",
  "permissions": ["string"]
}
```

#### Update Role
```
PATCH /api/admin/v1/roles/{id}
```
Required Permission: `roles::update`

Body (all optional):
```json
{
  "name": "string",
  "description": "string",
  "permissions": ["string"]
}
```

#### Delete Role
```
DELETE /api/admin/v1/roles/{id}
```
Required Permission: `roles::delete`

### User Role Assignments

#### Get User Roles
```
GET /api/admin/v1/users/{user_id}/roles
```
Required Permission: `users::view`

#### Assign Role to User
```
POST /api/admin/v1/users/{user_id}/roles
```
Required Permission: `users::update`

Body:
```json
{
  "role_id": number
}
```

#### Revoke Role from User
```
DELETE /api/admin/v1/users/{user_id}/roles/{role_id}
```
Required Permission: `users::update`

#### Get Current User's Admin Roles
```
GET /api/admin/v1/me/roles
```
Required Permission: None

### Host Management

#### List Hosts
```
GET /api/admin/v1/hosts
```
Query Parameters:
- `limit`: number (optional) - max 100, default 50
- `offset`: number (optional) - default 0

Required Permission: `hosts::view`

#### Get Host Details
```
GET /api/admin/v1/hosts/{id}
```
Required Permission: `hosts::view`

#### Update Host Configuration
```
PATCH /api/admin/v1/hosts/{id}
```
Required Permission: `hosts::update`

Body (all optional):
```json
{
  "name": "string",
  "ip": "string",
  "api_token": "string",
  "region_id": number,
  "kind": "libvirt", // VmHostKind enum
  "vlan_id": number | null,
  "enabled": boolean,
  "load_cpu": number,
  "load_memory": number,
  "load_disk": number
}
```

#### Create Host
```
POST /api/admin/v1/hosts
```
Required Permission: `hosts::create`

Body:
```json
{
  "name": "string",        // Required
  "ip": "string",         // Required
  "api_token": "string",  // Required
  "region_id": number,    // Required
  "kind": "proxmox",     // Required - VmHostKind enum
  "vlan_id": number | null,
  "cpu": number,         // Required
  "memory": number,      // Required
  "enabled": boolean,    // Optional - default true
  "load_cpu": number,    // Optional - default 1.0
  "load_memory": number, // Optional - default 1.0
  "load_disk": number    // Optional - default 1.0
}
```

#### List Host Disks
```
GET /api/admin/v1/hosts/{id}/disks
```
Required Permission: `hosts::view`

#### Get Host Disk Details
```
GET /api/admin/v1/hosts/{host_id}/disks/{disk_id}
```
Required Permission: `hosts::view`

#### Create Host Disk
```
POST /api/admin/v1/hosts/{host_id}/disks
```
Required Permission: `hosts::update`

Body:
```json
{
  "name": "string",         // Required - Disk name (e.g., "main-storage")
  "size": number,           // Required - Size in bytes
  "kind": "ssd",           // Required - DiskType enum: "hdd" or "ssd"
  "interface": "pcie",     // Required - DiskInterface enum: "sata", "scsi", or "pcie"
  "enabled": boolean       // Optional - Default: true
}
```

#### Update Host Disk Configuration
```
PATCH /api/admin/v1/hosts/{host_id}/disks/{disk_id}
```
Required Permission: `hosts::update`

Body (all optional):
```json
{
  "name": "string",         // Disk name
  "size": number,           // Size in bytes
  "kind": "ssd",           // DiskType enum: "hdd" or "ssd"
  "interface": "pcie",     // DiskInterface enum: "sata", "scsi", or "pcie"
  "enabled": boolean       // Enable/disable disk
}
```

### Region Management

#### List Regions
```
GET /api/admin/v1/regions
```
Query Parameters:
- `limit`: number (optional) - Items per page (max 100, default 50)
- `offset`: number (optional) - Pagination offset

Required Permission: `hosts::view`

Returns paginated list of VM host regions with configuration details, host counts, and statistics (only active VMs are counted).

#### Get Region Details
```
GET /api/admin/v1/regions/{id}
```
Required Permission: `hosts::view`

Returns detailed information about a specific region including host count and statistics (only active VMs are counted).

#### Create Region
```
POST /api/admin/v1/regions
```
Required Permission: `hosts::create`

Body:
```json
{
  "name": "string",
  "company_id": "number | null"
}
```

#### Update Region Configuration
```
PATCH /api/admin/v1/regions/{id}
```
Required Permission: `hosts::update`

Body parameters (all optional):
```json
{
  "name": "string",
  "enabled": boolean,
  "company_id": "number | null"
}
```

#### Delete Region
```
DELETE /api/admin/v1/regions/{id}
```
Required Permission: `hosts::delete`

Note: Regions with assigned hosts cannot be deleted and will be disabled instead to preserve referential integrity.

### VM OS Image Management

#### List VM OS Images
```
GET /api/admin/v1/vm_os_images
```
Query Parameters:
- `limit`: number (optional) - Items per page (max 100, default 50)
- `offset`: number (optional) - Pagination offset

Required Permission: `vm_os_image::view`

Returns paginated list of VM OS images with distribution, version, and configuration details.

#### Get VM OS Image Details
```
GET /api/admin/v1/vm_os_images/{id}
```
Required Permission: `vm_os_image::view`

Returns detailed information about a specific VM OS image.

#### Create VM OS Image
```
POST /api/admin/v1/vm_os_images
```
Required Permission: `vm_os_image::create`

Body:
```json
{
  "distribution": "ubuntu",      // ApiOsDistribution enum: "ubuntu", "debian", "centos", "fedora", "freebsd", "opensuse", "archlinux", "redhatenterprise"
  "flavour": "string",          // e.g., "server", "desktop"
  "version": "string",          // e.g., "22.04", "11", "8"
  "enabled": boolean,
  "release_date": "string (ISO 8601)",
  "url": "string",              // URL to the cloud image
  "default_username": "string (optional)"  // Default SSH username
}
```

#### Update VM OS Image
```
PATCH /api/admin/v1/vm_os_images/{id}
```
Required Permission: `vm_os_image::update`

Body (all optional):
```json
{
  "distribution": "debian",    // ApiOsDistribution enum: "ubuntu", "debian", "centos", "fedora", "freebsd", "opensuse", "archlinux", "redhatenterprise"
  "flavour": "string",
  "version": "string",
  "enabled": boolean,
  "release_date": "string (ISO 8601)",
  "url": "string",
  "default_username": "string"
}
```

#### Delete VM OS Image
```
DELETE /api/admin/v1/vm_os_images/{id}
```
Required Permission: `vm_os_image::delete`

Note: VM OS images that are referenced by existing VMs cannot be deleted.

### VM Template Management

#### List VM Templates
```
GET /api/admin/v1/vm_templates
```
Query Parameters:
- `limit`: number (optional) - Items per page (max 100, default 50)
- `offset`: number (optional) - Pagination offset

Required Permission: `vm_template::view`

Returns paginated list of VM templates with configuration details, cost plan names, and region names.

#### Get VM Template Details
```
GET /api/admin/v1/vm_templates/{id}
```
Required Permission: `vm_template::view`

Returns detailed information about a specific VM template including cost plan and region information.

#### Create VM Template
```
POST /api/admin/v1/vm_templates
```
Required Permission: `vm_template::create`

Body:
```json
{
  "name": "string",
  "enabled": boolean,         // optional, default true
  "expires": "string (ISO 8601) | null",  // optional
  "cpu": number,             // CPU cores
  "memory": number,          // Memory in bytes
  "disk_size": number,       // Disk size in bytes
  "disk_type": "hdd",        // DiskType enum: "hdd" or "ssd"
  "disk_interface": "sata",   // DiskInterface enum: "sata", "scsi", or "pcie"
  "cost_plan_id": number,    // optional - if not provided, cost plan will be auto-created
  "region_id": number,
  // Cost plan auto-creation fields (used when cost_plan_id not provided)
  "cost_plan_name": "string",            // optional, defaults to "{template_name} Cost Plan"
  "cost_plan_amount": number,            // required if cost_plan_id not provided
  "cost_plan_currency": "string",        // optional, defaults to "USD"
  "cost_plan_interval_amount": number,   // optional, defaults to 1
  "cost_plan_interval_type": "day" | "month" | "year"  // optional, defaults to "month"
}
```

#### Update VM Template
```
PATCH /api/admin/v1/vm_templates/{id}
```
Required Permission: `vm_template::update`

Body (all optional):
```json
{
  "name": "string",
  "enabled": boolean,
  "expires": "string (ISO 8601) | null",
  "cpu": number,
  "memory": number,
  "disk_size": number,
  "disk_type": "string",
  "disk_interface": "string",
  "cost_plan_id": number,
  "region_id": number,
  "cost_plan_name": "string",                    // Update associated cost plan name
  "cost_plan_amount": number,                    // Update associated cost plan amount
  "cost_plan_currency": "string",               // Update associated cost plan currency
  "cost_plan_interval_amount": number,          // Update associated cost plan interval amount
  "cost_plan_interval_type": "day" | "month" | "year"  // Update associated cost plan interval type
}
```

#### Delete VM Template
```
DELETE /api/admin/v1/vm_templates/{id}
```
Required Permission: `vm_template::delete`

Note: VM templates that are referenced by existing VMs cannot be deleted. When a template is deleted, its associated cost plan will also be deleted if no other templates are using it.

### Cost Plan Management

Cost plans define the billing structure for VM templates. When creating VM templates, you can either specify an existing cost plan or let the system automatically create a new one.

#### List Cost Plans
```
GET /api/admin/v1/cost_plans
```
Query Parameters:
- `limit`: number (optional) - Items per page (max 100, default 50)
- `offset`: number (optional) - Pagination offset

Required Permission: `vm_template::view`

Returns paginated list of cost plans with template usage counts.

#### Get Cost Plan Details
```
GET /api/admin/v1/cost_plans/{id}
```
Required Permission: `vm_template::view`

Returns detailed information about a specific cost plan including the number of templates using it.

#### Create Cost Plan
```
POST /api/admin/v1/cost_plans
```
Required Permission: `vm_template::create`

Body:
```json
{
  "name": "string",
  "amount": number,                        // Cost amount (must be >= 0)
  "currency": "string",                    // Currency code (e.g., "USD", "EUR")
  "interval_amount": number,               // Billing interval count (must be > 0)
  "interval_type": "day" | "month" | "year"  // Billing interval type
}
```

#### Update Cost Plan
```
PATCH /api/admin/v1/cost_plans/{id}
```
Required Permission: `vm_template::update`

Body (all optional):
```json
{
  "name": "string",
  "amount": number,
  "currency": "string",
  "interval_amount": number,
  "interval_type": "day" | "month" | "year"
}
```

#### Delete Cost Plan
```
DELETE /api/admin/v1/cost_plans/{id}
```
Required Permission: `vm_template::delete`

Note: Cost plans that are referenced by existing VM templates cannot be deleted.

### Custom Pricing Models Management

#### List Custom Pricing Models
```
GET /api/admin/v1/custom_pricing
```
Query Parameters:
- `limit`: number (optional) - Items per page (max 100, default 50)
- `offset`: number (optional) - Pagination offset
- `region_id`: number (optional) - Filter by region ID
- `enabled`: boolean (optional) - Filter by enabled status

Required Permission: `vm_custom_pricing::view`

Returns paginated list of custom pricing models with configuration details, region names, and disk pricing information.

#### Get Custom Pricing Model Details
```
GET /api/admin/v1/custom_pricing/{id}
```
Required Permission: `vm_custom_pricing::view`

Returns detailed information about a specific custom pricing model including associated disk pricing configurations.

#### Create Custom Pricing Model
```
POST /api/admin/v1/custom_pricing
```
Required Permission: `vm_custom_pricing::create`

Body:
```json
{
  "name": "string",
  "enabled": boolean,                    // optional, default true
  "expires": "string (ISO 8601) | null", // optional, null for no expiration
  "region_id": number,
  "currency": "string",                  // e.g., "USD", "EUR", "BTC"
  "cpu_cost": number,                   // Cost per CPU core per month
  "memory_cost": number,                // Cost per GB RAM per month
  "ip4_cost": number,                   // Cost per IPv4 address per month
  "ip6_cost": number,                   // Cost per IPv6 address per month
  "min_cpu": number,                    // Minimum CPU cores allowed
  "max_cpu": number,                    // Maximum CPU cores allowed
  "min_memory": number,                 // Minimum memory in bytes
  "max_memory": number,                 // Maximum memory in bytes
  "disk_pricing": [                     // Array of disk pricing configurations
    {
      "kind": "ssd",                    // DiskType enum: "hdd" or "ssd"
      "interface": "pcie",              // DiskInterface enum: "sata", "scsi", or "pcie"
      "cost": number,                   // Cost per GB per month
      "min_disk_size": number,          // Minimum disk size in bytes for this type/interface
      "max_disk_size": number           // Maximum disk size in bytes for this type/interface
    }
  ]
}
```

#### Update Custom Pricing Model
```
PATCH /api/admin/v1/custom_pricing/{id}
```
Required Permission: `vm_custom_pricing::update`

Body (all optional):
```json
{
  "name": "string",
  "enabled": boolean,
  "expires": "string (ISO 8601) | null",
  "region_id": number,
  "currency": "string",
  "cpu_cost": number,
  "memory_cost": number,
  "ip4_cost": number,
  "ip6_cost": number,
  "min_cpu": number,                        // Minimum CPU cores allowed
  "max_cpu": number,                        // Maximum CPU cores allowed
  "min_memory": number,                     // Minimum memory in bytes
  "max_memory": number,                     // Maximum memory in bytes
  "disk_pricing": [
    {
      "kind": "ssd",                        // DiskType enum: "hdd", "ssd"
      "interface": "pcie",                  // DiskInterface enum: "sata", "scsi", "pcie"
      "cost": number,
      "min_disk_size": number,              // Minimum disk size in bytes for this type/interface
      "max_disk_size": number               // Maximum disk size in bytes for this type/interface
    }
  ]
}
```

#### Delete Custom Pricing Model
```
DELETE /api/admin/v1/custom_pricing/{id}
```
Required Permission: `vm_custom_pricing::delete`

Note: Custom pricing models that are referenced by existing VMs cannot be deleted and will be disabled instead to preserve billing consistency.

#### List Custom Templates for Pricing Model
```
GET /api/admin/v1/custom_pricing/{pricing_id}/templates
```
Query Parameters:
- `limit`: number (optional) - Items per page (max 100, default 50)
- `offset`: number (optional) - Pagination offset

Required Permission: `vm_custom_pricing::view`

Returns paginated list of custom VM templates that use this pricing model.

#### Create Custom VM Template
```
POST /api/admin/v1/custom_pricing/{pricing_id}/templates
```
Required Permission: `vm_custom_pricing::create`

Body:
```json
{
  "cpu": number,                        // Number of CPU cores
  "memory": number,                     // Memory in bytes
  "disk_size": number,                  // Disk size in bytes
  "disk_type": "string",               // "hdd" or "ssd"
  "disk_interface": "string"           // "sata", "scsi", or "pcie"
}
```

#### Get Custom VM Template Details
```
GET /api/admin/v1/custom_templates/{id}
```
Required Permission: `vm_custom_pricing::view`

Returns detailed information about a specific custom VM template including calculated pricing breakdown.

#### Update Custom VM Template
```
PATCH /api/admin/v1/custom_templates/{id}
```
Required Permission: `vm_custom_pricing::update`

Body (all optional):
```json
{
  "cpu": number,
  "memory": number,
  "disk_size": number,
  "disk_type": "string",
  "disk_interface": "string",
  "pricing_id": number                  // Change pricing model
}
```

#### Delete Custom VM Template
```
DELETE /api/admin/v1/custom_templates/{id}
```
Required Permission: `vm_custom_pricing::delete`

Note: Custom templates that are referenced by existing VMs cannot be deleted.

#### Calculate Custom Pricing
```
POST /api/admin/v1/custom_pricing/{pricing_id}/calculate
```
Required Permission: `vm_custom_pricing::view`

Body:
```json
{
  "cpu": number,                        // Number of CPU cores
  "memory": number,                     // Memory in bytes
  "disk_size": number,                  // Disk size in bytes
  "disk_type": "ssd",                  // Enum: "hdd" or "ssd"
  "disk_interface": "pcie",            // Enum: "sata", "scsi", or "pcie"
  "ip4_count": number,                 // Number of IPv4 addresses (optional, default 1)
  "ip6_count": number                  // Number of IPv6 addresses (optional, default 1)
}
```

Returns calculated pricing breakdown for the specified configuration without creating a template:
```json
{
  "currency": "string",
  "cpu_cost": number,
  "memory_cost": number,
  "disk_cost": number,
  "ip4_cost": number,
  "ip6_cost": number,
  "total_monthly_cost": number
}
```

#### Get Region Pricing Models
```
GET /api/admin/v1/regions/{region_id}/custom_pricing
```
Query Parameters:
- `limit`: number (optional) - Items per page (max 100, default 50)
- `offset`: number (optional) - Pagination offset
- `enabled`: boolean (optional) - Filter by enabled status

Required Permission: `vm_custom_pricing::view`

Returns all custom pricing models available for a specific region.

#### Copy Custom Pricing Model
```
POST /api/admin/v1/custom_pricing/{id}/copy
```
Required Permission: `vm_custom_pricing::create`

Body:
```json
{
  "name": "string",                     // Name for the new pricing model
  "region_id": number,                  // Target region ID (optional, defaults to source region)
  "enabled": boolean                    // Enable the new pricing model (optional, default true)
}
```

Creates a copy of an existing custom pricing model with all disk pricing configurations.

### Company Management

#### List Companies
```
GET /api/admin/v1/companies
```
Query Parameters:
- `limit`: number (optional) - Items per page (max 100, default 50)
- `offset`: number (optional) - Pagination offset

Required Permission: `company::view`

Returns paginated list of companies with basic information and region count.

#### Get Company Details
```
GET /api/admin/v1/companies/{id}
```
Required Permission: `company::view`

Returns detailed information about a specific company including the number of regions assigned to it.

#### Create Company
```
POST /api/admin/v1/companies
```
Required Permission: `company::create`

Body:
```json
{
  "name": "string",                       // Required - Company name
  "address_1": "string | null",          // Optional - Primary address line
  "address_2": "string | null",          // Optional - Secondary address line
  "city": "string | null",               // Optional - City
  "state": "string | null",              // Optional - State/province
  "country_code": "string | null",       // Optional - Country code
  "tax_id": "string | null",             // Optional - Tax identification number
  "base_currency": "string",             // Required - Base currency code (EUR, USD, GBP, CAD, CHF, AUD, JPY, BTC)
  "postcode": "string | null",           // Optional - Postal/ZIP code
  "phone": "string | null",              // Optional - Phone number
  "email": "string | null"               // Optional - Contact email
}
```

The `base_currency` field is validated against the supported Currency enum values. Invalid currency codes will be rejected with an error message listing valid currencies.

#### Update Company
```
PATCH /api/admin/v1/companies/{id}
```
Required Permission: `company::update`

Body (all optional):
```json
{
  "name": "string",                       // Company name (cannot be empty if provided)
  "address_1": "string | null",          // Primary address line
  "address_2": "string | null",          // Secondary address line
  "city": "string | null",               // City
  "state": "string | null",              // State/province
  "country_code": "string | null",       // Country code
  "tax_id": "string | null",             // Tax identification number
  "base_currency": "string",             // Base currency code (EUR, USD, GBP, CAD, CHF, AUD, JPY, BTC)
  "postcode": "string | null",           // Postal/ZIP code
  "phone": "string | null",              // Phone number
  "email": "string | null"               // Contact email
}
```

The `base_currency` field is validated against the supported Currency enum values.

Note: Empty strings are treated as null values (clearing the field).

#### Delete Company
```
DELETE /api/admin/v1/companies/{id}
```
Required Permission: `company::delete`

Note: Companies with assigned regions cannot be deleted. You must first reassign or remove all regions before deleting a company.

### IP Range Management

#### List IP Ranges
```
GET /api/admin/v1/ip_ranges
```
Query Parameters:
- `limit`: number (optional) - Items per page (max 100, default 50)
- `offset`: number (optional) - Pagination offset
- `region_id`: number (optional) - Filter by region ID

Required Permission: `ip_range::view`

Returns paginated list of IP ranges with region names, access policy names, and assignment counts.

#### Get IP Range Details
```
GET /api/admin/v1/ip_ranges/{id}
```
Required Permission: `ip_range::view`

Returns detailed information about a specific IP range including region name, access policy name, and number of active IP assignments.

#### Create IP Range
```
POST /api/admin/v1/ip_ranges
```
Required Permission: `ip_range::create`

Body:
```json
{
  "cidr": "string",                          // Required - CIDR notation (e.g., "192.168.1.0/24")
  "gateway": "string",                       // Required - Gateway IP address
  "enabled": boolean,                        // Optional - Default: true
  "region_id": number,                       // Required - Region ID
  "reverse_zone_id": "string | null",       // Optional - Reverse DNS zone ID
  "access_policy_id": "number | null",      // Optional - Access policy ID
  "allocation_mode": "sequential",           // IpRangeAllocationMode enum: "random", "sequential", or "slaac_eui64", default: "sequential"
  "use_full_range": boolean                  // Optional - Use first and last IPs in range, default: false
}
```

#### Update IP Range
```
PATCH /api/admin/v1/ip_ranges/{id}
```
Required Permission: `ip_range::update`

Body (all optional):
```json
{
  "cidr": "string",                          // CIDR notation (e.g., "192.168.1.0/24")
  "gateway": "string",                       // Gateway IP address
  "enabled": boolean,                        // Enable/disable range
  "region_id": number,                       // Region ID
  "reverse_zone_id": "string | null",       // Reverse DNS zone ID (null to clear)
  "access_policy_id": "number | null",      // Access policy ID (null to clear)
  "allocation_mode": "sequential",           // IpRangeAllocationMode enum: "random", "sequential", or "slaac_eui64"
  "use_full_range": boolean                  // Use first and last IPs in range
}
```

#### Delete IP Range
```
DELETE /api/admin/v1/ip_ranges/{id}
```
Required Permission: `ip_range::delete`

Note: IP ranges with active IP assignments cannot be deleted. You must first remove all IP assignments before deleting an IP range.

### Access Policy Management

#### List Access Policies
```
GET /api/admin/v1/access_policies
```
Query Parameters:
- `limit`: number (optional) - Items per page (max 100, default 50)
- `offset`: number (optional) - Pagination offset

Required Permission: `access_policy::view`

Returns paginated list of access policies with router names and IP range usage counts.

#### Get Access Policy Details
```
GET /api/admin/v1/access_policies/{id}
```
Required Permission: `access_policy::view`

Returns detailed information about a specific access policy including router name and number of IP ranges using this policy.

#### Create Access Policy
```
POST /api/admin/v1/access_policies
```
Required Permission: `access_policy::create`

Body:
```json
{
  "name": "string",                          // Required - Policy name
  "kind": "static_arp",                      // NetworkAccessPolicyKind enum: "static_arp", default: "static_arp"
  "router_id": "number | null",              // Optional - Router ID for policy application
  "interface": "string | null"               // Optional - Interface name for policy application
}
```

#### Update Access Policy
```
PATCH /api/admin/v1/access_policies/{id}
```
Required Permission: `access_policy::update`

Body (all optional):
```json
{
  "name": "string",                          // Policy name
  "kind": "static_arp",                      // NetworkAccessPolicyKind enum: "static_arp"
  "router_id": "number | null",              // Router ID (null to clear)
  "interface": "string | null"               // Interface name (null to clear)
}
```

#### Delete Access Policy
```
DELETE /api/admin/v1/access_policies/{id}
```
Required Permission: `access_policy::delete`

Note: Access policies that are used by IP ranges cannot be deleted. You must first remove the policy from all IP ranges before deleting it.

### Router Management

#### List Routers
```
GET /api/admin/v1/routers
```
Query Parameters:
- `limit`: number (optional) - Items per page (max 100, default 50)
- `offset`: number (optional) - Pagination offset

Required Permission: `router::view`

Returns paginated list of routers with configuration details and access policy usage counts.

#### Get Router Details
```
GET /api/admin/v1/routers/{router_id}
```
Required Permission: `router::view`

Returns detailed information about a specific router including the number of access policies using this router.

#### Create Router
```
POST /api/admin/v1/routers
```
Required Permission: `router::create`

Body:
```json
{
  "name": "string",                          // Required - Router name
  "enabled": boolean,                        // Optional - Default: true
  "kind": "mikrotik",                        // RouterKind enum: "mikrotik" or "ovh_additional_ip"
  "url": "string",                           // Required - Router API URL
  "token": "string"                          // Required - Authentication token
}
```

#### Update Router
```
PATCH /api/admin/v1/routers/{router_id}
```
Required Permission: `router::update`

Body (all optional):
```json
{
  "name": "string",                          // Router name
  "enabled": boolean,                        // Enable/disable router
  "kind": "mikrotik",                        // RouterKind enum: "mikrotik" or "ovh_additional_ip"
  "url": "string",                           // Router API URL
  "token": "string"                          // Authentication token
}
```

#### Delete Router
```
DELETE /api/admin/v1/routers/{router_id}
```
Required Permission: `router::delete`

Note: Routers that are used by access policies cannot be deleted. You must first remove the router from all access policies before deleting it.

### VM IP Assignment Management

VM IP assignments bind specific IP addresses from IP ranges to virtual machines. These endpoints provide comprehensive management of these assignments.

#### List VM IP Assignments
```
GET /api/admin/v1/vm_ip_assignments
```
Query Parameters:
- `limit`: number (optional) - Items per page (max 100, default 50)
- `offset`: number (optional) - Pagination offset
- `vm_id`: number (optional) - Filter by VM ID
- `ip_range_id`: number (optional) - Filter by IP range ID
- `ip`: string (optional) - Filter by specific IP address
- `include_deleted`: boolean (optional) - Include soft-deleted assignments (default false)

Required Permission: `ip_range::view`

Returns paginated list of VM IP assignments with enriched data including user IDs, IP range CIDRs, region names, and all relevant IDs (vm_id, ip_range_id, region_id, user_id) for easy cross-referencing.

**Automatic IP Assignment:** When creating IP assignments without specifying an IP address, the system uses the IP range's allocation mode:
- **Sequential**: Assigns IPs in order, starting from the beginning of the range
- **Random**: Randomly selects available IPs from the range  
- **SLAAC EUI-64**: Uses IPv6 Stateless Address Autoconfiguration with EUI-64 (IPv6 only)

#### Get VM IP Assignment Details
```
GET /api/admin/v1/vm_ip_assignments/{id}
```
Required Permission: `ip_range::view`

Returns detailed information about a specific VM IP assignment including IP range and region details, with all relevant IDs for easy cross-referencing.

#### Create VM IP Assignment
```
POST /api/admin/v1/vm_ip_assignments
```
Required Permission: `virtual_machines::update`

Body:
```json
{
  "vm_id": number,                       // Required - VM ID to assign IP to
  "ip_range_id": number,                 // Required - IP range ID to assign from
  "ip": "string | null",                // Optional - Specific IP to assign (if null, auto-assigns from range)
  "arp_ref": "string | null",           // Optional - External ARP reference ID
  "dns_forward": "string | null",       // Optional - Forward DNS FQDN
  "dns_reverse": "string | null"        // Optional - Reverse DNS FQDN
}
```

Note: If `ip` is not provided, the system will automatically assign an available IP from the specified range using the range's allocation mode (sequential, random, or SLAAC EUI-64). If `ip` is provided, it must be within the specified IP range's CIDR and not already assigned to another VM.

**Asynchronous Processing:** This endpoint dispatches an `AssignVmIp` work job for distributed processing. The operation returns immediately with a job ID. Use the job feedback pub/sub channels to monitor progress.

Response:
```json
{
  "data": {
    "job_dispatched": true,
    "job_id": "stream-id-12345"
  }
}
```

#### Update VM IP Assignment
```
PATCH /api/admin/v1/vm_ip_assignments/{id}
```
Required Permission: `virtual_machines::update`

Body (all optional):
```json
{
  "ip": "string",                        // New IP address (must be within the IP range)
  "arp_ref": "string | null",           // ARP reference ID (null to clear)
  "dns_forward": "string | null",       // Forward DNS FQDN (null to clear)
  "dns_reverse": "string | null"        // Reverse DNS FQDN (null to clear)
}
```

**Asynchronous Processing:** This endpoint dispatches an `UpdateVmIp` work job for distributed processing. The operation returns immediately with a job ID.

Response:
```json
{
  "data": {
    "job_dispatched": true,
    "job_id": "stream-id-12345"
  }
}
```

#### Delete VM IP Assignment
```
DELETE /api/admin/v1/vm_ip_assignments/{id}
```
Required Permission: `virtual_machines::update`

Soft-deletes the VM IP assignment, marking it as deleted rather than permanently removing it from the database.

Response:
```json
{
  "data": {
    "job_id": "stream-id-12345"
  }
}
```

**Asynchronous Processing:** This endpoint dispatches an `UnassignVmIp` work job for distributed processing. The operation returns immediately with a job ID.

### Work Job Feedback System

Many admin endpoints now dispatch work jobs for asynchronous processing instead of blocking operations. This provides better performance and scalability for resource-intensive operations.

#### Job Feedback Channels

Work jobs publish real-time feedback via Redis pub/sub channels:

**Specific job feedback:** `worker:feedback:{job_id}` - Monitor a specific job
**Global feedback:** `worker:feedback` - Monitor all job activity

#### Job Feedback Message Format

Job feedback messages use Rust enum serialization where the enum variant becomes the key. Here are the possible status formats:

**Job Started:**
```json
{
  "job_id": "stream-id-12345",
  "job_type": "StartVm",
  "status": "Started",
  "timestamp": 1640995200,
  "metadata": {}
}
```

**Job Progress:**
```json
{
  "job_id": "stream-id-12345", 
  "job_type": "StartVm",
  "status": {
    "Progress": {
      "percent": 50,
      "message": "Configuring network..."
    }
  },
  "timestamp": 1640995200,
  "metadata": {}
}
```

**Job Completed:**
```json
{
  "job_id": "stream-id-12345",
  "job_type": "StartVm", 
  "status": {
    "Completed": {
      "result": "VM started successfully"
    }
  },
  "timestamp": 1640995200,
  "metadata": {}
}
```

**Job Failed:**
```json
{
  "job_id": "stream-id-12345",
  "job_type": "StartVm",
  "status": {
    "Failed": {
      "error": "VM failed to start: insufficient resources"
    }
  },
  "timestamp": 1640995200,
  "metadata": {}
}
```

**Job Cancelled:**
```json
{
  "job_id": "stream-id-12345",
  "job_type": "StartVm",
  "status": {
    "Cancelled": {
      "reason": "Admin cancelled operation"
    }
  },
  "timestamp": 1640995200,
  "metadata": {}
}
```

#### Job Status Types

- **Started** - Job has begun execution
- **Progress** - Job progress with percentage (0-100) and optional message
- **Completed** - Job completed successfully with optional result message
- **Failed** - Job failed with detailed error message
- **Cancelled** - Job was cancelled with optional reason

#### Work Job Types

The following admin operations are processed asynchronously via work jobs:

- **CreateVm** - Create a VM for a specific user (admin action)
- **StartVm** - Start a VM via the provisioner
- **StopVm** - Stop a VM via the provisioner  
- **DeleteVm** - Delete a VM and clean up resources
- **ProcessVmRefund** - Process automated VM refunds
- **AssignVmIp** - Assign IP address to VM via provisioner
- **UnassignVmIp** - Remove IP assignment from VM via provisioner
- **UpdateVmIp** - Update VM IP assignment configuration
- **ConfigureVm** - Re-configure VM using current database settings
- **BulkMessage** - Send bulk messages to active customers

#### Monitoring Job Progress

To monitor job progress, subscribe to the appropriate Redis pub/sub channel:

```bash
# Monitor all job activity
redis-cli SUBSCRIBE worker:feedback

# Monitor specific job
redis-cli SUBSCRIBE worker:feedback:stream-id-12345
```

**Integration Notes:**
- All job feedback messages are JSON-encoded
- Jobs include unique worker IDs for tracking which worker processed the job
- Failed jobs include detailed error messages for debugging
- Completed jobs may include result data or success confirmations

#### WebSocket Endpoints

For real-time job monitoring via WebSocket connections:

##### Job Feedback WebSocket
```
GET /api/admin/v1/jobs/feedback?auth={auth_token}&job_id={job_id} (WebSocket)
```
Required Permission: Any admin role

**Query Parameters:**
- `auth`: Base64-encoded NIP-98 authentication token (required, since WebSocket headers aren't supported in browsers)
- `job_id`: Specific job ID to monitor (optional, omit for global monitoring)

Establishes a WebSocket connection that streams job feedback messages. When `job_id` is provided, only feedback for that specific job is sent. When omitted, all job feedback is streamed.

**Message Types:**

All messages are structured with a `type` field for consistent handling:

- **Connected**: 
  ```json
  {
    "type": "connected", 
    "message": "Job feedback stream connected"
  }
  ```
  Or for specific job:
  ```json
  {
    "type": "connected", 
    "message": "Connected to job {job_id} feedback stream"
  }
  ```

- **Pong Response**: 
  ```json
  {"type": "pong"}
  ```

- **Error Messages**: 
  ```json
  {
    "type": "error", 
    "error": "Error description"
  }
  ```

- **Job Feedback**: 
  ```json
  {
    "type": "job_feedback",
    "feedback": {
      "job_id": "stream-id-12345",
      "worker_id": "worker-uuid",
      "job_type": "StartVm",
      "status": "Started",
      "timestamp": "2024-01-15T10:30:00Z"
    }
  }
  ```
  
  Or for progress/completion:
  ```json
  {
    "type": "job_feedback", 
    "feedback": {
      "job_id": "stream-id-12345",
      "worker_id": "worker-uuid",
      "job_type": "CreateVm",
      "status": {
        "Completed": {
          "result": "VM 456 created successfully for user 123"
        }
      },
      "timestamp": "2024-01-15T10:35:00Z"
    }
  }
  ```


### Reports

#### Time Series Report
```
GET /api/admin/v1/reports/time-series
```
Query Parameters:
- `start_date`: string (required) - YYYY-MM-DD format
- `end_date`: string (required) - YYYY-MM-DD format
- `company_id`: number (required)
- `currency`: string (optional) - EUR, USD, GBP, CAD, CHF, AUD, JPY, BTC

Required Permission: `analytics::view`

Response:
```json
{
  "data": {
    "start_date": "2025-01-01",
    "end_date": "2025-12-31",
    "payments": [
      {
        "id": "a1b2c3d4e5f6...",
        "vm_id": 123,
        "created": "2025-01-15T10:30:45Z",
        "expires": "2025-02-15T10:30:45Z",
        "amount": 125000,
        "currency": "USD",
        "payment_method": "lightning",
        "external_id": "inv_12345",
        "is_paid": true,
        "rate": 1.0,
        "time_value": 2592000,
        "tax": 26250,
        "company_id": 1,
        "company_name": "Acme Corp",
        "company_base_currency": "USD"
      }
    ]
  }
}
```

#### Referral Usage Time Series Report
```
GET /api/admin/v1/reports/referral-usage/time-series
```
Query Parameters:
- `start_date`: string (required) - YYYY-MM-DD format
- `end_date`: string (required) - YYYY-MM-DD format  
- `company_id`: number (required)
- `ref_code`: string (optional)

Required Permission: `analytics::view`

Response:
```json
{
  "data": {
    "start_date": "2025-01-01",
    "end_date": "2025-12-31",
    "referrals": [
      {
        "vm_id": 123,
        "ref_code": "PROMO2025",
        "created": "2025-01-15T10:30:45Z",
        "amount": 125000,
        "currency": "USD",
        "rate": 1.0,
        "base_currency": "USD"
      }
    ]
  }
}
```


## Error Responses

All error responses follow the format:
```json
{
  "error": string  // Error message
}
```

Common HTTP status codes:
- `400` - Bad Request (invalid input)
- `401` - Unauthorized (invalid or missing authentication)
- `403` - Forbidden (insufficient permissions)
- `404` - Not Found
- `500` - Internal Server Error

## Pagination

Endpoints that return lists support pagination through the following query parameters:
- `limit` - Number of items to return (default varies by endpoint)
- `offset` - Number of items to skip (default: 0)

Example:
```
GET /api/admin/v1/users?limit=10&offset=20
```

## Search and Filtering

Some endpoints support additional query parameters for search and filtering:
- `search` - Search by user pubkey (hex format) for user endpoints
- `user_id` - Filter VMs by user ID
- `host_id` - Filter VMs by host ID
- Additional filters may be available for specific endpoints

Example:
```
GET /api/admin/v1/vms?user_id=123&limit=10
```

## Available Permissions

The RBAC system uses the following permission format: `resource::action`

### Resources:
- `users` - User management
- `virtual_machines` - VM management  
- `hosts` - Host/server management
- `payments` - Payment and billing management
- `analytics` - Analytics and reporting
- `system` - System configuration
- `roles` - Role and permission management
- `audit` - Audit log access
- `access_policy` - Access policy management
- `company` - Company/organization management
- `ip_range` - IP address range management
- `router` - Network router configuration
- `vm_custom_pricing` - Custom VM pricing models
- `host_region` - Host region configuration
- `vm_os_image` - VM operating system images
- `vm_payment` - VM-specific payment management
- `vm_template` - VM template management
- `subscriptions` - Subscription management
- `subscription_line_items` - Subscription line item management
- `subscription_payments` - Subscription payment management

### Actions:
- `create` - Create new resources
- `view` - Read/view resources
- `update` - Modify existing resources
- `delete` - Delete resources

### Example Permissions:
- `users::view` - View user information
- `users::update` - Modify user accounts
- `virtual_machines::view` - View VM information
- `virtual_machines::delete` - Delete VMs
- `roles::create` - Create new roles
- `host_region::view` - View host regions
- `vm_template::create` - Create VM templates
- `ip_range::update` - Modify IP address ranges
- `vm_custom_pricing::delete` - Remove custom pricing models
- `company::view` - View company information
- `subscriptions::view` - View subscriptions
- `subscriptions::create` - Create new subscriptions
- `subscription_line_items::update` - Modify subscription line items
- `subscription_payments::view` - View subscription payments

## Response Models

### AdminRefundAmountInfo
```json
{
  "amount": number,      // Refund amount in smallest currency units (cents for fiat, milli-sats for BTC)
  "currency": "string",  // Currency code (USD, EUR, BTC, etc.)
  "rate": number,        // Exchange rate used for calculation
  "expires": "string",   // VM expiry date (ISO 8601)
  "seconds_remaining": number  // Seconds until VM expires
}
```

### AdminUserInfo
```json
{
  "id": number,
  "pubkey": "string (hex)",
  "created": "string (ISO 8601)",
  "email": "string | null",
  "contact_nip17": boolean,
  "contact_email": boolean,
  "country_code": "string | null",
  "billing_name": "string | null",
  "billing_address_1": "string | null",
  "billing_address_2": "string | null",
  "billing_city": "string | null",
  "billing_state": "string | null",
  "billing_postcode": "string | null",
  "billing_tax_id": "string | null",
  "vm_count": number,
  "last_login": "string (ISO 8601) | null",
  "is_admin": boolean
}
```

### AdminVmInfo
```json
{
  "id": number,                       // VM ID
  "created": "string (ISO 8601)",
  "expires": "string (ISO 8601)",
  "mac_address": "string",
  "image_id": number,                 // OS image ID for linking
  "image_name": "string",             // OS distribution, version and flavor (e.g., "Ubuntu 22.04 Server")
  "template_id": number,              // Template ID for linking (standard templates)
  "template_name": "string",          // Template name - shows "Custom - {pricing_name}" for custom templates
  "custom_template_id": number | null, // Custom template ID if using custom template
  "is_standard_template": boolean,    // True for standard templates, false for custom templates
  "ssh_key_id": number,               // SSH key ID for linking
  "ssh_key_name": "string",           // Simplified: SSH key name only
  "ip_addresses": [                   // Array of IP address objects with IDs for linking
    {
      "id": number,                   // IP assignment ID for linking
      "ip": "string",                 // IP address
      "range_id": number              // IP range ID for linking to range details
    }
  ],
  "running_state": {                  // Full VM running state with metrics (null if unavailable)
    "timestamp": number,              // Unix timestamp of when state was collected
    "state": "running",               // VmRunningStates enum: "running", "stopped", "starting", "deleting"
    "cpu_usage": number,              // Current CPU usage percentage (0.0-100.0)
    "mem_usage": number,              // Current memory usage percentage (0.0-100.0)
    "uptime": number,                 // VM uptime in seconds
    "net_in": number,                 // Network bytes received
    "net_out": number,                // Network bytes transmitted
    "disk_write": number,             // Disk bytes written
    "disk_read": number               // Disk bytes read
  } | null,
  "auto_renewal_enabled": boolean,    // Whether automatic renewal via NWC is enabled
  "cpu": number,                      // Number of CPU cores allocated
  "memory": number,                   // Memory in bytes allocated
  "disk_size": number,                // Disk size in bytes
  "disk_type": "ssd",                 // DiskType enum: "hdd" or "ssd"
  "disk_interface": "pcie",           // DiskInterface enum: "sata", "scsi", or "pcie"
  "host_id": number,
  "user_id": number,
  "user_pubkey": "string (hex)",
  "user_email": "string | null",
  "host_name": "string",
  "region_id": number,
  "region_name": "string",
  "deleted": boolean,
  "ref_code": "string | null"
}
```

### AdminRoleInfo
```json
{
  "id": number,
  "name": "string",
  "description": "string | null",
  "is_system_role": boolean,
  "permissions": ["string"],
  "user_count": number,
  "created_at": "string (ISO 8601)",
  "updated_at": "string (ISO 8601)"
}
```

### UserRoleInfo
```json
{
  "role": {
    "id": number,
    "name": "string",
    "description": "string | null",
    "is_system_role": boolean,
    "permissions": ["string"],
    "user_count": number,
    "created_at": "string (ISO 8601)",
    "updated_at": "string (ISO 8601)"
  },
  "assigned_by": "number | null",
  "assigned_at": "string (ISO 8601)",
  "expires_at": "string (ISO 8601) | null",
  "is_active": boolean
}
```

### AdminHostInfo
```json
{
  "id": number,
  "name": "string",
  "kind": "proxmox",                      // VmHostKind enum: "proxmox", "libvirt"
  "region": {
    "id": number,
    "name": "string",
    "enabled": boolean
  },
  "ip": "string",
  "cpu": number,
  "memory": number,
  "enabled": boolean,
  "load_cpu": number,
  "load_memory": number,
  "load_disk": number,
  "vlan_id": "number | null",
  "disks": [
    {
      "id": number,
      "name": "string",
      "size": number,
      "kind": "ssd",                        // DiskType enum: "hdd", "ssd"
      "interface": "pcie",                  // DiskInterface enum: "sata", "scsi", "pcie"
      "enabled": boolean
    }
  ],
  "calculated_load": {
    "overall_load": number,                 // Overall load percentage (0.0-1.0)
    "cpu_load": number,                     // CPU load percentage (0.0-1.0)
    "memory_load": number,                  // Memory load percentage (0.0-1.0)
    "disk_load": number,                    // Disk load percentage (0.0-1.0)
    "available_cpu": number,                // Available CPU cores
    "available_memory": number,             // Available memory in bytes
    "active_vms": number                    // Number of active VMs on this host
  }
}
```


### AdminRegionInfo
```json
{
  "id": number,
  "name": "string",
  "enabled": boolean,
  "company_id": "number | null",
  "host_count": number,
  "total_vms": number,  // Count of active (non-deleted) VMs only
  "total_cpu_cores": number,
  "total_memory_bytes": number,  // Total memory in bytes (not GB)
  "total_ip_assignments": number  // IP assignments from active VMs only
}
```


### RegionDeleteResponse
```json
{
  "success": boolean,
  "message": "string"
}
```

### AdminHostDisk
```json
{
  "id": number,
  "name": "string",
  "size": number,
  "kind": "string",
  "interface": "string",
  "enabled": boolean
}
```

### AdminVmHistoryInfo
```json
{
  "id": number,
  "vm_id": number,
  "action_type": "started",               // AdminVmHistoryActionType enum: "created", "started", "stopped", etc.
  "timestamp": "string (ISO 8601)",       // When this action occurred
  "initiated_by_user": number | null,     // User ID who initiated this action (if applicable)
  "initiated_by_user_pubkey": "string | null", // Hex-encoded pubkey of initiating user
  "initiated_by_user_email": "string | null",  // Email of initiating user
  "description": "string | null"          // Human-readable description of the action
}
```

### AdminVmPaymentInfo
```json
{
  "id": "string",                         // Hex-encoded payment ID
  "vm_id": number,
  "created": "string (ISO 8601)",         // When payment was created
  "expires": "string (ISO 8601)",         // When payment expires
  "amount": number,                       // Amount in smallest currency unit (satoshis, cents)
  "currency": "string",                   // Currency code (e.g., "EUR", "USD", "BTC")
  "payment_method": "lightning",          // AdminPaymentMethod enum: "lightning", "revolut", "paypal", "stripe"
  "external_id": "string | null",         // External payment provider ID
  "is_paid": boolean,                     // Whether payment has been completed
  "rate": number                          // Exchange rate to base currency (EUR)
}
```

### AdminSubscriptionInfo
```json
{
  "id": number,
  "user_id": number,
  "name": "string",
  "description": "string | null",
  "created": "string (ISO 8601)",
  "expires": "string (ISO 8601) | null",
  "is_active": boolean,
  "currency": "string",                     // "USD", "EUR", "BTC", "GBP", "CAD", "CHF", "AUD", "JPY"
  "interval_amount": number,                // Billing cycle multiplier (e.g., 1, 3, 12)
  "interval_type": "day" | "month" | "year",
  "setup_fee": number,                      // One-time setup fee in cents/millisats
  "auto_renewal_enabled": boolean,
  "external_id": "string | null",          // External payment processor ID (Stripe, PayPal, etc.)
  "line_items": [                          // All services included in this subscription
    {
      "id": number,
      "subscription_id": number,
      "name": "string",
      "description": "string | null",
      "amount": number,                     // Recurring cost per billing cycle in cents/millisats
      "setup_amount": number,               // One-time setup fee in cents/millisats
      "configuration": object               // Service-specific JSON configuration
    }
  ],
  "payment_count": number                   // Total number of payments for this subscription
}
```

### AdminSubscriptionLineItemInfo
```json
{
  "id": number,
  "subscription_id": number,
  "name": "string",
  "description": "string | null",
  "amount": number,                        // Recurring cost per billing cycle in cents/millisats
  "setup_amount": number,                  // One-time setup fee in cents/millisats
  "configuration": object | null           // Service-specific JSON configuration
}
```

### AdminSubscriptionPaymentInfo
```json
{
  "id": "string",                          // Hex-encoded payment ID
  "subscription_id": number,
  "user_id": number,
  "created": "string (ISO 8601)",
  "expires": "string (ISO 8601) | null",
  "amount": number,                        // Total amount in cents/millisats
  "currency": "string",                    // "USD", "EUR", "BTC", etc.
  "payment_method": "lightning" | "revolut" | "paypal" | "stripe",
  "payment_type": "purchase" | "renewal",  // SubscriptionPaymentType enum
  "is_paid": boolean,
  "rate": number | null,                   // Exchange rate if applicable
  "time_value": number,                    // Duration purchased in seconds
  "tax": number,                           // Tax amount in cents/millisats
  "external_id": "string | null",         // External payment processor ID
  "company_id": number | null,            // Associated company ID
  "company_name": "string | null",        // Associated company name
  "company_base_currency": "string | null" // Company's base currency
}
```

### AdminVmOsImageInfo
```json
{
  "id": number,
  "distribution": "debian",    // ApiOsDistribution enum: "ubuntu", "debian", "centos", "fedora", "freebsd", "opensuse", "archlinux", "redhatenterprise"
  "flavour": "string",
  "version": "string",
  "enabled": boolean,
  "release_date": "string (ISO 8601)",
  "url": "string",
  "default_username": "string | null",
  "active_vm_count": number              // Number of active (non-deleted) VMs using this image
}
```

### AdminVmTemplateInfo
```json
{
  "id": number,
  "name": "string",
  "enabled": boolean,
  "created": "string (ISO 8601)",
  "expires": "string (ISO 8601) | null",
  "cpu": number,
  "memory": number,
  "disk_size": number,
  "disk_type": "ssd",         // DiskType enum: "hdd" or "ssd"
  "disk_interface": "pcie",   // DiskInterface enum: "sata", "scsi", or "pcie"
  "cost_plan_id": number,
  "region_id": number,
  "region_name": "string | null",    // Populated with region name
  "cost_plan_name": "string | null", // Populated with cost plan name
  "active_vm_count": number          // Number of active (non-deleted) VMs using this template
}
```

### AdminCustomPricingInfo
```json
{
  "id": number,
  "name": "string",
  "enabled": boolean,
  "created": "string (ISO 8601)",
  "expires": "string (ISO 8601) | null",
  "region_id": number,
  "region_name": "string | null",       // Populated with region name
  "currency": "string",                 // e.g., "USD", "EUR", "BTC"
  "cpu_cost": number,                   // Cost per CPU core per month
  "memory_cost": number,                // Cost per GB RAM per month
  "ip4_cost": number,                   // Cost per IPv4 address per month
  "ip6_cost": number,                   // Cost per IPv6 address per month
  "min_cpu": number,                    // Minimum CPU cores allowed
  "max_cpu": number,                    // Maximum CPU cores allowed
  "min_memory": number,                 // Minimum memory in bytes
  "max_memory": number,                 // Maximum memory in bytes
  "disk_pricing": [                     // Array of disk pricing configurations
    {
      "id": number,
      "kind": "ssd",                    // DiskType enum: "hdd" or "ssd"
      "interface": "pcie",              // DiskInterface enum: "sata", "scsi", or "pcie"
      "cost": number,                   // Cost per GB per month
      "min_disk_size": number,          // Minimum disk size in bytes for this type/interface
      "max_disk_size": number           // Maximum disk size in bytes for this type/interface
    }
  ],
  "template_count": number              // Number of custom templates using this pricing
}
```

### AdminCustomTemplateInfo
```json
{
  "id": number,
  "cpu": number,                        // Number of CPU cores
  "memory": number,                     // Memory in bytes
  "disk_size": number,                  // Disk size in bytes
  "disk_type": "ssd",                  // Enum: "hdd" or "ssd"
  "disk_interface": "pcie",            // Enum: "sata", "scsi", or "pcie"
  "pricing_id": number,
  "pricing_name": "string | null",     // Populated with pricing model name
  "region_id": number,                 // From associated pricing model
  "region_name": "string | null",     // From associated pricing model
  "currency": "string",                // From associated pricing model
  "calculated_cost": {                 // Calculated monthly cost breakdown
    "cpu_cost": number,
    "memory_cost": number,
    "disk_cost": number,
    "ip4_cost": number,                // Based on default 1 IPv4
    "ip6_cost": number,                // Based on default 1 IPv6
    "total_monthly_cost": number
  },
  "vm_count": number                   // Number of VMs using this template
}
```

### AdminCompanyInfo
```json
{
  "id": number,
  "created": "string (ISO 8601)",
  "name": "string",
  "address_1": "string | null",
  "address_2": "string | null",
  "city": "string | null",
  "state": "string | null",
  "country_code": "string | null",
  "tax_id": "string | null",
  "base_currency": "string",           // Company's base currency (EUR, USD, GBP, CAD, CHF, AUD, JPY, BTC)
  "postcode": "string | null",
  "phone": "string | null",
  "email": "string | null",
  "region_count": number               // Number of regions assigned to this company
}
```

### AdminIpRangeInfo
```json
{
  "id": number,
  "cidr": "string",                    // CIDR notation (e.g., "192.168.1.0/24")
  "gateway": "string",                 // Gateway IP address
  "enabled": boolean,
  "region_id": number,
  "region_name": "string | null",     // Populated with region name
  "reverse_zone_id": "string | null", // DNS reverse zone ID
  "access_policy_id": "number | null",
  "access_policy_name": "string | null", // Populated with access policy name
  "allocation_mode": "sequential",     // IpRangeAllocationMode enum: "random", "sequential", or "slaac_eui64"
  "use_full_range": boolean,           // Whether to use first and last IPs in range
  "assignment_count": number           // Number of active IP assignments in this range
}
```

### AdminAccessPolicyInfo
```json
{
  "id": number,
  "name": "string",
  "kind": "static_arp",                // NetworkAccessPolicyKind enum: "static_arp" 
  "router_id": "number | null",       // Router ID for policy application
  "interface": "string | null"        // Interface name for policy application
}
```

### AdminAccessPolicyDetail
```json
{
  "id": number,
  "name": "string",
  "kind": "static_arp",                // NetworkAccessPolicyKind enum: "static_arp"
  "router_id": "number | null",       // Router ID for policy application
  "router_name": "string | null",     // Populated with router name
  "interface": "string | null",       // Interface name for policy application
  "ip_range_count": number             // Number of IP ranges using this policy
}
```

### AdminRouterDetail
```json
{
  "id": number,
  "name": "string",
  "enabled": boolean,
  "kind": "ovh_additional_ip",         // RouterKind enum: "mikrotik" or "ovh_additional_ip"
  "url": "string",                     // Router API URL
  "access_policy_count": number        // Number of access policies using this router
}
```

### CustomPricingCalculation
```json
{
  "currency": "string",
  "cpu_cost": number,                   // Cost for specified CPU cores
  "memory_cost": number,                // Cost for specified memory
  "disk_cost": number,                  // Cost for specified disk size
  "ip4_cost": number,                   // Cost for specified IPv4 addresses
  "ip6_cost": number,                   // Cost for specified IPv6 addresses
  "total_monthly_cost": number,         // Sum of all costs
  "configuration": {                    // Echo of input configuration
    "cpu": number,
    "memory": number,
    "disk_size": number,
    "disk_type": "string",
    "disk_interface": "string",
    "ip4_count": number,
    "ip6_count": number
  }
}
```

### AdminCostPlanInfo
```json
{
  "id": number,
  "name": "string",
  "created": "string (ISO 8601)",
  "amount": number,                         // Cost amount
  "currency": "string",                     // Currency code (e.g., "USD", "EUR")
  "interval_amount": number,                // Billing interval count
  "interval_type": "day" | "month" | "year", // Billing interval type
  "template_count": number                  // Number of VM templates using this cost plan
}
```

### ReferralReport
```json
{
  "vm_id": number,
  "ref_code": "string",
  "created": "string (ISO 8601)",
  "amount": number,
  "currency": "string",
  "rate": number,
  "base_currency": "string"
}
```

### ReferralTimeSeriesReport
```json
{
  "start_date": "string",
  "end_date": "string",
  "referrals": ["ReferralReport"]
}
```

### TimeSeriesPayment
```json
{
  "id": "string",                    // Hex-encoded payment ID
  "vm_id": number,
  "created": "string (ISO 8601)",
  "expires": "string (ISO 8601)",
  "amount": number,                  // Amount in smallest currency unit
  "currency": "string",
  "payment_method": "string",
  "external_id": "string | null",
  "is_paid": boolean,
  "rate": number,                    // Exchange rate to company's base currency
  "time_value": number,              // Seconds this payment adds to VM expiry
  "tax": number,                     // Tax amount in smallest currency unit
  "company_id": number,
  "company_name": "string",
  "company_base_currency": "string"
}
```

### TimeSeriesReport
```json
{
  "start_date": "string",
  "end_date": "string",
  "payments": ["TimeSeriesPayment"]
}
```

### AdminVmIpAddress
```json
{
  "id": number,                      // IP assignment ID for linking
  "ip": "string",                    // IP address
  "range_id": number                 // IP range ID for linking to range details
}
```

### CalculatedHostLoad
```json
{
  "overall_load": number,            // Overall load percentage (0.0-1.0)
  "cpu_load": number,                // CPU load percentage (0.0-1.0)
  "memory_load": number,             // Memory load percentage (0.0-1.0)
  "disk_load": number,               // Disk load percentage (0.0-1.0)
  "available_cpu": number,           // Available CPU cores
  "available_memory": number,        // Available memory in bytes
  "active_vms": number               // Number of active VMs on this host
}
```

### AdminHostRegion
```json
{
  "id": number,
  "name": "string",
  "enabled": boolean
}
```

### AdminCustomPricingDisk
```json
{
  "id": number,
  "kind": "ssd",                     // DiskType enum: "hdd" or "ssd"
  "interface": "pcie",               // DiskInterface enum: "sata", "scsi", or "pcie"
  "cost": number,
  "min_disk_size": number,           // Minimum disk size in bytes for this type/interface
  "max_disk_size": number            // Maximum disk size in bytes for this type/interface
}
```

### AdminVmIpAssignmentInfo
```json
{
  "id": number,                      // Assignment ID
  "vm_id": number,                   // VM ID this IP is assigned to
  "ip_range_id": number,             // IP range ID this IP belongs to
  "region_id": number,               // Region ID containing the IP range
  "user_id": number,                 // User ID who owns the VM
  "ip": "string",                    // The assigned IP address (IPv4 or IPv6)
  "deleted": boolean,                // Whether this assignment is soft-deleted
  "arp_ref": "string | null",       // External ARP reference ID
  "dns_forward": "string | null",   // Forward DNS FQDN
  "dns_forward_ref": "string | null", // External reference for forward DNS entry
  "dns_reverse": "string | null",   // Reverse DNS FQDN
  "dns_reverse_ref": "string | null", // External reference for reverse DNS entry
  "ip_range_cidr": "string | null", // CIDR notation of the IP range
  "region_name": "string | null"    // Name of the region containing the IP range
}
```

### CustomPricingCalculation
```json
{
  "currency": "string",
  "cpu_cost": number,                // Cost for specified CPU cores
  "memory_cost": number,             // Cost for specified memory
  "disk_cost": number,               // Cost for specified disk size
  "ip4_cost": number,                // Cost for specified IPv4 addresses
  "ip6_cost": number,                // Cost for specified IPv6 addresses
  "total_monthly_cost": number,      // Sum of all costs
  "configuration": {                 // Echo of input configuration
    "cpu": number,
    "memory": number,
    "disk_size": number,
    "disk_type": "string",
    "disk_interface": "string",
    "ip4_count": number,
    "ip6_count": number
  }
}
```

---

## IP Space Management

### List IP Spaces
```
GET /api/admin/v1/ip_space
```
Query Parameters:
- `limit`: number (optional) - max 100, default 50
- `offset`: number (optional) - default 0
- `is_available`: boolean (optional) - filter by availability
- `registry`: number (optional) - 0=ARIN, 1=RIPE, 2=APNIC, 3=LACNIC, 4=AFRINIC

Required Permission: `ip_space::view`

Response: Paginated list of `AdminAvailableIpSpaceInfo`

### Get IP Space
```
GET /api/admin/v1/ip_space/{id}
```
Required Permission: `ip_space::view`

Response: Single `AdminAvailableIpSpaceInfo`

### Create IP Space
```
POST /api/admin/v1/ip_space
```
Request Body: `CreateAvailableIpSpaceRequest`

Required Permission: `ip_space::create`

Response: Created `AdminAvailableIpSpaceInfo`

### Update IP Space
```
PATCH /api/admin/v1/ip_space/{id}
```
Request Body: `UpdateAvailableIpSpaceRequest`

Required Permission: `ip_space::update`

Response: Updated `AdminAvailableIpSpaceInfo`

### Delete IP Space
```
DELETE /api/admin/v1/ip_space/{id}
```
Required Permission: `ip_space::delete`

Response: Empty success response

Error: `"Cannot delete IP space with active subscriptions. Please cancel subscriptions first."` if active subscriptions exist

### List IP Space Pricing
```
GET /api/admin/v1/ip_space/{id}/pricing
```
Query Parameters:
- `limit`: number (optional) - max 100, default 50
- `offset`: number (optional) - default 0

Required Permission: `ip_space::view`

Response: Paginated list of `AdminIpSpacePricingInfo`

### Get IP Space Pricing
```
GET /api/admin/v1/ip_space/{space_id}/pricing/{pricing_id}
```
Required Permission: `ip_space::view`

Response: Single `AdminIpSpacePricingInfo`

### Create IP Space Pricing
```
POST /api/admin/v1/ip_space/{id}/pricing
```
Request Body: `CreateIpSpacePricingRequest`

Required Permission: `ip_space::create`

Response: Created `AdminIpSpacePricingInfo`

Errors:
- `"Prefix size must be between {min} and {max}"` - prefix_size outside space bounds
- `"Pricing already exists for prefix size /{size}"` - duplicate pricing

### Update IP Space Pricing
```
PATCH /api/admin/v1/ip_space/{space_id}/pricing/{pricing_id}
```
Request Body: `UpdateIpSpacePricingRequest`

Required Permission: `ip_space::update`

Response: Updated `AdminIpSpacePricingInfo`

Errors:
- `"Pricing does not belong to the specified IP space"` - mismatched IDs
- `"Prefix size must be between {min} and {max}"` - prefix_size outside space bounds
- `"Pricing already exists for prefix size /{size}"` - duplicate pricing

### Delete IP Space Pricing
```
DELETE /api/admin/v1/ip_space/{space_id}/pricing/{pricing_id}
```
Required Permission: `ip_space::delete`

Response: Empty success response

### List IP Space Subscriptions
```
GET /api/admin/v1/ip_space/{id}/subscriptions
```
Query Parameters:
- `limit`: number (optional) - max 100, default 50
- `offset`: number (optional) - default 0
- `user_id`: number (optional) - filter by user
- `is_active`: boolean (optional) - filter by active status

Required Permission: `subscriptions::view`

Response: Paginated list of `AdminIpRangeSubscriptionInfo`

---

## IP Space Data Types

### AdminAvailableIpSpaceInfo
```json
{
  "id": number,
  "cidr": "string",                      // e.g., "192.168.0.0/22"
  "min_prefix_size": number,             // e.g., 24 (smallest allocation /24)
  "max_prefix_size": number,             // e.g., 22 (largest allocation /22)
  "registry": {
    "value": number,                     // 0=ARIN, 1=RIPE, 2=APNIC, 3=LACNIC, 4=AFRINIC
    "name": "string"                     // "ARIN", "RIPE", etc.
  },
  "external_id": "string | null",        // RIR allocation ID (e.g., "NET-192-168-0-0-1")
  "is_available": boolean,               // Whether space is available for allocation
  "is_reserved": boolean,                // Whether space is reserved for special use
  "metadata": object | null,             // JSON metadata (routing requirements, upstream provider, etc.)
  "pricing_count": number                // Number of pricing tiers configured
}
```

### CreateAvailableIpSpaceRequest
```json
{
  "cidr": "string",                      // CIDR notation (validated)
  "min_prefix_size": number,             // Must be <= max_prefix_size
  "max_prefix_size": number,             // Must be >= min_prefix_size
  "registry": number,                    // 0=ARIN, 1=RIPE, 2=APNIC, 3=LACNIC, 4=AFRINIC
  "external_id": "string | null",        // Optional RIR allocation ID
  "is_available": boolean,               // Optional, default: true
  "is_reserved": boolean,                // Optional, default: false
  "metadata": object | null              // Optional JSON metadata
}
```

### UpdateAvailableIpSpaceRequest
```json
{
  "cidr": "string | null",               // Optional CIDR update (validated)
  "min_prefix_size": number | null,      // Optional, must be <= max_prefix_size
  "max_prefix_size": number | null,      // Optional, must be >= min_prefix_size
  "registry": number | null,             // Optional registry update
  "external_id": "string | null",        // Optional, null to clear
  "is_available": boolean | null,        // Optional availability update
  "is_reserved": boolean | null,         // Optional reserved status update
  "metadata": object | null              // Optional, null to clear
}
```

### AdminIpSpacePricingInfo
```json
{
  "id": number,
  "available_ip_space_id": number,       // Parent IP space ID
  "prefix_size": number,                 // e.g., 24 for /24 subnet
  "price_per_month": number,             // Monthly recurring price in cents/millisats
  "currency": "string",                  // e.g., "USD", "EUR", "BTC"
  "setup_fee": number,                   // One-time setup fee in cents/millisats
  "cidr": "string | null"                // Parent CIDR for context (populated by API)
}
```

### CreateIpSpacePricingRequest
```json
{
  "prefix_size": number,                 // Must be within space's min/max bounds
  "price_per_month": number,             // In cents/millisats (cannot be negative)
  "currency": "string | null",           // Optional, default: "USD"
  "setup_fee": number | null             // Optional, default: 0
}
```

### UpdateIpSpacePricingRequest
```json
{
  "prefix_size": number | null,          // Optional, must be within space's min/max bounds
  "price_per_month": number | null,      // Optional (cannot be negative)
  "currency": "string | null",           // Optional currency update
  "setup_fee": number | null             // Optional (cannot be negative)
}
```

### AdminIpRangeSubscriptionInfo
```json
{
  "id": number,
  "subscription_line_item_id": number,   // Links to subscription line item
  "available_ip_space_id": number,       // IP space this was allocated from
  "cidr": "string",                      // Allocated CIDR e.g., "192.168.1.0/24"
  "is_active": boolean,                  // Whether subscription is active
  "started_at": "string",                // ISO 8601 datetime
  "ended_at": "string | null",           // ISO 8601 datetime or null if active
  "metadata": object | null,             // JSON metadata (routing info, ASN assignments, etc.)
  "subscription_id": number | null,      // Subscription ID (enriched)
  "user_id": number | null,              // User ID (enriched)
  "parent_cidr": "string | null"         // Parent IP space CIDR (enriched)
}
```

### Notes

**IP Space Prefix Sizes:**
- Smaller prefix numbers = larger networks (e.g., /22 = 1024 IPs)
- Larger prefix numbers = smaller networks (e.g., /24 = 256 IPs)
- `min_prefix_size` should be the largest number (smallest allocation)
- `max_prefix_size` should be the smallest number (largest allocation)
- Example: min=24, max=22 allows selling /24, /23, and /22 subnets

**Pricing Structure:**
- Multiple pricing tiers can exist for the same IP space
- Each tier targets a specific prefix size (e.g., /24, /28, /32)
- One pricing entry per prefix size per space (enforced uniqueness)
- Prices are in smallest currency unit (cents for USD, millisats for BTC)

**IP Space Lifecycle:**
- `is_available=true, is_reserved=false` → Available for customer purchase
- `is_available=false` → Hidden from customer browsing
- `is_reserved=true` → Admin reserved, not for sale
- Cannot delete IP space with active subscriptions

**Metadata Examples:**
```json
{
  "routing_requirements": "BGP announcement required",
  "upstream_provider": "Cogent",
  "asn": "AS64512",
  "notes": "IPv6 PI allocation from ARIN"
}
```
