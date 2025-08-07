# LNVPS Admin API Endpoints

This document lists all available endpoints in the LNVPS Admin API.

## API Design Changes

**Enum Values**: This API uses strongly-typed enums instead of arbitrary strings for better type safety and validation. When you see a field with an enum comment like `// Enum: "value1", "value2"`, only those exact values are accepted. Invalid values will be rejected during deserialization.

This provides better API documentation, IDE auto-completion, and prevents runtime errors from invalid string values.

## Currency Support

The system supports company-based base currencies. Each company can have its own base currency which is used for pricing calculations and reports. Supported currencies include:

- **EUR**: Euro
- **USD**: US Dollar  
- **GBP**: British Pound
- **CAD**: Canadian Dollar
- **CHF**: Swiss Franc
- **AUD**: Australian Dollar
- **JPY**: Japanese Yen
- **BTC**: Bitcoin

All financial reports and pricing calculations will use the company's configured base currency. Exchange rates are automatically calculated to ensure mathematical consistency across different payment currencies.

## Enum Types Reference

All enum types used in this API are listed below with their possible values:

### VM and Hardware Enums

#### DiskType
**Values**: `"hdd"`, `"ssd"`
- Used in: VM templates, custom pricing, host disks
- Example: `"disk_type": "ssd"`

#### DiskInterface  
**Values**: `"sata"`, `"scsi"`, `"pcie"`
- Used in: VM templates, custom pricing, host disks
- Example: `"disk_interface": "pcie"`

#### VmRunningStates
**Values**: `"running"`, `"stopped"`, `"starting"`, `"deleting"`
- Used in: VM running state information (within running_state object)
- Example: `"state": "running"`

#### AdminVmHistoryActionType
**Values**: `"created"`, `"started"`, `"stopped"`, `"restarted"`, `"deleted"`, `"expired"`, `"renewed"`, `"reinstalled"`, `"state_changed"`, `"payment_received"`, `"configuration_changed"`
- Used in: VM history entries
- Example: `"action_type": "started"`

#### AdminPaymentMethod
**Values**: `"lightning"`, `"revolut"`, `"paypal"`
- Used in: Payment information
- Example: `"payment_method": "lightning"`

#### VmHostKind
**Values**: `"proxmox"`, `"libvirt"`
- Used in: Host configuration
- Example: `"kind": "proxmox"`

#### CostPlanIntervalType
**Values**: `"day"`, `"month"`, `"year"`
- Used in: Cost plan configuration, VM template cost plan settings
- Example: `"interval_type": "month"`
- Details:
  - `"day"`: Billing interval is daily
  - `"month"`: Billing interval is monthly (default)
  - `"year"`: Billing interval is yearly

### Operating System Enums

#### ApiOsDistribution
**Values**: `"ubuntu"`, `"debian"`, `"centos"`, `"fedora"`, `"freebsd"`, `"opensuse"`, `"archlinux"`, `"redhatenterprise"`
- Used in: VM OS images
- Example: `"distribution": "ubuntu"`

### Network Configuration Enums

#### IpRangeAllocationMode
**Values**: `"random"`, `"sequential"`, `"slaac_eui64"`
- Used in: IP range configuration
- Example: `"allocation_mode": "sequential"`
- Details:
  - `"random"`: Assign IPs randomly from available pool
  - `"sequential"`: Assign IPs in sequential order
  - `"slaac_eui64"`: Use SLAAC with EUI-64 for IPv6 auto-configuration

#### NetworkAccessPolicyKind
**Values**: `"static_arp"`
- Used in: Access policy configuration
- Example: `"kind": "static_arp"`

#### RouterKind
**Values**: `"mikrotik"`, `"ovh_additional_ip"`
- Used in: Router configuration
- Example: `"kind": "mikrotik"`

### User Management Enums

#### AdminUserRole
**Values**: `"super_admin"`, `"admin"`, `"read_only"`
- Used in: User role assignment
- Example: `"admin_role": "admin"`
- Details:
  - `"super_admin"`: Full system access including user role management
  - `"admin"`: Administrative access with some restrictions
  - `"read_only"`: View-only access to admin functions

#### AdminUserStatus
**Values**: `"active"`, `"suspended"`, `"deleted"`
- Used in: User account status
- Example: `"status": "active"`

### Enum Validation

All enum fields in request bodies are validated during deserialization. Sending an invalid enum value will result in a `400 Bad Request` error with a descriptive message indicating the accepted values.

**Example error response for invalid enum**:
```json
{
  "error": "Invalid disk_type 'nvme'. Valid values are: hdd, ssd"
}
```

## Authentication

All endpoints require NIP-98 (Nostr) authentication. The authentication header should be formatted as:
```
Authorization: Nostr <base64-encoded-event>
```

Each endpoint also requires specific admin permissions, which are validated through the RBAC system.

## Common Response Format

All endpoints return data in a standardized format:

**Single item responses:**
```json
{
  "data": T
}
```

**Paginated list responses:**
```json
{
  "data": T[],
  "total": number,
  "limit": number,
  "offset": number
}
```

## Endpoints

### User Management

#### List Users
```
GET /api/admin/v1/users
```
Query Parameters:
- `limit`: number (optional) - Items per page (max 100, default 50)
- `offset`: number (optional) - Pagination offset
- `search`: string (optional) - Search by user pubkey (hex format)

Required Permission: `users::view`

Response includes user details with VM count, admin status, and billing information.

#### Update User
```
PATCH /api/admin/v1/users/{id}
```
Required Permission: `users::update`

Body parameters (all optional):
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
  "admin_role": "super_admin" // AdminUserRole enum: "super_admin", "admin", "read_only", or null
}
```

### VM Management

#### List VMs
```
GET /api/admin/v1/vms
```
Query Parameters:
- `limit`: number (optional) - Items per page (max 100, default 50)
- `offset`: number (optional) - Pagination offset
- `user_id`: number (optional) - Filter by user ID
- `host_id`: number (optional) - Filter by host ID
- `pubkey`: string (optional) - Filter by user's public key (hex format)
- `region_id`: number (optional) - Filter by region ID
- `include_deleted`: boolean (optional) - Include deleted VMs in results (default: false)

Required Permission: `virtual_machines::view`

Returns detailed VM information including user details, host information, region, VM resources (CPU, memory, disk), template information (standard/custom), and deletion status.

The endpoint supports multiple filter combinations:
- Filter by specific user using either `user_id` or `pubkey` (if both provided, `pubkey` takes precedence)
- Filter by host using `host_id`  
- Filter by region using `region_id`
- Control deleted VM visibility using `include_deleted` (false by default excludes deleted VMs)
- Multiple filters can be combined (e.g., user + region, host + region, include_deleted + any filter)

Template information includes:
- `template_name`: Name of the template (shows "Custom - {pricing_name}" for custom templates)
- `custom_template_id`: ID of custom template if applicable
- `is_standard_template`: Boolean indicating if using a standard template

#### Get VM Details
```
GET /api/admin/v1/vms/{id}
```
Required Permission: `virtual_machines::view`

Returns detailed information about a specific VM including user details, host information, region, VM resources (CPU, memory, disk), and deletion status.

#### Start VM
```
POST /api/admin/v1/vms/{id}/start
```
Required Permission: `virtual_machines::update`

#### Stop VM
```
POST /api/admin/v1/vms/{id}/stop
```
Required Permission: `virtual_machines::update`

#### Delete VM
```
DELETE /api/admin/v1/vms/{id}
```
Required Permission: `virtual_machines::delete`

#### List VM History
```
GET /api/admin/v1/vms/{vm_id}/history
```
Query Parameters:
- `limit`: number (optional) - Items per page (max 100, default 50)  
- `offset`: number (optional) - Pagination offset

Required Permission: `virtual_machines::view`

Returns a paginated list of history entries for the specified VM, including actions like creation, start/stop operations, payments, configuration changes, etc.

#### Get VM History Entry
```
GET /api/admin/v1/vms/{vm_id}/history/{history_id}
```
Required Permission: `virtual_machines::view`

Returns detailed information about a specific VM history entry.

#### List VM Payments
```
GET /api/admin/v1/vms/{vm_id}/payments
```
Query Parameters:
- `limit`: number (optional) - Items per page (max 100, default 50)
- `offset`: number (optional) - Pagination offset

Required Permission: `payments::view`

Returns paginated payment records for the specified VM, including payment status, amounts, and payment methods. Payments are ordered by creation date (newest first).

#### Get VM Payment
```
GET /api/admin/v1/vms/{vm_id}/payments/{payment_id}
```
Required Permission: `payments::view`

Returns detailed information about a specific VM payment. The `payment_id` should be hex-encoded.

### Role Management

#### List Roles
```
GET /api/admin/v1/roles
```
Query Parameters:
- `limit`: number (optional) - Items per page (max 100, default 50)
- `offset`: number (optional) - Pagination offset

Required Permission: `roles::view`

Returns roles with their permissions and user count.

#### Get Role Details
```
GET /api/admin/v1/roles/{id}
```
Required Permission: `roles::view`

Returns detailed role information including permissions and user count.

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
  "permissions": ["string array of permissions like 'users::view'"]
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
  "permissions": ["string array of permissions"]
}
```

Note: System roles cannot be modified.

#### Delete Role
```
DELETE /api/admin/v1/roles/{id}
```
Required Permission: `roles::delete`

Note: System roles cannot be deleted. Roles with assigned users cannot be deleted.

### User Role Assignments

#### Get User Roles
```
GET /api/admin/v1/users/{user_id}/roles
```
Required Permission: `users::view`

Returns detailed role assignment information including who assigned the role, when it was assigned, expiration date, and active status.

#### Assign Role to User
```
POST /api/admin/v1/users/{user_id}/roles
```
Required Permission: `users::update`

Body:
```json
{
  "role_id": "number"
}
```

#### Revoke Role from User
```
DELETE /api/admin/v1/users/{user_id}/roles/{role_id}
```
Required Permission: `users::update`

Note: Users cannot revoke their own roles to prevent locking themselves out.

#### Get Current User's Admin Roles
```
GET /api/admin/v1/me/roles
```
Required Permission: None (authenticated admin user can view their own roles)

Returns array of `UserRoleInfo` objects for the current authenticated user.

### Host Management

#### List Hosts
```
GET /api/admin/v1/hosts
```
Query Parameters:
- `limit`: number (optional) - Items per page (max 100, default 50)
- `offset`: number (optional) - Pagination offset

Required Permission: `hosts::view`

Returns paginated list of VM hosts with configuration details and real-time calculated load metrics based on actual VM resource consumption.

#### Get Host Details
```
GET /api/admin/v1/hosts/{id}
```
Required Permission: `hosts::view`

Returns detailed information about a specific VM host including real-time calculated load metrics based on actual VM resource consumption.

#### Update Host Configuration
```
PATCH /api/admin/v1/hosts/{id}
```
Required Permission: `hosts::update`

Body parameters (all optional):
```json
{
  "name": "string",
  "ip": "string",
  "api_token": "string",
  "region_id": number,
  "kind": "libvirt",           // AdminVmHostKind enum: "proxmox" or "libvirt"
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
  "name": "string",               // Required - Host name/hostname
  "ip": "string",                // Required - Host IP address
  "api_token": "string",         // Required - API token for host communication
  "region_id": number,           // Required - Region ID
  "kind": "proxmox",            // Required - AdminVmHostKind enum: "proxmox" or "libvirt"
  "vlan_id": number | null,     // Optional - VLAN ID
  "cpu": number,                // Required - Number of CPU cores
  "memory": number,             // Required - Memory in bytes
  "enabled": boolean,           // Optional - Default: true
  "load_cpu": number,           // Optional - CPU load factor (default: 1.0)
  "load_memory": number,        // Optional - Memory load factor (default: 1.0)
  "load_disk": number          // Optional - Disk load factor (default: 1.0)
}
```


#### List Host Disks
```
GET /api/admin/v1/hosts/{id}/disks
```
Required Permission: `hosts::view`

Returns list of all disks available on the specified host with disk configuration details.

#### Get Host Disk Details
```
GET /api/admin/v1/hosts/{host_id}/disks/{disk_id}
```
Required Permission: `hosts::view`

Returns detailed information about a specific disk on a host.

#### Update Host Disk Configuration
```
PATCH /api/admin/v1/hosts/{host_id}/disks/{disk_id}
```
Required Permission: `hosts::update`

Body parameters (all optional):
```json
{
  "enabled": boolean
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
  "disk_pricing": [                     // Array of disk pricing configurations
    {
      "kind": "ssd",                    // DiskType enum: "hdd" or "ssd"
      "interface": "pcie",              // DiskInterface enum: "sata", "scsi", or "pcie"
      "cost": number                    // Cost per GB per month
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
  "disk_pricing": [
    {
      "kind": "ssd",                        // DiskType enum: "hdd", "ssd"
      "interface": "pcie",                  // DiskInterface enum: "sata", "scsi", "pcie"
      "cost": number
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

### Reports

#### Time Series Report
```
GET /api/admin/v1/reports/time-series?start_date={date}&end_date={date}&interval={interval}&company_id={company_id}&currency={currency}
```
Query Parameters:
- `start_date`: string (required) - Start date in YYYY-MM-DD format (e.g., "2025-01-01")
- `end_date`: string (required) - End date in YYYY-MM-DD format (e.g., "2025-12-31")
- `interval`: string (required) - Time interval for data aggregation: "daily", "weekly", "monthly", "quarterly", "yearly"
- `company_id`: number (required) - Company ID to generate report for
- `currency`: string (optional) - Filter by specific currency (EUR, USD, GBP, CAD, CHF, AUD, JPY, BTC)

Required Permission: `analytics::view`

Returns time-series payment data for a specific company with optional currency filtering. This endpoint provides both period-based aggregated summaries and individual payment records with time period grouping, enabling comprehensive analysis and reporting.

**Key Features:**
- **Company-Specific Reports**: Always scoped to a specific company for focused analysis
- **Period Aggregation**: Server-side aggregation by time period and currency with totals
- **Raw Payment Data**: Individual payment records for detailed drill-down analysis
- **Optimized Database Query**: Single SQL join with efficient company filtering
- **Flexible Time Intervals**: Automatic period calculation for daily, weekly, monthly, quarterly, and yearly intervals
- **Optional Currency Filtering**: Filter by specific currency within the company's payments
- **Company Context**: Each payment includes company information and base currency
- **Dual Analysis**: Both aggregated summaries and raw data for flexible client-side use

**Response:**
```json
{
  "data": {
    "start_date": "2025-01-01",
    "end_date": "2025-12-31", 
    "interval": "monthly",
    "company_id": 1,
    "company_name": "Acme Corp",
    "company_base_currency": "USD",
    "period_summaries": [
      {
        "period": "2025-01",
        "currency": "USD",
        "payment_count": 25,
        "net_total": 3125000,
        "tax_total": 656250,
        "base_currency_net": 3125000,
        "base_currency_tax": 656250
      },
      {
        "period": "2025-01", 
        "currency": "BTC",
        "payment_count": 8,
        "net_total": 1000,
        "tax_total": 208,
        "base_currency_net": 1000,
        "base_currency_tax": 208
      }
    ],
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
        "company_base_currency": "USD",
        "period": "2025-01"
      },
      {
        "id": "b2c3d4e5f6a1...",
        "vm_id": 456,
        "created": "2025-01-20T14:22:31Z",
        "expires": "2025-02-20T14:22:31Z",
        "amount": 125,
        "currency": "BTC",
        "payment_method": "lightning",
        "external_id": "inv_67890",
        "is_paid": true,
        "rate": 100000.0,
        "time_value": 2592000,
        "tax": 26,
        "company_id": 1,
        "company_name": "Acme Corp",
        "company_base_currency": "USD",
        "period": "2025-01"
      }
    ]
  }
}
```

**Time Interval Formats:**
- **Daily**: `"2025-01-15"` - Individual days
- **Weekly**: `"2025-01-13"` - Monday of each week (ISO week starting Monday)
- **Monthly**: `"2025-01"` - Year and month
- **Quarterly**: `"2025-Q1"` - Year and quarter
- **Yearly**: `"2025"` - Year only

**Payment Record Structure:**
Each payment record includes complete payment information with company context:

- `id`: Hex-encoded payment identifier
- `vm_id`: Associated virtual machine ID
- `created` / `expires`: ISO 8601 timestamps
- `amount`: Payment amount in smallest currency unit (cents, satoshis, etc.)
- `currency`: Payment currency code
- `payment_method`: Payment method used ("lightning", "revolut", "paypal")
- `external_id`: External payment system identifier  
- `is_paid`: Payment completion status
- `rate`: Exchange rate to company's base currency
- `time_value`: VM expiry extension in seconds
- `tax`: Tax amount in smallest currency unit
- `company_id` / `company_name`: Company identification and name
- `company_base_currency`: Company's configured base currency
- `period`: Calculated time period based on selected interval

**Benefits of Company-Scoped Approach:**
- **Simplified Database Query**: Always filters by company for optimal performance
- **Focused Analysis**: Company-specific data reduces complexity and improves clarity
- **Efficient Indexing**: Database can optimize queries with consistent company filtering
- **Security**: Natural data isolation by company boundary
- **Scalability**: Better query performance as data grows

**Period Summaries Structure:**
Each period summary aggregates payments by time period and currency:
- `period`: Time period identifier based on selected interval (e.g., "2025-01", "2025-Q1", "2025-01-15")
- `currency`: Currency code for this aggregation group 
- `payment_count`: Number of individual payments in this period/currency combination
- `net_total`: Sum of payment amounts (excluding tax) in smallest currency unit
- `tax_total`: Sum of tax amounts in smallest currency unit
- `base_currency_net`: Sum of net amounts converted to company's base currency using proper decimal conversion and exchange rates
- `base_currency_tax`: Sum of tax amounts converted to company's base currency using proper decimal conversion and exchange rates

**Currency Conversion Logic:**
The `base_currency_net` and `base_currency_tax` calculations properly handle different currency types:
- BTC amounts are converted from millisatoshis to full decimal BTC before multiplying by exchange rate
- Fiat amounts are converted from cents to full decimal amount before multiplying by exchange rate  
- Results are converted back to the base currency's smallest unit (cents for fiat, millisatoshis for BTC)
- Net and tax amounts are converted separately to maintain precision and allow for independent analysis

**Benefits of Dual Data Approach:**
- **Performance**: Single optimized database query with efficient aggregation
- **Flexibility**: Both aggregated summaries for dashboards and raw data for detailed analysis
- **Comprehensive**: Period-based totals for trending with individual records for drill-down
- **Scalable**: Server-side aggregation reduces client-side processing for large datasets
- **Custom Analysis**: UI can still perform additional aggregations using raw payment data

**Use Cases:**
- **Revenue Dashboards**: Use period_summaries for charts and KPIs showing revenue trends over time
- **Multi-currency Analysis**: Compare performance across different payment currencies using both original amounts and base currency conversions
- **Unified Reporting**: Sum base_currency_net and base_currency_tax values across currencies for total company revenue per period
- **Tax Analysis**: Separate base_currency_tax values allow for detailed tax reporting and compliance analysis
- **Net Revenue Tracking**: base_currency_net provides clean revenue figures excluding tax effects
- **Seasonal Analysis**: Identify payment patterns using period summaries grouped by time intervals
- **Detailed Investigations**: Drill down from period summaries into individual payments for investigation
- **Financial Reporting**: Generate summary reports from period_summaries with consistent base currency values
- **Payment Method Analysis**: Use raw payment data to analyze preferred payment methods by time period
- **Custom Aggregations**: Combine period_summaries with custom groupings from raw payment data

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

## Response Models

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
  "cpu": number,                      // Number of CPU cores allocated
  "memory": number,                   // Memory in bytes allocated
  "disk_size": number,                // Disk size in bytes
  "disk_type": "ssd",                 // DiskType enum: "hdd" or "ssd"
  "disk_interface": "pcie",           // DiskInterface enum: "sata", "scsi", or "pcie"
  "host_id": number,
  "user_id": number,
  "user_pubkey": "string (hex)",
  "user_email": "string | null",
  "host_name": "string | null",
  "region_name": "string | null",
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
  "payment_method": "lightning",          // AdminPaymentMethod enum: "lightning", "revolut", "paypal"
  "external_id": "string | null",         // External payment provider ID
  "is_paid": boolean,                     // Whether payment has been completed
  "rate": number                          // Exchange rate to base currency (EUR)
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
  "disk_pricing": [                     // Array of disk pricing configurations
    {
      "id": number,
      "kind": "ssd",                    // DiskType enum: "hdd" or "ssd"
      "interface": "pcie",              // DiskInterface enum: "sata", "scsi", or "pcie"
      "cost": number                    // Cost per GB per month
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