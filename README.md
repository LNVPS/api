## LNVPS

A bitcoin powered VPS system.

## Features

- MySQL database
- Payments:
  - Bitcoin:
      - LND
      - [Bitvora](https://bitvora.com?r=lnvps)
  - Fiat:
    - [RevolutPay](https://www.revolut.com/business/revolut-pay/)
- VM Backend:
  - Proxmox
- Network Resources:
  - Mikrotik JSON-API
  - OVH API (dedicated server virtual mac)
- DNS Resources:
  - Cloudflare API 

## Required Config

```yaml
# MySql database connection string
db: "mysql://root:root@localhost:3376/lnvps"

# LN node connection details (Only 1 allowed)
lightning:
  lnd:
    url: "https://127.0.0.1:10003"
    cert: "$HOME/.lnd/tls.cert"
    macaroon: "$HOME/.lnd/data/chain/bitcoin/mainnet/admin.macaroon"
  #bitvora:
  #  token: "my-api-token"
  #  webhook-secret: "my-webhook-secret"
    
# Number of days after a VM expires to delete
delete-after: 3
  
# Read-only mode prevents spawning VM's
read-only: false

# Provisioner is the main process which handles creating/deleting VM's
# Currently supports: Proxmox
provisioner:
  proxmox:
    # Proxmox (QEMU) settings used for spawning VM's
    qemu:
      bios: "ovmf"
      machine: "q35"
      os-type: "l26"
      bridge: "vmbr0"
      cpu: "kvm64"
      kvm: false
```

### Email notifications

Email notifications can be enabled, this is primarily intended for admin notifications.

```yaml
# (Optional) 
# Email notifications settings
smtp:
  # Admin user id, used to send notifications of failed jobs etc. (optional)
  admin: 1
  # SMTP server url
  server: "smtp.gmail.com"
  # From header used in the email (optional)
  from: "LNVPS <no-reply@example.com>"
  username: "no-reply@example.com"
  password: "mypassword123"
```

### Nostr notifications (NIP-17)

```yaml
# (Optional) 
# Nostr connection settings for notifications
nostr:
  # Nostr relays to publish notifications to
  relays:
    - "wss://relay.snort.social"
    - "wss://relay.damus.io"
    - "wss://nos.lol"
  # Private key used to sign notifications
  nsec: "nsec1234xxx"
```

### Network Setup (Advanced)

**TODO:** AccessPolicy is now managed in the database

### DNS (PTR/A/AAAA)

To create PTR records automatically use the following config:
```yaml
dns:
  # The zone where forward (A/AAAA) entries are added (eg. lnvps.cloud zone)
  # We create forward entries with the format vm-<vmid>.lnvps.cloud
  forward-zone-id: "my-forward-zone-id"
  api:
    cloudflare:
      # API token to add/remove DNS records to this zone
      token: "my-api-token"
```

### Taxes
To charge taxes add the following config, the values are percentage whole numbers:
```yaml
tax-rate:
  IE: 23
  US: 15
```

Taxes are charged based on the users specified country