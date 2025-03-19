## LNVPS

A bitcoin powered VPS system.

## Requirements

- MySQL database
- Payments:
  - Bitcoin:
      - LND
      - [Bitvora](https://bitvora.com?r=lnvps)
  - Fiat:
    - [RevolutPay](https://www.revolut.com/business/revolut-pay/)
- VM Backend:
  - Proxmox

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
      vlan: 100
      kvm: false

# Networking policy
network-policy:
  # Configure network equipment on provisioning IP resources
  access: "auto"
  # Use SLAAC to auto-configure VM ipv6 addresses
  ip6-slaac: true
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

When ARP is disabled (reply-only) on your router you may need to create static ARP entries when allocating
IPs, we support managing ARP entries on routers directly as part of the provisioning process.

```yaml
# (Optional) 
# When allocating IPs for VM's it may be necessary to create static ARP entries on 
# your router, at least one router can be configured
#
# Currently supports: Mikrotik
router:
  mikrotik:
    # !! MAKE SURE TO USE HTTPS !!
    url: "https://my-router.net"
    username: "admin"
    password: "admin"
network-policy:
  # How packets get to the VM 
  # (default "auto", nothing to do, packets will always arrive)
  access:
    # Static ARP entries are added to the router for each provisioned IP
    static-arp:
      # Interface where the static ARP entry is added
      interface: "bridge1"
```

### DNS (PTR/A/AAAA)

To create PTR records automatically use the following config:
```yaml
dns:
  cloudflare:
    # The zone containing the reverse domain (eg. X.Y.Z.in-addr.arpa)
    reverse-zone-id: "my-reverse-zone-id"
    # The zone where forward (A/AAAA) entries are added (eg. lnvps.cloud zone)
    # We create forward entries with the format vm-<vmid>.lnvps.cloud
    forward-zone-id: "my-forward-zone-id"
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