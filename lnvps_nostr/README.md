# LNVPS Nostr Services

A simple webserver hosting various nostr based services for lnvps.net

## Features

### Nostr Domain Name Service

Provides NIP-05 identifier verification via the `/.well-known/nostr.json` endpoint.

#### Domain Activation

Domains can be activated in two ways:

1. **DNS-based activation (HTTPS)**: Point your domain's DNS A record to the LNVPS nostr hostname. Once detected, the domain will be activated with HTTPS support and SSL/TLS certificates will be automatically provisioned via cert-manager.

2. **Path-based activation (HTTP-only)**: For domains where you cannot configure DNS but can proxy a specific path, you can activate the domain by proxying `/.well-known/nostr.json?name=<activation_hash>` to the LNVPS servers. The activation hash is a randomly generated UUID v4 assigned when you register the domain — retrieve it from the domain registration response.

   Example activation URL:
   ```
   http://yourdomain.com/.well-known/nostr.json?name=550e8400-e29b-41d4-a716-446655440000
   ```

   Domains activated via path-based activation run in HTTP-only mode (no SSL redirect) until DNS is configured.

#### Automatic HTTPS Upgrade

If a domain was initially activated via path-based activation (HTTP-only) and DNS is later configured to point to the LNVPS servers, the domain will automatically be upgraded to HTTPS with SSL/TLS certificates.
