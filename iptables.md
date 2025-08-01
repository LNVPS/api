# Helpful iptables rules

## Proxmox

### Disable connection tracking

Since we don't use stateful firewalling and allow all connections to the hosts, there is no need to track
connections to the VM's so we disable it.

```bash
iptables -t raw -A PREROUTING -d <my-ips> -j NOTRACK
iptables -t raw -A OUTPUT -s <my-ips> -j NOTRACK
```

Allow invalid connections in `/etc/pve/local/host.fw`

```conf
nf_conntrack_allow_invalid: 1
```