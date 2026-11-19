# Moving VMs between host kinds and regions

How to move a VM from a libvirt or marketplace node host to Proxmox, or between
Proxmox hosts in different regions, with `POST /api/admin/v1/vms/{id}/migrate`.
The endpoint is documented in `ADMIN_API_ENDPOINTS.md` (Migrate VM).

Nothing here has been run against production. Every request below that is not
a `dry_run` changes a customer VM and needs the owner's approval first.

## How it works

Same-region Proxmox to Proxmox keeps using `qm migrate` (method `hypervisor`).
Everything else that is supported is a `copy_and_adopt`:

1. A row in `vm_migration` locks the VM: a second request is refused and the
   placement poller (`ReconcileVmHosts`, `CheckVms`) leaves the VM alone.
2. The VM is stopped on the source.
3. With `ip_policy=reassign`, new addresses are allocated in the target region.
4. A new VM is created on the target from the database (same vmid, MAC, CPU
   count, memory, cloud-init, OVMF with a fresh EFI disk, virtio-scsi, serial
   socket, the target host's CPU model and machine type from the Proxmox
   config).
5. The source disk is streamed: libvirt `virStorageVolDownload` from the source
   (marketplace nodes over their tunnel), then over SSH into
   `/var/lib/vz/template/iso/lnvps-migrate-vm<id>.<raw|qcow2>` on the target
   node, hashed with `sha256sum` as it lands. The API hashes what it sent; the
   two SHA-256 sums and byte counts must match. The file is imported with
   `qm set <vmid> --scsi0 <storage>:0,import-from=...`, resized to the plan
   size and deleted.
6. If the source VM was started during the copy, the copy is thrown away.
7. `vm.host_id`/`vm.disk_id` switch to the target. From here on a failure does
   not roll back; it flags the migration (`needs_attention`).
8. The source copy is stopped with autostart (libvirt) or `onboot` (Proxmox)
   off. Static ARP and DNS are refreshed, or with `reassign` the old addresses
   are released (DNS records removed) and the new ones get ARP and DNS.
   The firewall is re-applied on the target, the VM is started there and the
   marketplace tunnel routes are recomputed (`SyncTunnelPool`).
9. With `keep_source=false` and nothing flagged, the source copy is deleted.
   Otherwise it stays, stopped, for deletion by hand.

Every step is a `migration_progress` entry in the VM history.

### Supported guests

Linux cloud images built by LNVPS (the catalog images). They boot under OVMF on
both sides and find their disk and NIC by virtio, so the guest needs no change.
FreeBSD, OpenBSD and NetBSD are refused. A qcow2 disk with a backing file is
refused; flatten it first.

### Rollback on failure

Before the switch-over, a failure deletes the target VM and its disk, frees any
newly allocated addresses and starts the VM again on the source if it was
running. The migration row ends `rolled_back`. A retry is safe: a target VM left
behind by an earlier failed attempt of the same migration is deleted first, and
a VM with the same id that no migration explains is never overwritten.

An attempt that never finished (the worker died) blocks new attempts until its
copy timeout plus one hour has passed. The next request then marks it failed
and flagged, and carries over whether the VM had been running, so a rollback of
the new attempt still restarts it.

## Marketplace accounting

A marketplace operator's share follows the host a VM runs on. Once the VM is on
an LNVPS Proxmox host, the operator stops earning on it from that point on;
nothing already accrued changes. The plan lists this as a warning and the
admin notification after the move says so again.

## Candidate VMs on marketplace host 7

Read with `GET /api/admin/v1/hosts` and `GET /api/admin/v1/vms?host_id=7` on
2026-11-06. Host 7 (`i9-14900k-74`) is a marketplace node in region 1 (Dublin),
disabled for new placements, 12 VMs, 388 GiB of disk in total.

| VM | User | Image | vCPU | RAM GiB | Disk GiB | State | Addresses |
|---|---|---|---|---|---|---|---|
| 2179 | 14040349 | Alpine server 3.24 | 1 | 2 | 10 | running | 185.18.221.255, 2a13:2c0::20b4:ab3d:6c23:22f1 |
| 2177 | 19472563 | Ubuntu server 26.04 | 2 | 2 | 20 | running | 185.18.221.32, 2a13:2c0::f0a9:790f:c6fe:1958 |
| 2175 | 19472259 | Ubuntu Server 22.04 | 3 | 3 | 60 | running | 185.18.221.35, 2a13:2c0::44ad:8244:5e9e:c506 |
| 2173 | 19470921 | Debian Server 13 | 1 | 1 | 10 | running | 185.18.221.43, 2a13:2c0::4888:bccc:e696:47ad |
| 2168 | 19453833 | Debian Server 13 | 1 | 1 | 18 | running | 185.18.221.244, 2a13:2c0::28ba:9493:9c66:ff0d |
| 2166 | 18085873 | Arch Linux Cloud Latest | 1 | 1 | 10 | running | 185.18.221.71, 2a13:2c0::a9fb:fce3:6d18:1961 |
| 2165 | 18085873 | Arch Linux Cloud Latest | 1 | 1 | 10 | running | 185.18.221.64, 2a13:2c0::df07:9886:d0e2:e9ac |
| 2160 | 19385648 | Ubuntu Server 24.04 | 4 | 8 | 80 | running | 2a13:2c0::8509:3696:1f09:3961, 185.18.221.25 |
| 2159 | 19290189 | Ubuntu Server 24.04 | 12 | 12 | 50 | running | 185.18.221.48, 2a13:2c0::9e72:82e9:5041:179e |
| 2157 | 19243120 | Ubuntu server 26.04 | 2 | 4 | 60 | running | 185.18.221.99, 2a13:2c0::7e63:737:ea2f:6d40 |
| 2118 | 18667224 | Debian Server 13 | 2 | 2 | 20 | stopped | 185.18.221.90, 2a13:2c0::1a43:44f4:4b42:68c |
| 2040 | 1 | Debian Server 13 | 1 | 1 | 40 | stopped | 185.18.221.201, 2a13:2c0::c308:ffe4:9d27:9285 |

All of them are Linux and all their ranges (1, 4, 8, 18 for IPv4, 3 for IPv6)
are region 1, the same region as `pve` (host 1) and `pve2` (host 3). They move
with `ip_policy=keep`: no customer address changes. The disk sizes above are
the plan sizes; the bytes copied are the allocated size of each volume on the
node, which is smaller for thin qcow2 disks.

The IPv6 addresses were derived by SLAAC from each VM's MAC. The MAC is kept,
so they stay the same.

## Pre-migration checklist

- [ ] The API and worker running the release with `20261106215109_vm_migration.sql`
      applied (check `GET /api/admin/v1/vms/{id}/history` shows
      `migration_progress` for a dry run test VM).
- [ ] The worker can SSH to the target Proxmox node (the `ssh` block of the
      Proxmox provisioner config) and `qm` works there.
- [ ] `/var/lib/vz/template/iso` on the target node has free space for the
      largest disk (80 GiB for VM 2160). The job checks this and refuses
      otherwise.
- [ ] The target storage (`local-zfs` on `pve`/`pve2`) has room for the total.
- [ ] The marketplace node is online: `GET /api/admin/v1/hosts/7` reports it and
      its tunnel is up. The disk is read over the node's libvirt connection.
- [ ] `/var/lib/vz/snippets/lnvps-vendor.yaml` exists on the target node (the
      API writes it, but a VM will not start if it is missing).
- [ ] The VM owner has been told about the downtime: the VM is stopped for the
      whole copy. At the ~50 MB/s the plan assumes, 10 GiB is about 3.5
      minutes and 80 GiB about 27 minutes. The tunnel from a home-LAN node may
      be slower; the dry run's `estimated_seconds` is a floor.
- [ ] A dry run for the VM returns no `refusals`.

## Commands

Set up once:

```bash
SEC=$(cat ~/.nostr/lnvps-admin.nsec)
API=https://admin-api.lnvps.net/api/admin/v1
```

Dry run (changes nothing, safe at any time):

```bash
NOSTR_SECRET_KEY=$SEC nak curl -X POST -H "Content-Type: application/json" \
  -d '{"target_host_id": 3, "dry_run": true}' \
  "$API/vms/2173/migrate"
```

Check `data.plan.refusals` is empty, `method` is `copy_and_adopt`,
`target_storage` is `local-zfs`, and `ip_changes` is empty.

Migrate one VM, keeping the source copy (start with a small stopped one, 2118 or
2040, then a small running one such as 2173):

```bash
NOSTR_SECRET_KEY=$SEC nak curl -X POST -H "Content-Type: application/json" \
  -d '{"target_host_id": 3, "ip_policy": "keep", "keep_source": true,
       "reason": "Move off marketplace node 7 to pve2"}' \
  "$API/vms/2040/migrate"
```

Follow it:

```bash
NOSTR_SECRET_KEY=$SEC nak curl "$API/vms/2040/history?limit=20"
NOSTR_SECRET_KEY=$SEC nak curl "$API/vms/2040"
```

The last `migration_progress` entry is `completed` and `host_id` is 3. Check the
guest answers (`ping`, `ssh`) on its old addresses, allowing 60 to 90 seconds
after the start.

To spread the load, send the larger VMs (2160, 2159, 2157, 2175) to `pve`
(host 1) and the rest to `pve2` (host 3), one at a time. The worker runs jobs
in order, so queueing several is safe but each holds the worker for its copy.

## After each VM

- The VM answers on every address and SSH host keys are unchanged.
- `GET /api/admin/v1/vms/{id}` shows the new host and disk.
- The stopped copy on node 7 has autostart off. Delete it once the VM has run
  cleanly for a day:

  ```bash
  ssh root@10.100.2.73 virsh undefine VM2040 --nvram --remove-all-storage
  ```

  (`--remove-all-storage` also deletes the `vm-<id>-seed.iso` volume.)

## Rollback

Before the switch-over the job rolls back by itself. After it, to put a VM
back on the node by hand:

1. Stop it on Proxmox: `qm stop <id+100>` on the target node.
2. Start the retained copy on the node: `virsh start VM<id>` and
   `virsh autostart VM<id>`.
3. Point the database back: `POST /api/admin/v1/vms/{id}/migrate` cannot go
   back to a marketplace node, so let the placement poller do it. First mark
   the retained copy as live again, or the poller keeps ignoring it:
   `UPDATE vm_migration SET source_retained = 0 WHERE vm_id = <id>`. Then
   delete the Proxmox copy (`qm destroy <id+100> --purge`). `ReconcileVmHosts`
   (every 10 minutes) sees the VM only on host 7 and updates `host_id`.
4. Recompute the node's tunnel routes so they include the VM's addresses
   again: `POST /api/admin/v1/tunnel_pools/{pool_id}/sync` for the node's pool.

A flagged migration (`needs_attention`) says what failed in its `error` and in
the admin notification. Fix that item (start the VM, re-apply DNS with
`POST /api/admin/v1/ip_ranges/{id}/patch_dns`, delete the source copy) and clear
the flag with `UPDATE vm_migration SET needs_attention = 0 WHERE id = <id>`.
