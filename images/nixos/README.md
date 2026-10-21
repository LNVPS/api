# LNVPS NixOS cloud image

NixOS ships **no official cloud-init qcow2** (unlike Ubuntu/Debian), so LNVPS
builds and hosts its own. This directory is a reproducible recipe for that
image plus the CI that publishes it.

## Why this exists

LNVPS provisions a VM by downloading a distro's cloud image and having Proxmox
inject the user's SSH key, hostname and IP config through the **cloud-init
drive** on first boot. That only works if the guest image *runs cloud-init*.

Stock NixOS images do not. And you can't fix that with a bootstrap script —
cloud-init user-data can only run on an image that already listens for it
(chicken-and-egg). The `services.cloud-init.enable = true` module therefore has
to be **baked into the image at build time**, which is exactly what
[`configuration.nix`](./configuration.nix) does.

## Files

| File | Purpose |
|---|---|
| `flake.nix` | Pins nixpkgs + `nixos-generators`; exposes a `qcow-efi` (UEFI) image per arch |
| `configuration.nix` | The NixOS profile: cloud-init, OpenSSH, serial console |
| `encrypted.nix` | Extra module for the encrypted variant: LUKS2 root, passphrase prompt on the serial console |
| `build.sh` | Builds the qcow2 images (`cloudinit`, `encrypted` or both), xz-compresses them, writes `SHA256SUMS` |
| `../../.github/workflows/nixos-image.yml` | CI that builds + publishes on `nixos-image-v*` tags |

## Build locally

Requires Nix with flakes enabled.

```bash
cd images/nixos
./build.sh 24.11 x86_64      # -> out/nixos-24.11-{cloudinit,encrypted}-x86_64.qcow2.xz + out/SHA256SUMS
./build.sh 24.11 x86_64 encrypted   # only one variant
```

The `.xz` extension matters: LNVPS recognises it as a compressed image and
decompresses it host-side (see `OS_IMAGE_COMPRESSION_EXTENSIONS` in
`lnvps_db`).

## Build & publish via CI

Push a dedicated tag (kept separate from the main `v*` release tags so it does
not trigger the firewall `.deb` build):

```bash
git tag nixos-image-v24.11
git push https://github.com/LNVPS/api.git nixos-image-v24.11
```

The workflow builds the qcow2 and attaches
`nixos-<version>-cloudinit-x86_64.qcow2.xz` + `SHA256SUMS` to the GitHub
release. You can also run it manually via **workflow_dispatch**.

Host the published `.qcow2.xz` and `SHA256SUMS` wherever your other OS images
are served (or point `url` straight at the GitHub release asset).

## Register the image

Once hosted, create the OS image record. `distribution: 11` is
`OsDistribution::NixOS` (already wired end-to-end in the codebase).

```http
POST /api/admin/v1/vm_os_images
Content-Type: application/json

{
  "distribution": 11,
  "flavour": "cloudinit",
  "version": "24.11",
  "enabled": true,
  "release_date": "2024-11-30T00:00:00Z",
  "url": "https://<host>/nixos-24.11-cloudinit-x86_64.qcow2.xz",
  "cpu_arch": "x86_64",
  "default_username": "root",
  "sha2_url": "https://<host>/SHA256SUMS"
}
```

LNVPS downloads the URL, verifies it against `sha2_url`, decompresses it, and
uses it like any other cloud image. Set `enabled: true` to make it selectable.

## Encrypted variant

`nixos-<version>-encrypted-<arch>.qcow2.xz` is the same image with a LUKS2 root
(`aes-xts-plain64`, argon2id). Register it like the plain image, with
`"flavour": "encrypted"` and `"encrypted": true`; the flag is returned by
`GET /api/v1/image` so clients can warn the user before they order.

How it works, all in the initrd (systemd stage 1):

1. **First boot.** The image ships with an unencrypted ext4 root. A service
   asks for a new passphrase twice on the serial console, then encrypts the
   partition in place with `cryptsetup reencrypt`. This takes about 20 seconds
   on a 4 GB image and the master key is generated on the VM, so no two VMs
   share a key.
2. **Every boot.** systemd asks for the passphrase on the serial console and
   retries until it is right. Nothing is stored anywhere LNVPS can read.
3. **Resize.** If the disk was enlarged, the partition, the LUKS container and
   the ext4 filesystem all grow on the next boot, with no extra prompt.

The user types the passphrase in the web terminal (`/api/v1/vm/{id}/console`).

Consequences to communicate to users:

- The VM waits at the prompt after **every** reboot, host maintenance, migration
  or reinstall, until someone enters the passphrase. Nothing else starts,
  including SSH.
- A forgotten passphrase means the data is gone. LNVPS cannot recover it.
- The prompt is printed once. A user who connects late presses Enter, or
  restarts the VM, to see it again.
- It protects against disk theft, retired drives, snapshots and backups. It
  does not protect against someone with access to the hypervisor, who can read
  the VM's memory after it is unlocked.
- cloud-init runs after unlock, so SSH keys and IPs are applied as usual.

Testing it without Proxmox: boot the qcow2 under QEMU with OVMF and a unix
socket serial port (`-serial unix:ser.sock,server=on,wait=off`), and drive the
prompts over the socket.

## Caveats to communicate to users

1. **cloud-init vs. the declarative model.** SSH keys / IPs applied by
   cloud-init are imperative state. A later `nixos-rebuild` can overwrite them
   unless the user carries them in their own Nix configuration.
2. **You maintain this image.** There is no upstream mirror to track — bump the
   `nixpkgs` channel in `flake.nix` and `system.stateVersion` in
   `configuration.nix` together each NixOS release, then re-tag.
3. **UEFI only.** LNVPS boots every VM with OVMF (UEFI) firmware, so the flake
   uses the `qcow-efi` format (ESP + `efiInstallAsRemovable`). The plain `qcow`
   format is legacy-BIOS only and will **not boot** under LNVPS — do not switch
   back to it.

## First-boot smoke test (recommended before enabling)

On a real Proxmox host, provision one VM from the image and confirm:

- SSH login as `root` with the registered key succeeds (cloud-init applied the key),
- the assigned IP matches what LNVPS configured (`ipconfig0`),
- the root filesystem grew to the provisioned disk size,
- the Proxmox console shows the serial getty.
