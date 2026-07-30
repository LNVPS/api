# LNVPS NixOS cloud image profile.
#
# This is the piece that makes NixOS usable with LNVPS's provisioning model:
# LNVPS/Proxmox inject SSH keys, hostname and IP configuration through the
# cloud-init drive on first boot. Stock NixOS images do NOT run cloud-init, so
# without this module those injections are silently ignored. The cloud-init
# module must be baked in at build time — it cannot be added later via user-data.
#
# NOTE on the declarative model: anything cloud-init applies (SSH keys, IPs) is
# imperative state that a subsequent `nixos-rebuild` can overwrite unless the
# user preserves it in their own configuration. Document this for users.
{
  modulesPath,
  lib,
  pkgs,
  ...
}:
{
  imports = [
    # Guest drivers (virtio, etc.) for running under QEMU/KVM on Proxmox.
    "${modulesPath}/profiles/qemu-guest.nix"
  ];

  # --- cloud-init: the whole point of this image ---------------------------
  services.cloud-init = {
    enable = true;
    # Let cloud-init render network config from the metadata Proxmox provides
    # (ipconfig0 -> NoCloud/ConfigDrive datasource). Keep NixOS DHCP off so the
    # two do not fight over the interface.
    network.enable = true;
  };
  networking.useDHCP = lib.mkDefault false;

  # --- SSH: keys are injected by cloud-init at first boot ------------------
  services.openssh = {
    enable = true;
    settings = {
      # Match `default_username: root` in the OS image record. Users log in as
      # root with the key they registered; password auth stays disabled.
      PermitRootLogin = "prohibit-password";
      PasswordAuthentication = false;
    };
  };

  # --- Proxmox integration -------------------------------------------------
  # Serial console so the Proxmox "Console" (xterm.js) works out of the box.
  boot.kernelParams = [
    "console=ttyS0,115200n8"
    "console=tty0"
  ];

  # --- Sensible defaults for a fresh VPS ----------------------------------
  # Enable flakes/nix-command so users can `nixos-rebuild` with a flake.
  nix.settings.experimental-features = [
    "nix-command"
    "flakes"
  ];
  environment.systemPackages = with pkgs; [
    vim
    git
    curl
    htop
  ];
  time.timeZone = lib.mkDefault "UTC";

  # Keep this in sync with the nixpkgs channel pinned in flake.nix.
  system.stateVersion = "24.11";
}
