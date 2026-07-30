{
  description = "LNVPS NixOS cloud-init disk images (qcow2) for Proxmox provisioning";

  inputs = {
    # Pin to a release channel so image builds are reproducible. Bump this in
    # lockstep with the `version` you register in the OS image record.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";

    nixos-generators = {
      url = "github:nix-community/nixos-generators";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      nixos-generators,
      ...
    }:
    let
      # The qcow disk image is built for the guest architecture. LNVPS records
      # carry a `cpu_arch` field (x86_64 / arm64), so we expose one image per arch.
      mkImage =
        system:
        nixos-generators.nixosGenerate {
          inherit system;
          # `qcow-efi` (NOT `qcow`) is required: LNVPS boots every VM with OVMF
          # (UEFI) firmware and hands it a fresh, empty efidisk0. The plain
          # `qcow` format installs GRUB to the MBR for legacy BIOS boot and has
          # no EFI system partition, so it will not boot under OVMF. `qcow-efi`
          # creates an ESP and sets efiInstallAsRemovable, installing GRUB to the
          # UEFI fallback path (EFI/BOOT/BOOTX64.EFI) that OVMF finds without a
          # pre-existing NVRAM boot entry.
          format = "qcow-efi";
          modules = [ ./configuration.nix ];
        };
    in
    {
      packages = {
        "x86_64-linux" = {
          qcow-efi = mkImage "x86_64-linux";
          default = mkImage "x86_64-linux";
        };
        "aarch64-linux" = {
          qcow-efi = mkImage "aarch64-linux";
          default = mkImage "aarch64-linux";
        };
      };
    };
}
