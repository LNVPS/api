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
          # `qcow` produces a cloud-ready qcow2 with a growable root partition,
          # a serial console and a GRUB/systemd-boot loader already configured.
          format = "qcow";
          modules = [ ./configuration.nix ];
        };
    in
    {
      packages = {
        "x86_64-linux" = {
          qcow = mkImage "x86_64-linux";
          default = mkImage "x86_64-linux";
        };
        "aarch64-linux" = {
          qcow = mkImage "aarch64-linux";
          default = mkImage "aarch64-linux";
        };
      };
    };
}
