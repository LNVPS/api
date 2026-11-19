{
  config,
  lib,
  pkgs,
  ...
}:
let
  luksName = "cryptroot";
  rootPartition = "/dev/disk/by-partlabel/primary";
  rootUnit = "dev-disk-by\\x2dpartlabel-primary.device";

  tools = [
    pkgs.coreutils
    pkgs.gawk
    pkgs.gnused
    pkgs.util-linux
    pkgs.cryptsetup
    pkgs.e2fsprogs
    pkgs.gptfdisk
    config.boot.initrd.systemd.package
  ];

  prepareRoot = pkgs.writeShellScript "lnvps-prepare-root" ''
    set -eu
    export PATH=${lib.makeBinPath tools}

    root=$(readlink -f ${rootPartition})
    name=$(basename "$root")
    number=$(cat "/sys/class/block/$name/partition")
    disk=/dev/$(basename "$(readlink -f "/sys/class/block/$name/..")")

    ask() {
      systemd-ask-password --timeout=0 --echo=no "$1"
    }

    choose_passphrase() {
      echo >&2
      echo "================================================================" >&2
      echo " LNVPS encrypted disk: first boot" >&2
      echo " Choose a passphrase. It is asked for on every boot and is never" >&2
      echo " stored. If you lose it the data cannot be recovered." >&2
      echo "================================================================" >&2
      while :; do
        first=$(ask "New disk passphrase (min 8 characters):")
        if [ "''${#first}" -lt 8 ]; then
          echo "Too short, try again." >&2
          continue
        fi
        second=$(ask "Repeat passphrase:")
        if [ "$first" = "$second" ]; then
          printf '%s' "$first"
          return
        fi
        echo "Passphrases did not match, try again." >&2
      done
    }

    encrypt() {
      passphrase=$(choose_passphrase)
      echo "Encrypting the disk, please wait..."
      e2fsck -fy "$root" || [ $? -le 1 ]
      sectors=$(cat "/sys/class/block/$name/size")
      resize2fs "$root" "$(( sectors / 2 - 32768 ))K"
      printf '%s' "$passphrase" | cryptsetup reencrypt --encrypt --type luks2 \
        --cipher aes-xts-plain64 --key-size 512 --pbkdf argon2id \
        --pbkdf-memory 262144 --reduce-device-size 32M --batch-mode \
        --key-file - "$root"
      echo "Disk encrypted."
    }

    grow() {
      total=$(cat "/sys/class/block/''${disk#/dev/}/size")
      end=$(sgdisk -i "$number" "$disk" | awk '/^Last sector:/ {print $3}')
      [ "$end" -lt "$(( total - 2048 ))" ] || return 0
      sgdisk -e "$disk" >/dev/null
      start=$(sgdisk -i "$number" "$disk" | awk '/^First sector:/ {print $3}')
      guid=$(sgdisk -i "$number" "$disk" | awk '/^Partition unique GUID:/ {print $4}')
      label=$(sgdisk -i "$number" "$disk" | sed -n "s/^Partition name: '\(.*\)'/\1/p")
      sgdisk -d "$number" -n "$number:$start:0" -t "$number:8300" \
        -u "$number:$guid" -c "$number:$label" "$disk" >/dev/null
      partx -u "$disk" || true
      udevadm settle
      for _ in $(seq 100); do
        systemctl is-active --quiet '${rootUnit}' && break
        sleep 0.1
      done
    }

    cryptsetup isLuks "$root" || encrypt
    grow
    echo
    echo "LNVPS encrypted disk: unlocking."
  '';
in
{
  boot.growPartition = lib.mkForce false;

  boot.kernelParams = lib.mkAfter [ "console=ttyS0,115200n8" ];

  boot.initrd.systemd.enable = true;
  boot.initrd.systemd.emergencyAccess = true;
  boot.initrd.systemd.storePaths = [ prepareRoot ] ++ tools;

  boot.initrd.luks.devices.${luksName} = {
    device = rootPartition;
    crypttabExtraOpts = [ "tries=0" ];
  };

  fileSystems."/".device = lib.mkForce "/dev/mapper/${luksName}";

  boot.initrd.systemd.services.lnvps-prepare-root = {
    description = "Encrypt and grow the LNVPS root partition";
    requiredBy = [ "systemd-cryptsetup@${luksName}.service" ];
    before = [ "systemd-cryptsetup@${luksName}.service" ];
    requires = [ rootUnit ];
    after = [ rootUnit ];
    unitConfig.DefaultDependencies = false;
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      TimeoutSec = "infinity";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
      ExecStart = prepareRoot;
    };
  };
}
