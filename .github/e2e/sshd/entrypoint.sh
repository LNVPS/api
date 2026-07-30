#!/bin/sh
# Test sshd for the SshClient integration tests.
#
# The client keypair is generated into the mounted /keys volume on first start
# rather than committed, so no private key lives in the repository. The host
# reads /keys/id_ed25519 to authenticate.
set -eu

KEY=/keys/id_ed25519

if [ ! -f "$KEY" ]; then
    ssh-keygen -t ed25519 -f "$KEY" -N "" -C lnvps-e2e >/dev/null
fi

mkdir -p /root/.ssh
cp "${KEY}.pub" /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
# World-readable so the test process on the host can read it out of the mounted
# volume; it is a throwaway key generated per volume and never leaves the stack.
chmod 644 "${KEY}.pub" "$KEY"

# Echo server on a unix socket: whatever the tunnel writes comes straight back.
socat UNIX-LISTEN:/tmp/e2e-echo.sock,fork EXEC:cat &

exec /usr/sbin/sshd -D -e
