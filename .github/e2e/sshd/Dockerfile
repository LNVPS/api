FROM alpine:3.21

# socat provides the unix socket the direct-streamlocal tunnel test connects to,
# standing in for the QEMU serial socket on a Proxmox node.
RUN apk add --no-cache openssh socat

# sshd takes the first occurrence of a keyword, so the shipped directives are
# rewritten in place rather than appended to. Alpine defaults
# AllowTcpForwarding to no, which also denies direct-streamlocal.
RUN ssh-keygen -A \
    && sed -i \
        -e 's|^#*PermitRootLogin .*|PermitRootLogin prohibit-password|' \
        -e 's|^#*AllowTcpForwarding .*|AllowTcpForwarding yes|' \
        /etc/ssh/sshd_config \
    && printf 'AllowStreamLocalForwarding yes\n' >> /etc/ssh/sshd_config

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
