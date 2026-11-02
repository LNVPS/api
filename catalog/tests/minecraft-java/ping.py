import json
import socket
import struct
import sys


def varint(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def read_varint(sock):
    n = 0
    for i in range(5):
        b = sock.recv(1)
        if not b:
            raise EOFError("connection closed")
        n |= (b[0] & 0x7F) << (7 * i)
        if not b[0] & 0x80:
            return n
    raise ValueError("varint too long")


def read_exact(sock, size):
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise EOFError("connection closed")
        buf += chunk
    return buf


def status(host, port):
    with socket.create_connection((host, port), timeout=5) as s:
        handshake = b"\x00" + varint(765) + varint(len(host)) + host.encode() + struct.pack(">H", port) + varint(1)
        s.sendall(varint(len(handshake)) + handshake)
        s.sendall(b"\x01\x00")
        read_varint(s)
        if read_varint(s) != 0:
            raise ValueError("unexpected packet id")
        size = read_varint(s)
        return json.loads(read_exact(s, size))


if __name__ == "__main__":
    host, port = sys.argv[1].rsplit(":", 1)
    print(json.dumps(status(host, int(port))))
