import base64, json, os, socket, struct, sys
from urllib.parse import urlparse


def connect(url):
    u = urlparse(url)
    s = socket.create_connection((u.hostname, u.port), timeout=10)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall(
        (
            f"GET {u.path or '/'} HTTP/1.1\r\nHost: {u.hostname}:{u.port}\r\n"
            f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
    )
    head = b""
    while b"\r\n\r\n" not in head:
        head += s.recv(1)
    if b" 101 " not in head.split(b"\r\n")[0]:
        sys.exit(f"handshake failed: {head!r}")
    return s


def send(s, text):
    data = text.encode()
    mask = os.urandom(4)
    n = len(data)
    head = bytes([0x81])
    if n < 126:
        head += bytes([0x80 | n])
    elif n < 65536:
        head += bytes([0x80 | 126]) + struct.pack(">H", n)
    else:
        head += bytes([0x80 | 127]) + struct.pack(">Q", n)
    s.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))


def read_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            sys.exit("connection closed")
        buf += chunk
    return buf


def recv(s):
    while True:
        b0, b1 = read_exact(s, 2)
        n = b1 & 0x7F
        if n == 126:
            n = struct.unpack(">H", read_exact(s, 2))[0]
        elif n == 127:
            n = struct.unpack(">Q", read_exact(s, 8))[0]
        payload = read_exact(s, n)
        if b0 & 0x0F == 1:
            return json.loads(payload)


def main():
    url, message = sys.argv[1], sys.argv[2]
    s = connect(url)
    send(s, message)
    print(json.dumps(recv(s)))


main()
