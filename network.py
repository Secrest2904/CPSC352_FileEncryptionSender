import json
import struct

def send_json(sock, obj):
    data = json.dumps(obj).encode("utf-8")
    length = struct.pack("!I", len(data))
    sock.sendall(length + data)

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed")
        buf += chunk
    return buf

def recv_json(sock):
    raw_len = recv_exact(sock, 4)
    (length,) = struct.unpack("!I", raw_len)
    data = recv_exact(sock, length)
    return json.loads(data.decode("utf-8"))