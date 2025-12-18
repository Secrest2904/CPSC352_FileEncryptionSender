import json
import struct

def send_json(sock, data):
    json_str = json.dumps(data)
    json_bytes = json_str.encode('utf-8')
    length = len(json_bytes)
    sock.sendall(struct.pack('>I', length))
    sock.sendall(json_bytes)

def receive_json(sock):
    length_bytes = sock.recv(4)
    if not length_bytes:
        raise ConnectionError("Connection closed")
    length = struct.unpack('>I', length_bytes)[0]
    json_bytes = b''
    while len(json_bytes) < length:
        chunk = sock.recv(min(4096, length - len(json_bytes)))
        if not chunk:
            raise ConnectionError("Connection closed")
        json_bytes += chunk
    json_str = json_bytes.decode('utf-8')
    return json.loads(json_str)