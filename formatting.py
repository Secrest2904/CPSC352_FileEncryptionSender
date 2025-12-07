import json
import struct

def send_json(socket, object):
    data = json.dumps(object).encode("utf-8")
    length = struct.pack("!I", len(data)) # !I unpacks it as 32 bit integers
    socket.sendall(length + data)

def limited_receive(socket, n):
    buffer = b""
    while len(buffer) < n:
        chunk = socket.recv(n - len(buffer))
        if not chunk:
            raise ConnectionError("The Socket connection closed")
        buffer += chunk
    return buffer

def receive_json(socket):
    datalen = limited_receive(socket, 4)
    (Length,) = struct.unpack("!I", datalen) # Because it returns length as a tuple
    data = limited_receive(socket, Length)
    return json.loads(data.decode("utf-8"))