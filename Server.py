import socket, threading, uuid
from network import send_json, recv_json

HOST = "0.0.0.0"
PORT = 5000

USERS = {}
FILES = {}

def handle_client(conn, addr):
    try:
        while True:
            try:
                req = recv_json(conn)
            except ConnectionError:
                break

            rtype = req.get("type")
            if rtype == "REGISTER":
                user_id = req["user_id"]
                public_key_pem = req["public_key_pem"]
                USERS[user_id] = public_key_pem
                send_json(conn, {"ok": True})

            elif rtype == "GET_PUBKEY":
                user_id = req["user_id"]
                if user_id in USERS:
                    send_json(conn, {"ok": True, "public_key_pem": USERS[user_id]})
                else:
                    send_json(conn, {"ok": False, "error": "unknown user"})

            elif rtype == "UPLOAD_FILE":
                package = req["package"]
                file_id = package.get("file_id") or str(uuid.uuid4())
                package["file_id"] = file_id
                FILES[file_id] = package
                send_json(conn, {"ok": True, "file_id": file_id})

            elif rtype == "LIST_FILES":
                receiver_id = req["receiver_id"]
                meta = [
                    {"file_id": fid, "sender_id": pkg["sender_id"]}
                    for fid, pkg in FILES.items()
                    if pkg["receiver_id"] == receiver_id
                ]
                send_json(conn, {"ok": True, "files": meta})

            elif rtype == "DOWNLOAD_FILE":
                file_id = req["file_id"]
                pkg = FILES.get(file_id)
                if pkg is None:
                    send_json(conn, {"ok": False, "error": "no such file"})
                else:
                    send_json(conn, {"ok": True, "package": pkg})

            else:
                send_json(conn, {"ok": False, "error": "unknown type"})
    finally:
        conn.close()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            print("Connection from", addr)
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()