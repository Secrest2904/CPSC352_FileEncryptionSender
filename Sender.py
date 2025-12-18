import socket, base64
from network import send_json, recv_json
from cryptographyfunc import (
    load_or_create_rsa_keypair,
    private_key_to_pem,
    public_key_to_pem,
    load_public_key_from_pem,
    package_for_receiver,
)

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000

def register_user(sock, user_id, public_key_pem):
    send_json(sock, {
        "type": "REGISTER",
        "user_id": user_id,
        "public_key_pem": public_key_pem.decode("utf-8"),
    })
    resp = recv_json(sock)
    assert resp.get("ok"), f"register failed: {resp}"

def get_pubkey(sock, user_id):
    send_json(sock, {"type": "GET_PUBKEY", "user_id": user_id})
    resp = recv_json(sock)
    if not resp.get("ok"):
        raise RuntimeError(f"get_pubkey failed: {resp}")
    pem_str = resp["public_key_pem"]
    return load_public_key_from_pem(pem_str.encode("utf-8"))

def upload_file(sock, package):
    send_json(sock, {"type": "UPLOAD_FILE", "package": package})
    resp = recv_json(sock)
    if not resp.get("ok"):
        raise RuntimeError(f"upload_file failed: {resp}")
    return resp["file_id"]

def main():
    sender_id = "alice"
    receiver_id = "bob"
    file_path = "secret.txt"

    # For demo: generate a fresh keypair each run
    sk_sender, pk_sender = load_or_create_rsa_keypair(sender_id)
    sk_pem = private_key_to_pem(sk_sender)
    pk_pem = public_key_to_pem(pk_sender)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((SERVER_HOST, SERVER_PORT))

        # 1) register
        register_user(sock, sender_id, pk_pem)

        # 2) get receiver pubkey
        receiver_pub = get_pubkey(sock, receiver_id)

        # 3) read file
        with open(file_path, "rb") as f:
            plaintext = f.read()

        # 4) create crypto package
        file_id = "file-1"  # or uuid manually
        package = package_for_receiver(
            plaintext,
            sender_id=sender_id,
            receiver_id=receiver_id,
            file_id=file_id,
            sender_private_key=sk_sender,
            receiver_public_key=receiver_pub,
        )

        # 5) upload
        real_file_id = upload_file(sock, package)
        print("Uploaded file with id:", real_file_id)

if __name__ == "__main__":
    main()
