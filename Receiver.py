import socket, uuid
from network import send_json, recv_json
from cryptographyfunc import (
    load_or_create_rsa_keypair,
    private_key_to_pem,
    public_key_to_pem,
    load_public_key_from_pem,
    unpack_for_receiver,
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

def list_files(sock, receiver_id):
    send_json(sock, {"type": "LIST_FILES", "receiver_id": receiver_id})
    resp = recv_json(sock)
    if not resp.get("ok"):
        raise RuntimeError(f"list_files failed: {resp}")
    return resp["files"]

def download_file(sock, file_id):
    send_json(sock, {"type": "DOWNLOAD_FILE", "file_id": file_id})
    resp = recv_json(sock)
    if not resp.get("ok"):
        raise RuntimeError(f"download_file failed: {resp}")
    return resp["package"]

def get_sender_public_key_by_id(sender_id):
    raise NotImplementedError("Hook this up to server GET_PUBKEY in real code")

def main():
    receiver_id = "bob"

    sk_receiver, pk_receiver = load_or_create_rsa_keypair(receiver_id)
    sk_pem = private_key_to_pem(sk_receiver)
    pk_pem = public_key_to_pem(pk_receiver)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((SERVER_HOST, SERVER_PORT))

        register_user(sock, receiver_id, pk_pem)

        files = list_files(sock, receiver_id)
        print("Files for", receiver_id, ":", files)
        if not files:
            print("No files.")
            return

        file_id = files[0]["file_id"]
        sender_id = files[0]["sender_id"]

        package = download_file(sock, file_id)

        def get_pub(sender_id_inner):
            send_json(sock, {"type": "GET_PUBKEY", "user_id": sender_id_inner})
            resp = recv_json(sock)
            if not resp.get("ok"):
                raise RuntimeError(f"GET_PUBKEY failed: {resp}")
            pem_str = resp["public_key_pem"].encode("utf-8")
            return load_public_key_from_pem(pem_str)

        plaintext = unpack_for_receiver(
            package,
            receiver_private_key=sk_receiver,
            get_sender_public_key_by_id=get_pub,
        )

        out_name = f"received_{file_id}.bin"
        with open(out_name, "wb") as f:
            f.write(plaintext)

        print("Saved decrypted file as", out_name)

if __name__ == "__main__":
    main()
