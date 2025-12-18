import os, base64, json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 3072
)
    public_key = private_key.public_key()
    return private_key, public_key

def load_or_create_rsa_keypair(user_id: str):
    priv_path = f"{user_id}_private.pem"
    pub_path = f"{user_id}_public.pem"

    if os.path.exists(priv_path):
        with open(priv_path, "rb") as f:
            priv_pem = f.read()
        private_key = load_private_key_from_pem(priv_pem, password=None)
        public_key = private_key.public_key()
        return private_key, public_key

    # No key yet
    private_key, public_key = generate_rsa_keypair()

    priv_pem = private_key_to_pem(private_key)
    pub_pem = public_key_to_pem(public_key)

    with open(priv_path, "wb") as f:
        f.write(priv_pem)
    with open(pub_path, "wb") as f:
        f.write(pub_pem)

    return private_key, public_key


def private_key_to_pem(private_key, password=None):
    enc_alg = (
        serialization.BestAvailableEncryption(password)
        if password is not None
        else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_alg,
    )

def public_key_to_pem(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def load_private_key_from_pem(pem_bytes, password=None):
    return serialization.load_pem_private_key(pem_bytes, password=password)

def load_public_key_from_pem(pem_bytes):
    return serialization.load_pem_public_key(pem_bytes)



def aead_encrypt(plaintext: bytes, aad: bytes):
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    # AESGCM.encrypt returns ciphertext || tag
    return key, nonce, ciphertext

def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes):
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return plaintext

def encrypt_key_for_receiver(receiver_public_key, sym_key: bytes) -> bytes:
    return receiver_public_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )

def decrypt_key_for_receiver(receiver_private_key, enc_sym_key: bytes) -> bytes:
    return receiver_private_key.decrypt(
        enc_sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )


def sign_bytes(sender_private_key, data: bytes) -> bytes:
    return sender_private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

def verify_signature(sender_public_key, signature: bytes, data: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    try:
        sender_public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
    

def package_for_receiver(
    plaintext: bytes,
    sender_id: str,
    receiver_id: str,
    file_id: str,
    sender_private_key,
    receiver_public_key,
):

    aad_dict = {
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "file_id": file_id,
    }
    aad_bytes = json.dumps(aad_dict).encode("utf-8")

    sym_key, nonce, ciphertext = aead_encrypt(plaintext, aad_bytes)

    enc_sym_key = encrypt_key_for_receiver(receiver_public_key, sym_key)

    from cryptography.hazmat.primitives import hashes
    digest = hashes.Hash(hashes.SHA256())
    digest.update(ciphertext)
    digest.update(aad_bytes)
    digest.update(enc_sym_key)
    h = digest.finalize()

    signature = sign_bytes(sender_private_key, h)

    def b64(x: bytes) -> str:
        return base64.b64encode(x).decode("ascii")

    package = {
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "file_id": file_id,
        "aad": aad_dict,
        "nonce_b64": b64(nonce),
        "ciphertext_b64": b64(ciphertext),
        "enc_sym_key_b64": b64(enc_sym_key),
        "signature_b64": b64(signature),
    }
    return package

def unpack_for_receiver(
    package: dict,
    receiver_private_key,
    get_sender_public_key_by_id,
) -> bytes:
    import base64, json
    aad_dict = package["aad"]
    aad_bytes = json.dumps(aad_dict).encode("utf-8")

    def b64d(s: str) -> bytes:
        return base64.b64decode(s.encode("ascii"))

    nonce = b64d(package["nonce_b64"])
    ciphertext = b64d(package["ciphertext_b64"])
    enc_sym_key = b64d(package["enc_sym_key_b64"])
    signature = b64d(package["signature_b64"])

    sender_id = package["sender_id"]

    # 2) Decrypt symmetric key
    sym_key = decrypt_key_for_receiver(receiver_private_key, enc_sym_key)

    # 3) AEAD decrypt
    plaintext = aead_decrypt(sym_key, nonce, ciphertext, aad_bytes)

    # 4) Verify signature
    from cryptography.hazmat.primitives import hashes
    digest = hashes.Hash(hashes.SHA256())
    digest.update(ciphertext)
    digest.update(aad_bytes)
    digest.update(enc_sym_key)
    h = digest.finalize()

    sender_pub = get_sender_public_key_by_id(sender_id)
    if not verify_signature(sender_pub, signature, h):
        raise ValueError("Signature verification failed")

    return plaintext