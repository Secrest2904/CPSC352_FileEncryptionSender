import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os

class CryptoUtils:
    
    def __init__(self):
        self.backend = default_backend()
    
    def generate_rsa_keypair(self, key_size=2048):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def save_private_key(self, private_key, filepath):
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(filepath, 'wb') as f:
            f.write(pem)
    
    def save_public_key(self, public_key, filepath):
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(filepath, 'wb') as f:
            f.write(pem)
    
    def load_private_key(self, filepath):
        with open(filepath, 'rb') as f:
            pem = f.read()
        return serialization.load_pem_private_key(
            pem, password=None, backend=self.backend
        )
    
    def load_public_key(self, filepath):
        with open(filepath, 'rb') as f:
            pem = f.read()
        return serialization.load_pem_public_key(pem, backend=self.backend)
    
    def generate_symmetric_key(self, key_size=256):
        return os.urandom(key_size // 8)
    
    def aes_encrypt(self, plaintext, symmetric_key):
        iv = os.urandom(12)
        cipher = AESGCM(symmetric_key)
        ciphertext = cipher.encrypt(iv, plaintext, None)
        tag = ciphertext[-16:]
        encrypted_data = ciphertext[:-16]
        return encrypted_data, iv, tag
    
    def aes_decrypt(self, ciphertext, symmetric_key, iv, tag):
        cipher = AESGCM(symmetric_key)
        return cipher.decrypt(iv, ciphertext + tag, None)
    
    def rsa_encrypt(self, plaintext, public_key):
        return public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def rsa_decrypt(self, ciphertext, private_key):
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def sign(self, data, private_key):
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    def verify_signature(self, data, signature, public_key):
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    def public_key_to_pem(self, public_key):
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    
    def pem_to_public_key(self, pem_string):
        if isinstance(pem_string, str):
            pem_string = pem_string.encode('utf-8')
        return serialization.load_pem_public_key(pem_string, backend=self.backend)
    
    def bytes_to_b64(self, data):
        return base64.b64encode(data).decode('utf-8')
    
    def b64_to_bytes(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.b64decode(data)

crypto = CryptoUtils()