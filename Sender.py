import socket
import sys
from pathlib import Path
from formatting import send_json, receive_json
from crypto_utils import crypto


class FileSender:
    
    def __init__(self, sender_id, server_host='127.0.0.1', server_port=5000):
        self.sender_id = sender_id
        self.server_host = server_host
        self.server_port = server_port
        
        self.keys_dir = Path(f'keys/{sender_id}')
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        
        self.load_or_generate_keypair()
        self.register_with_server()
    
    def load_or_generate_keypair(self):
        private_key_file = self.keys_dir / 'private.pem'
        public_key_file = self.keys_dir / 'public.pem'
        
        if private_key_file.exists() and public_key_file.exists():
            self.private_key = crypto.load_private_key(str(private_key_file))
            self.public_key = crypto.load_public_key(str(public_key_file))
            print(f"✓ Loaded keypair for {self.sender_id}")
        else:
            print(f"→ Generating new keypair for {self.sender_id}...")
            self.private_key, self.public_key = crypto.generate_rsa_keypair()
            crypto.save_private_key(self.private_key, str(private_key_file))
            crypto.save_public_key(self.public_key, str(public_key_file))
            print(f"✓ Keypair generated and saved\n")
    
    def send_request(self, request):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.server_host, self.server_port))
            send_json(sock, request)
            response = receive_json(sock)
            sock.close()
            return response
        except Exception as e:
            print(f"✗ Server connection error: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def register_with_server(self):
        public_key_pem = crypto.public_key_to_pem(self.public_key)
        response = self.send_request({
            'action': 'register',
            'user_id': self.sender_id,
            'public_key': public_key_pem
        })
        
        if response.get('status') == 'success':
            print(f"✓ Registered with server as {self.sender_id}\n")
        else:
            print(f"✗ Registration failed: {response.get('message')}\n")
    
    def get_receiver_pubkey(self, receiver_id):
        response = self.send_request({
            'action': 'get_receiver_pubkey',
            'receiver_id': receiver_id
        })
        
        if response.get('status') == 'success':
            return crypto.pem_to_public_key(response['public_key'])
        else:
            return None
    
    def send_file(self, filename, receiver_id):
        try:
            print(f"\n{'='*70}")
            print(f"  CPSC 352 - Secure File Encryption Sender")
            print(f"{'='*70}\n")
            
            print(f"→ Requesting {receiver_id}'s public key...")
            receiver_pubkey = self.get_receiver_pubkey(receiver_id)
            
            if not receiver_pubkey:
                print(f"   ✗ Could not retrieve {receiver_id}'s public key")
                print(f"   → Continuing without receiver public key validation...\n")
                receiver_pubkey = None
            else:
                print(f"   ✓ Retrieved {receiver_id}'s public key\n")
            
            print(f"→ Reading file: {filename}")
            try:
                with open(filename, 'rb') as f:
                    plaintext = f.read()
                print(f"   ✓ File read ({len(plaintext)} bytes)\n")
            except Exception as e:
                print(f"   ✗ File read error: {e}\n")
                return False
            
            print(f"→ Generating 256-bit symmetric key (AES)...")
            symmetric_key = crypto.generate_symmetric_key(256)
            print(f"   ✓ Symmetric key generated\n")
            
            print(f"→ Encrypting file with AES-256-GCM...")
            encrypted_file, iv, tag = crypto.aes_encrypt(plaintext, symmetric_key)
            print(f"   ✓ File encrypted ({len(plaintext)} bytes → {len(encrypted_file)} bytes with auth tag)")
            print(f"   IV: {crypto.bytes_to_b64(iv)[:32]}...")
            print(f"   Auth Tag: {crypto.bytes_to_b64(tag)[:32]}...\n")
            
            print(f"→ Signing encrypted file with RSA-PSS...")
            signature = crypto.sign(encrypted_file, self.private_key)
            print(f"   ✓ Signature generated ({len(signature)} bytes)\n")
            
            if not receiver_pubkey:
                print(f"\n   ✗ SENDER ERROR")
                print(f"   Cannot proceed without receiver's public key.")
                print(f"   Make sure receiver has registered first.\n")
                print(f"   Receiver should run:")
                print(f"     python Receiver.py {receiver_id}\n")
                return False
            
            print(f"→ Encrypting symmetric key with RSA-OAEP...")
            encrypted_key = crypto.rsa_encrypt(symmetric_key, receiver_pubkey)
            print(f"   ✓ Symmetric key encrypted ({len(symmetric_key)} bytes → {len(encrypted_key)} bytes)\n")
            
            print(f"→ Uploading to server...")
            response = self.send_request({
                'action': 'upload_file',
                'sender_id': self.sender_id,
                'receiver_id': receiver_id,
                'filename': Path(filename).name,
                'encrypted_file': crypto.bytes_to_b64(encrypted_file),
                'encrypted_symmetric_key': crypto.bytes_to_b64(encrypted_key),
                'signature': crypto.bytes_to_b64(signature),
                'iv': crypto.bytes_to_b64(iv),
                'tag': crypto.bytes_to_b64(tag)
            })
            
            if response.get('status') != 'success':
                print(f"   ✗ Upload failed: {response.get('message')}\n")
                return False
            
            print(f"\n{'='*70}")
            print(f"✓ FILE UPLOAD SUCCESSFUL")
            print(f"{'='*70}")
            print(f"  File ID: {response.get('file_id')}")
            print(f"  To: {receiver_id}")
            print(f"  Filename: {Path(filename).name}")
            print(f"  Size: {len(plaintext)} bytes")
            print(f"  Encrypted Size: {len(encrypted_file)} bytes")
            print(f"  Server Response: {response.get('message')}\n")
            
            return True
        
        except Exception as e:
            print(f"✗ Unexpected error: {e}\n")
            return False
    
    def interactive_mode(self):
        while True:
            print(f"{'='*70}")
            print(f"  SENDER MENU")
            print(f"{'='*70}")
            print(f"  [1] Send encrypted file")
            print(f"  [2] Exit")
            print(f"{'='*70}\n")
            
            choice = input("  Select option (1-2): ").strip()
            
            if choice == '1':
                filename = input("  Enter filename to encrypt: ").strip()
                receiver_id = input("  Enter receiver ID: ").strip()
                
                if not filename or not receiver_id:
                    print("  Invalid input\n")
                    continue
                
                self.send_file(filename, receiver_id)
            
            elif choice == '2':
                print("\n  Goodbye!\n")
                break
            
            else:
                print("  Invalid option\n")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python Sender.py <sender_id> [server_host] [server_port]")
        print("  python Sender.py <sender_id> <filename> <receiver_id> [host] [port]\n")
        print("Example:")
        print("  python Sender.py alice                                  (interactive)")
        print("  python Sender.py alice 127.0.0.1 5000                  (interactive)")
        print("  python Sender.py alice document.pdf bob                (direct send)\n")
        sys.exit(1)
    
    sender_id = sys.argv[1]
    
    if len(sys.argv) >= 4:
        filename = sys.argv[2]
        receiver_id = sys.argv[3]
        server_host = sys.argv[4] if len(sys.argv) > 4 else '127.0.0.1'
        server_port = int(sys.argv[5]) if len(sys.argv) > 5 else 5000
        
        sender = FileSender(sender_id, server_host, server_port)
        sender.send_file(filename, receiver_id)
    else:
        server_host = sys.argv[2] if len(sys.argv) > 2 else '127.0.0.1'
        server_port = int(sys.argv[3]) if len(sys.argv) > 3 else 5000
        
        sender = FileSender(sender_id, server_host, server_port)
        sender.interactive_mode()


if __name__ == '__main__':
    main()