import socket
import sys
import io
from pathlib import Path
from formatting import send_json, receive_json
from crypto_utils import crypto
import os


if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')


class FileReceiver:
    
    def __init__(self, receiver_id, server_host='127.0.0.1', server_port=5000):
        self.receiver_id = receiver_id
        self.server_host = server_host
        self.server_port = server_port
        
        self.keys_dir = Path(f'keys/{receiver_id}')
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        
        self.received_dir = Path(f'received_files/{receiver_id}')
        self.received_dir.mkdir(parents=True, exist_ok=True)
        
        self.load_or_generate_keypair()
        self.register_with_server()
    
    def load_or_generate_keypair(self):
        private_key_file = self.keys_dir / 'private.pem'
        public_key_file = self.keys_dir / 'public.pem'
        
        if private_key_file.exists() and public_key_file.exists():
            self.private_key = crypto.load_private_key(str(private_key_file))
            self.public_key = crypto.load_public_key(str(public_key_file))
            print(f"[OK] Loaded keypair for {self.receiver_id}")
        else:
            print(f"[*] Generating new keypair for {self.receiver_id}...")
            self.private_key, self.public_key = crypto.generate_rsa_keypair()
            crypto.save_private_key(self.private_key, str(private_key_file))
            crypto.save_public_key(self.public_key, str(public_key_file))
            print(f"[OK] Keypair generated and saved\n")
    
    def send_request(self, request):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.server_host, self.server_port))
            send_json(sock, request)
            response = receive_json(sock)
            sock.close()
            return response
        except Exception as e:
            print(f"[FAIL] Server connection error: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def register_with_server(self):
        public_key_pem = crypto.public_key_to_pem(self.public_key)
        response = self.send_request({
            'action': 'register',
            'user_id': self.receiver_id,
            'public_key': public_key_pem
        })
        
        if response.get('status') == 'success':
            print(f"[OK] Registered with server as {self.receiver_id}\n")
        else:
            print(f"[FAIL] Registration failed: {response.get('message')}\n")
    
    def list_files(self):
        print(f"\n{'='*70}")
        print(f"  Encrypted Files for {self.receiver_id}")
        print(f"{'='*70}\n")
        
        response = self.send_request({
            'action': 'list_files',
            'receiver_id': self.receiver_id
        })
        
        if response.get('status') != 'success':
            print(f"[FAIL] Failed to list files: {response.get('message')}\n")
            return []
        
        files = response.get('files', [])
        
        if not files:
            print(f"  (No encrypted files available)\n")
            return []
        
        for i, file_info in enumerate(files, 1):
            print(f"  [{i}] From: {file_info['sender_id']}")
            print(f"      File: {file_info['filename']}")
            print(f"      ID: {file_info['file_id']}")
            print(f"      Time: {file_info['created_at']}\n")
        
        return files
    
    def download_and_decrypt(self, file_id, sender_id):
        try:
            print(f"\n[*] Downloading encrypted file from server...")
            response = self.send_request({
                'action': 'download_file',
                'file_id': file_id
            })
            
            if response.get('status') != 'success':
                print(f"[FAIL] Download failed: {response.get('message')}\n")
                return False
            
            encrypted_file_b64 = response.get('encrypted_file')
            encrypted_key_b64 = response.get('encrypted_symmetric_key')
            signature_b64 = response.get('signature')
            iv_b64 = response.get('iv')
            tag_b64 = response.get('tag')
            filename = response.get('filename', 'decrypted_file')
            
            encrypted_file = crypto.b64_to_bytes(encrypted_file_b64)
            encrypted_key = crypto.b64_to_bytes(encrypted_key_b64)
            signature = crypto.b64_to_bytes(signature_b64)
            iv = crypto.b64_to_bytes(iv_b64)
            tag = crypto.b64_to_bytes(tag_b64)
            
            print(f"   [OK] Downloaded {len(encrypted_file)} bytes")
            print(f"   IV: {iv_b64[:32]}...")
            print(f"   Auth Tag: {tag_b64[:32]}...\n")
            
            print(f"[*] Decrypting symmetric key with private key (RSA-OAEP)...")
            try:
                symmetric_key = crypto.rsa_decrypt(encrypted_key, self.private_key)
                print(f"   [OK] Symmetric key decrypted ({len(symmetric_key)} bytes)\n")
            except Exception as e:
                print(f"   [FAIL] Failed to decrypt symmetric key: {e}")
                print(f"   This file may not be intended for you.\n")
                return False
            
            print(f"[*] Decrypting file with AES-256-GCM...")
            try:
                plaintext = crypto.aes_decrypt(encrypted_file, symmetric_key, iv, tag)
                print(f"   [OK] File decrypted ({len(plaintext)} bytes)\n")
            except Exception as e:
                print(f"   [FAIL] Decryption failed: {e}")
                print(f"   File may be corrupted.\n")
                return False
            
            print(f"[*] Requesting sender's public key ({sender_id})...")
            response = self.send_request({
                'action': 'get_receiver_pubkey',
                'receiver_id': sender_id
            })
            
            if response.get('status') != 'success':
                print(f"   [FAIL] Could not retrieve sender's public key: {response.get('message')}")
                print(f"   Signature verification skipped.\n")
                sender_pubkey = None
            else:
                sender_pubkey = crypto.pem_to_public_key(response['public_key'])
                print(f"   [OK] Retrieved {sender_id}'s public key\n")
            
            if sender_pubkey:
                print(f"[*] Verifying digital signature...")
                is_valid = crypto.verify_signature(encrypted_file, signature, sender_pubkey)
                
                if is_valid:
                    print(f"   [OK] Signature VERIFIED")
                    print(f"   [OK] File is authentic from {sender_id}\n")
                else:
                    print(f"   [FAIL] Signature INVALID")
                    print(f"   WARNING: File may have been tampered with!\n")
                    return False
            
            print(f"[*] Saving decrypted file...")
            output_path = self.received_dir / filename
            
            if output_path.exists():
                base_name = output_path.stem
                extension = output_path.suffix
                counter = 1
                while output_path.exists():
                    output_path = self.received_dir / f"{base_name}_{counter}{extension}"
                    counter += 1
            
            with open(output_path, 'wb') as f:
                f.write(plaintext)
            
            print(f"   [OK] Saved to: {output_path}\n")
            
            print(f"{'='*70}")
            print(f"[OK] FILE DECRYPTION SUCCESSFUL")
            print(f"{'='*70}")
            print(f"  File ID: {file_id}")
            print(f"  From: {sender_id}")
            print(f"  Original name: {filename}")
            print(f"  Saved to: {output_path}")
            print(f"  Size: {len(plaintext)} bytes")
            print(f"  Signature: VERIFIED\n")
            
            return True
        
        except Exception as e:
            print(f"[FAIL] Unexpected error: {e}\n")
            return False
    
    def interactive_mode(self):
        while True:
            print(f"{'='*70}")
            print(f"  RECEIVER MENU")
            print(f"{'='*70}")
            print(f"  [1] List encrypted files")
            print(f"  [2] Decrypt a file")
            print(f"  [3] Exit")
            print(f"{'='*70}\n")
            
            choice = input("  Select option (1-3): ").strip()
            
            if choice == '1':
                self.list_files()
            
            elif choice == '2':
                files = self.list_files()
                if not files:
                    print()
                    continue
                
                try:
                    file_num = int(input("  Select file number (or 0 to cancel): ").strip())
                    if file_num == 0:
                        print()
                        continue
                    if file_num < 1 or file_num > len(files):
                        print("  Invalid selection\n")
                        continue
                    
                    selected_file = files[file_num - 1]
                    file_id = selected_file['file_id']
                    sender_id = selected_file['sender_id']
                    
                    self.download_and_decrypt(file_id, sender_id)
                
                except ValueError:
                    print("  Invalid input\n")
                except Exception as e:
                    print(f"  Error: {e}\n")
            
            elif choice == '3':
                print("\n  Goodbye!\n")
                break
            
            else:
                print("  Invalid option\n")



def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python Receiver.py <receiver_id> [server_host] [server_port]")
        print("  python Receiver.py <receiver_id> <file_id> <sender_id>  (direct mode)\n")
        print("Example:")
        print("  python Receiver.py bob                                  (interactive)")
        print("  python Receiver.py bob 127.0.0.1 5000                  (interactive)")
        print("  python Receiver.py bob a1b2c3d4 alice                  (direct decrypt)\n")
        sys.exit(1)
    
    receiver_id = sys.argv[1]
    
    if len(sys.argv) >= 4:
        file_id = sys.argv[2]
        sender_id = sys.argv[3]
        server_host = sys.argv[4] if len(sys.argv) > 4 else '127.0.0.1'
        server_port = int(sys.argv[5]) if len(sys.argv) > 5 else 5000
        
        print(f"\n{'='*70}")
        print(f"  CPSC 352 - Secure File Encryption Receiver")
        print(f"{'='*70}\n")
        
        receiver = FileReceiver(receiver_id, server_host, server_port)
        receiver.download_and_decrypt(file_id, sender_id)
    else:
        server_host = sys.argv[2] if len(sys.argv) > 2 else '127.0.0.1'
        server_port = int(sys.argv[3]) if len(sys.argv) > 3 else 5000
        
        print(f"\n{'='*70}")
        print(f"  CPSC 352 - Secure File Encryption Receiver")
        print(f"{'='*70}\n")
        
        receiver = FileReceiver(receiver_id, server_host, server_port)

        if len(sys.argv) == 2:
            receiver.interactive_mode()
        else:
            receiver.interactive_mode()

if __name__ == '__main__':
    main()