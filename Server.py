import socket
import json
import sqlite3
import threading
from pathlib import Path
from datetime import datetime
import uuid
from formatting import send_json, receive_json
from crypto_utils import crypto


class FileDropServer:
    
    def __init__(self, host='127.0.0.1', port=5000):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        self.storage_dir = Path('server_storage')
        self.storage_dir.mkdir(exist_ok=True)
        
        self.db_file = self.storage_dir / 'files.db'
        self.init_database()
        
        self.server_keys_dir = self.storage_dir / 'server_keys'
        self.server_keys_dir.mkdir(exist_ok=True)
        self.load_or_generate_server_keys()
        
        self.running = True
        self.client_count = 0
    
    def init_database(self):
        try:
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            
            c.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            c.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    file_id TEXT PRIMARY KEY,
                    sender_id TEXT NOT NULL,
                    receiver_id TEXT NOT NULL,
                    filename TEXT,
                    encrypted_file TEXT NOT NULL,
                    encrypted_symmetric_key TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    iv TEXT NOT NULL,
                    tag TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(sender_id) REFERENCES users(user_id),
                    FOREIGN KEY(receiver_id) REFERENCES users(user_id)
                )
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"✗ Database initialization error: {e}")
            raise
    
    def load_or_generate_server_keys(self):
        try:
            private_key_file = self.server_keys_dir / 'server_private.pem'
            public_key_file = self.server_keys_dir / 'server_public.pem'
            
            if private_key_file.exists() and public_key_file.exists():
                self.server_private_key = crypto.load_private_key(str(private_key_file))
                self.server_public_key = crypto.load_public_key(str(public_key_file))
                print("✓ Loaded existing server keys")
            else:
                print("→ Generating new server keypair...")
                self.server_private_key, self.server_public_key = crypto.generate_rsa_keypair()
                crypto.save_private_key(self.server_private_key, str(private_key_file))
                crypto.save_public_key(self.server_public_key, str(public_key_file))
                print("✓ Server keypair generated and saved")
        except Exception as e:
            print(f"✗ Error loading/generating server keys: {e}")
            raise
    
    def validate_user_id(self, user_id):
        if not user_id or not isinstance(user_id, str):
            return False, "Invalid user_id: must be non-empty string"
        if len(user_id) > 256:
            return False, "Invalid user_id: too long (max 256 characters)"
        if not user_id.replace('_', '').replace('-', '').isalnum():
            return False, "Invalid user_id: only alphanumeric, dash, underscore allowed"
        return True, ""
    
    def handle_client(self, client_socket, addr):
        client_id = f"{addr[0]}:{addr[1]}"
        try:
            request = receive_json(client_socket)
            action = request.get('action')
            
            print(f"\n📨 [{client_id}] Request: {action}")
            
            if action == 'register':
                response = self.handle_register(request)
            elif action == 'get_server_pubkey':
                response = self.handle_get_server_pubkey()
            elif action == 'get_receiver_pubkey':
                response = self.handle_get_receiver_pubkey(request)
            elif action == 'upload_file':
                response = self.handle_upload_file(request)
            elif action == 'list_files':
                response = self.handle_list_files(request)
            elif action == 'download_file':
                response = self.handle_download_file(request)
            else:
                response = {'status': 'error', 'message': 'Unknown action'}
            
            send_json(client_socket, response)
            print(f"✓ Response sent to {client_id}")
            
        except json.JSONDecodeError:
            print(f"✗ Invalid JSON from {client_id}")
            try:
                send_json(client_socket, {'status': 'error', 'message': 'Invalid JSON'})
            except:
                pass
        except Exception as e:
            print(f"✗ Error handling client {client_id}: {e}")
            try:
                send_json(client_socket, {'status': 'error', 'message': str(e)})
            except:
                pass
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def handle_register(self, request):
        try:
            user_id = request.get('user_id')
            public_key_pem = request.get('public_key')
            
            is_valid, error_msg = self.validate_user_id(user_id)
            if not is_valid:
                return {'status': 'error', 'message': error_msg}
            
            if not public_key_pem or not isinstance(public_key_pem, str):
                return {'status': 'error', 'message': 'Missing or invalid public_key'}
            
            try:
                crypto.pem_to_public_key(public_key_pem)
            except Exception as e:
                return {'status': 'error', 'message': f'Invalid public key format: {e}'}
            
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            c.execute(
                'INSERT OR REPLACE INTO users (user_id, public_key) VALUES (?, ?)',
                (user_id, public_key_pem)
            )
            conn.commit()
            conn.close()
            
            print(f"  ✓ User registered: {user_id}")
            return {'status': 'success', 'message': f'User {user_id} registered'}
        
        except Exception as e:
            print(f"  ✗ Registration error: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def handle_get_server_pubkey(self):
        try:
            server_pubkey_pem = crypto.public_key_to_pem(self.server_public_key)
            return {'status': 'success', 'public_key': server_pubkey_pem}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def handle_get_receiver_pubkey(self, request):
        try:
            receiver_id = request.get('receiver_id')
            
            if not receiver_id:
                return {'status': 'error', 'message': 'Missing receiver_id'}
            
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            c.execute('SELECT public_key FROM users WHERE user_id = ?', (receiver_id,))
            result = c.fetchone()
            conn.close()
            
            if not result:
                return {'status': 'error', 'message': f'Receiver {receiver_id} not found'}
            
            return {'status': 'success', 'receiver_id': receiver_id, 'public_key': result[0]}
        
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def handle_upload_file(self, request):
        try:
            sender_id = request.get('sender_id')
            receiver_id = request.get('receiver_id')
            filename = request.get('filename', 'unknown')
            encrypted_file = request.get('encrypted_file')
            encrypted_key = request.get('encrypted_symmetric_key')
            signature = request.get('signature')
            iv = request.get('iv')
            tag = request.get('tag')
            
            required_fields = [
                'sender_id', 'receiver_id', 'encrypted_file',
                'encrypted_symmetric_key', 'signature', 'iv', 'tag'
            ]
            
            for field in required_fields:
                if not request.get(field):
                    return {'status': 'error', 'message': f'Missing required field: {field}'}
            
            is_valid, error_msg = self.validate_user_id(sender_id)
            if not is_valid:
                return {'status': 'error', 'message': f'Invalid sender_id: {error_msg}'}
            
            is_valid, error_msg = self.validate_user_id(receiver_id)
            if not is_valid:
                return {'status': 'error', 'message': f'Invalid receiver_id: {error_msg}'}
            
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            c.execute('SELECT user_id FROM users WHERE user_id IN (?, ?)', (sender_id, receiver_id))
            results = c.fetchall()
            
            if len(results) != 2:
                conn.close()
                return {'status': 'error', 'message': 'Sender or receiver not registered'}
            
            file_id = str(uuid.uuid4())
            try:
                c.execute('''
                    INSERT INTO files
                    (file_id, sender_id, receiver_id, filename, encrypted_file,
                     encrypted_symmetric_key, signature, iv, tag)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (file_id, sender_id, receiver_id, filename, encrypted_file,
                      encrypted_key, signature, iv, tag))
                
                conn.commit()
            except Exception as e:
                conn.close()
                return {'status': 'error', 'message': f'Database error: {e}'}
            finally:
                conn.close()
            
            print(f"  ✓ File stored: {file_id}")
            print(f"    From: {sender_id} → To: {receiver_id}")
            print(f"    Size: {len(encrypted_file)} bytes (encrypted)")
            
            return {
                'status': 'success',
                'file_id': file_id,
                'message': 'File uploaded successfully'
            }
        
        except Exception as e:
            print(f"  ✗ Upload error: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def handle_list_files(self, request):
        try:
            receiver_id = request.get('receiver_id')
            
            if not receiver_id:
                return {'status': 'error', 'message': 'Missing receiver_id'}
            
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            c.execute('''
                SELECT file_id, sender_id, filename, created_at
                FROM files WHERE receiver_id = ? ORDER BY created_at DESC
            ''', (receiver_id,))
            results = c.fetchall()
            conn.close()
            
            files = [
                {
                    'file_id': r[0],
                    'sender_id': r[1],
                    'filename': r[2],
                    'created_at': r[3]
                }
                for r in results
            ]
            
            return {'status': 'success', 'files': files}
        
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def handle_download_file(self, request):
        try:
            file_id = request.get('file_id')
            
            if not file_id:
                return {'status': 'error', 'message': 'Missing file_id'}
            
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            c.execute('''
                SELECT sender_id, receiver_id, encrypted_file, encrypted_symmetric_key,
                       signature, iv, tag, filename
                FROM files WHERE file_id = ?
            ''', (file_id,))
            result = c.fetchone()
            conn.close()
            
            if not result:
                return {'status': 'error', 'message': 'File not found'}
            
            sender_id, receiver_id, encrypted_file, encrypted_key, signature, iv, tag, filename = result
            
            print(f"  ✓ File downloaded: {file_id}")
            print(f"    From: {sender_id} → To: {receiver_id}")
            
            return {
                'status': 'success',
                'file_id': file_id,
                'sender_id': sender_id,
                'receiver_id': receiver_id,
                'filename': filename,
                'encrypted_file': encrypted_file,
                'encrypted_symmetric_key': encrypted_key,
                'signature': signature,
                'iv': iv,
                'tag': tag
            }
        
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def start(self):
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            print(f"\n🔒 File Drop Server Started")
            print(f"   Host: {self.host}")
            print(f"   Port: {self.port}")
            print(f"   Storage: {self.storage_dir}")
            print(f"   Database: {self.db_file}")
            print(f"\n⏳ Waiting for connections...\n")
            
            while self.running:
                try:
                    client_socket, addr = self.socket.accept()
                    self.client_count += 1
                    print(f"→ Client #{self.client_count} connected from {addr[0]}:{addr[1]}")
                    
                    thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, addr),
                        daemon=True
                    )
                    thread.start()
                
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"✗ Error accepting client: {e}")
        
        except OSError as e:
            print(f"✗ Failed to start server: {e}")
            print(f"   Check if port {self.port} is already in use")
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
    
    def stop(self):
        print(f"\n\n🛑 Server shutting down...")
        self.running = False
        try:
            self.socket.close()
        except:
            pass
        print(f"✓ Server stopped\n")


if __name__ == '__main__':
    server = FileDropServer('127.0.0.1', 5000)
    server.start()