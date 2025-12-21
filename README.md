# CPSC 352 - Secure File Encryption System

A **secure end-to-end encrypted file transfer system** built with Python. Transfer files between users with RSA-2048 encryption, AES-256-GCM symmetric encryption, and digital signature verification.

## Features

- **AES-256-GCM** symmetric encryption for files
- **RSA-2048-OAEP** key exchange for secure symmetric key distribution
- **RSA-PSS** digital signatures for authenticity verification
- **Client-Server architecture** with SQLite database
- **Interactive menu** for managing encrypted files

## Quick Start

### Prerequisites
```bash
pip install -r requirements.txt
```

### Terminal 1: Start Server
```bash
python Server.py
```
Server listens on `127.0.0.1:5000`

### Terminal 2: Register Receiver
```bash
python Receiver.py bob
```
Shows interactive menu:
- [1] List encrypted files
- [2] Decrypt a file
- [3] Exit

### Terminal 3: Send File
```bash
# Create test file
echo "Secret message!" > secret.txt

# Send to bob
python Sender.py alice secret.txt bob
```

Copy the **File ID** from output.

### Back to Terminal 2: Decrypt
In the receiver menu, select `[2]`, then choose the file to decrypt.
Decrypted file saved to `received_files/bob/`

## Usage Guide

| Command | Purpose |
|---------|---------|
| `python Server.py` | Start encrypted file server |
| `python Receiver.py <name>` | Register & open receiver menu |
| `python Sender.py <name> <file> <receiver>` | Send encrypted file |
| `python Receiver.py <name> <file_id> <sender>` | Direct decryption mode |

## Architecture

### Files
- **Server.py** - Central secure file storage server
- **Sender.py** - Client for encrypting & sending files
- **Receiver.py** - Client for decrypting & receiving files
- **crypto_utils.py** - Encryption/decryption utilities
- **formatting.py** - JSON socket communication

### Security Flow
1. **Registration**: Users register public keys with server
2. **Encryption**: Sender encrypts file with AES-256-GCM
3. **Signing**: Sender signs encrypted file with RSA-PSS
4. **Key Wrapping**: Sender encrypts symmetric key with receiver's public key
5. **Upload**: All components sent to server
6. **Download**: Receiver downloads & decrypts with private key
7. **Verification**: Receiver verifies signature with sender's public key

## File Structure
```
CPSC352_FileEncryptionSender/
├── Server.py
├── Sender.py
├── Receiver.py
├── crypto_utils.py
├── formatting.py
├── requirements.txt
├── .gitignore
└── README.md
```

## Technologies Used

- **Cryptography**: `cryptography` library (RSA-2048, AES-256, SHA-256)
- **Database**: SQLite3
- **Networking**: Python sockets
- **Serialization**: JSON

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Connection refused" | Start server first in Terminal 1 |
| "Receiver not found" | Register receiver before sending |
| "Could not retrieve public key" | Restart receiver client |
| Port 5000 in use | Kill process: `lsof -ti:5000 \| xargs kill -9` |

## License

CPSC 352 Course Project - California State University, Fullerton

## Submission

- **Course**: CPSC 352
- **Semester**: Fall 2025
- **Project Type**: End-to-End Encryption System