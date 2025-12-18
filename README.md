# CPSC352_FileEncryptionSender
For CPSC 352 group 3, this is our program for sending files across a network, ensuring everything is cryptographically secure. 

This project implements a simple encrypted file-drop service consisting of three independent Python programs:

1. server.py – stores encrypted files and public keys
2. sender.py – encrypts a file for a specific receiver and uploads it
3. receiver.py – downloads encrypted files addressed to the receiver and decrypts them

All encryption occurs on client machines. The server never sees plaintext files or private keys.


This project relies on the *cryptography* python library. 
Install it using the same Python interpreter that will run the scripts:

python3 -m pip install cryptography

or on Windows:

C:\Python313\python.exe -m pip install cryptography

No other third-party packages are required.


---------------------------------------------------------------------


Your project directory should include:

server.py
sender.py
receiver.py
cryptographyfunc.py
net_helpers.py

Additionally, sender.py expects a file named:

secret.txt

Place secret.txt in the same directory as sender.py.
Its contents can be anything; this is the plaintext file that will be encrypted and uploaded.

3. Files Created at Runtime

When sender.py or receiver.py runs for the first time, they create RSA key pairs on disk:

alice_private.pem
alice_public.pem
bob_private.pem
bob_public.pem

These are saved automatically in the working directory.
Future runs reuse these keys.

When receiver.py decrypts a file, it writes the result as:

received_<file_id>.bin

Example:

received_file-1.bin

This file contains the decrypted plaintext that was originally inside secret.txt.

---------------------------------------------------------------------

4. How to Run the System Locally

All components can run on the same machine using separate terminals.

Step 1: Start the server
Open a terminal and run:

python3 server.py

The server will display:

Server listening on 0.0.0.0:5000

Leave this terminal open.

Step 2: Register the receiver
Open a second terminal:

python3 receiver.py

On first run this will:

- Generate Bob’s RSA key pair
- Register Bob’s public key with the server
- List files for Bob (initially none)

Expected output:

Files for bob : []
No files.

Step 3: Send a file
Open a third terminal:

python3 sender.py

This will:

- Generate Alice’s RSA key pair (or load existing keys)
- Request Bob’s public key from the server
- Read secret.txt
- Encrypt it with a new symmetric key
- Encrypt the symmetric key with Bob’s public key
- Sign the encrypted data
- Upload the encrypted package to the server

You should see something like:

Uploaded file with id: file-1

Step 4: Receive and decrypt the file
Return to the receiver terminal or open another terminal:

python3 receiver.py

Now Bob should see the uploaded file:

Files for bob : [{'file_id': 'file-1', 'sender_id': 'alice'}]

The script will download the encrypted package, decrypt it, verify the signature, and write:

received_file-1.bin

This file contains the recovered plaintext originally stored in secret.txt.

---------------------------------------------------------------------

5. Notes and Recommendations

1. Restarting the server clears all in-memory users and uploaded files. If the server restarts, re-run sender.py and receiver.py to register keys again.
2. Run all scripts from inside the project folder so relative paths (such as secret.txt) work correctly.
3. Key files (*.pem) and decrypted outputs are saved in the working directory.
4. If you see “Decryption failed,” it usually means the receiver generated a new key after the sender encrypted the file. Restart the server and repeat the full workflow.