"""
Assignment 2 (Part 1) - Encrypted File Transfer
Client Code Skeleton

Student Name: Elena Orozco
Student ID: 2342655

Instructions:
  Fill in all sections marked with ## TODO to complete this file.
  Run this file AFTER starting part1_server.py.
"""

import socket
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Helper Functions  (already complete â€” read them!)
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def deserialize_public_key(public_key_bytes):
    """Convert raw PEM bytes received from the server back into a key object."""
    return serialization.load_pem_public_key(public_key_bytes)

def rsa_encrypt(public_key, plaintext):
    """Encrypt a small piece of data (e.g., an AES key) using the server's RSA public key."""
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def aes_encrypt(key, plaintext):
    """
    Encrypt arbitrary bytes with AES-CFB.
    Prepends a random 16-byte IV to the ciphertext so the server can decrypt.
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext          # first 16 bytes = IV, rest = ciphertext


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Client Logic
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def client():
    SERVER_HOST = '127.0.0.1'
    SERVER_PORT = 6000

    file_name = input("Enter the file name to send: ").strip()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((SERVER_HOST, SERVER_PORT))
        print(f"[+] Connected to server {SERVER_HOST}:{SERVER_PORT}")

        # â”€â”€ Step 1: Receive the server's RSA public key â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        # The server sends its PEM-encoded public key first (up to 4096 bytes).
        ## TODO: receive up to 4096 bytes from the socket and store in
        ##       'server_public_key_bytes', then deserialize it into
        ##       'server_public_key' using deserialize_public_key().
        # DONE
        server_public_key_bytes = sock.recv(4096)
        server_public_key = deserialize_public_key(server_public_key_bytes)
        print("[+] Received server public key.")

        # â”€â”€ Step 2: Generate a random AES key and send it (RSA-encrypted) â”€â”€â”€
        symmetric_key = os.urandom(32)   # 256-bit AES key

        ## TODO: encrypt 'symmetric_key' with 'server_public_key' using
        ##       rsa_encrypt(), store the result in 'encrypted_symmetric_key',
        ##       then send it through the socket.
        #
        encrypted_symmetric_key = rsa_encrypt(server_public_key, symmetric_key)
        sock.sendall(encrypted_symmetric_key)
        print("[+] Sent encrypted AES key to server.")

        # â”€â”€ Step 3: Send the filename â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        file_name_bytes  = file_name.encode('utf-8')
        file_name_length = len(file_name_bytes)
        sock.sendall(file_name_length.to_bytes(4, 'big'))   # 4-byte length prefix
        sock.sendall(file_name_bytes)
        print(f"[+] Sent filename: {file_name}")

        # â”€â”€ Step 4: Read, encrypt, and send the file â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        with open(file_name, 'rb') as f:
            file_content = f.read()

        ## TODO: encrypt 'file_content' using aes_encrypt() with 'symmetric_key'.
        ##       Store the result in 'encrypted_content'.
        #
        encrypted_content = aes_encrypt(symmetric_key, file_content)

        # Send the length of the encrypted content (8 bytes), then the content.
        sock.sendall(len(encrypted_content).to_bytes(8, 'big'))

        ## TODO: send 'encrypted_content' in 4096-byte chunks using a loop.
        #
        chunk_size = 4096
        for i in range(0, len(encrypted_content), chunk_size):
            chunk = encrypted_content[i:i+chunk_size]
            sock.sendall(chunk)

        print(f"[+] File '{file_name}' sent successfully.")


if __name__ == "__main__":
    client()