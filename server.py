"""
Assignment 2 (Part 1) - Encrypted File Transfer
Server Code Skeleton

Student Name: Elena Orozco
Student ID:   2342655

Instructions:
  Fill in all sections marked with ## TODO to complete this file.
  Run this file BEFORE starting part1_client.py.
"""

import socket
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Helper Functions  (already complete â€” read them!)
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def generate_rsa_key_pair():
    """Generate a 2048-bit RSA key pair. Returns (private_key, public_key)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()

def serialize_public_key(public_key):
    """Encode a public key as PEM bytes so it can be sent over a socket."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def rsa_decrypt(private_key, ciphertext):
    """Decrypt data that was encrypted with our RSA public key."""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def aes_decrypt(key, data):
    """
    Decrypt AES-CFB ciphertext.
    Expects 'data' to have a 16-byte IV prepended (as produced by aes_encrypt).
    """
    iv               = data[:16]
    actual_ciphertext = data[16:]
    cipher    = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(actual_ciphertext) + decryptor.finalize()


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Server Logic
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def server():
    HOST       = '0.0.0.0'
    PORT       = 6000
    UPLOAD_DIR = './uploads'
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    # â”€â”€ Generate the server's RSA key pair once at startup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    ## TODO: call generate_rsa_key_pair() and store the results in
    ##       'server_private_key' and 'server_public_key'.
    # DONE
    server_private_key, server_public_key = generate_rsa_key_pair()
    print("[+] RSA key pair generated.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"[+] Server listening on {HOST}:{PORT} ...")

        while True:
            client_socket, client_address = server_socket.accept()
            print(f"\n[+] Connection from {client_address}")

            try:
                # â”€â”€ Step 1: Send our public key to the client â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                ## TODO: serialize 'server_public_key' into 'server_public_key_bytes'
                ##       using serialize_public_key(), then send it.
                # DONE
                server_public_key_bytes = serialize_public_key(server_public_key)
                client_socket.sendall(server_public_key_bytes)
                print("[+] Public key sent to client.")

                # â”€â”€ Step 2: Receive the encrypted AES key and decrypt it â”€â”€â”€â”€â”€â”€â”€
                ## TODO: receive up to 4096 bytes (the RSA-encrypted AES key).
                ##       Decrypt it with rsa_decrypt() and store in 'symmetric_key'.
                # DONE
                encrypted_symmetric_key = client_socket.recv(4096)
                symmetric_key = rsa_decrypt(server_private_key, encrypted_symmetric_key)
                print("[+] Received and decrypted AES key.")

                # â”€â”€ Step 3: Receive the filename â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                file_name_length = int.from_bytes(client_socket.recv(4), 'big')
                ## TODO: receive exactly 'file_name_length' bytes and decode
                ##       them as UTF-8. Store the result in 'file_name'.
                # DONE
                file_name = client_socket.recv(file_name_length).decode('utf-8')
                print(f"[+] Receiving file: {file_name}")

                # â”€â”€ Step 4: Receive the encrypted file content â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                encrypted_length = int.from_bytes(client_socket.recv(8), 'big')

                encrypted_file_content = bytearray()
                ## TODO: loop until you have received 'encrypted_length' total bytes.
                ##       Receive in 4096-byte chunks and append each to
                ##       'encrypted_file_content'.
                # DONE
                while len(encrypted_file_content) < encrypted_length:
                    chunk_size = min(4096, encrypted_length - len(encrypted_file_content))
                    chunk = client_socket.recv(chunk_size)
                    if not chunk:
                        break
                    encrypted_file_content += chunk

                # â”€â”€ Step 5: Decrypt and save the file â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                ## TODO: call aes_decrypt() with 'symmetric_key' and the bytes
                ##       version of 'encrypted_file_content'. Store the result
                ##       in 'decrypted_content'.
                # DONE
                decrypted_content = aes_decrypt(symmetric_key, bytes(encrypted_file_content))

                file_path = os.path.join(UPLOAD_DIR, file_name)
                with open(file_path, 'wb') as f:
                    f.write(decrypted_content)

                print(f"[+] File '{file_name}' saved to {file_path}")
                print(f"    Content preview: {decrypted_content[:100]}")

            except Exception as e:
                print(f"[!] Error: {e}")
            finally:
                client_socket.close()


if __name__ == "__main__":
    server()