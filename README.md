# Encrypted File Transfer

This folder contains a simple encrypted file transfer system using:
- **RSA (2048-bit)** for secure AES key exchange
- **AES-256-CFB** for file content encryption
- **TCP sockets** for communication

## Files

- `server.py` - Starts a server on port `6000`, receives encrypted files, decrypts, and saves into `uploads/`
- `client.py` - Connects to the server, encrypts a file, and sends it
- `uploads/` - Destination directory for received files
- `myfile.txt` - Example file you can send

## Prerequisites

- Python 3.x
- `cryptography` package

If needed, install dependency:

```bash
pip install cryptography
```

If you use your local virtual environment in this workspace:

```bash
source ../env/bin/activate
pip install cryptography
```

## How to Run

Open two terminals and run from the root directory.

### 1) Start server first

```bash
python3 server.py
```

Expected message includes:
- `RSA key pair generated`
- `Server listening on 0.0.0.0:6000`

### 2) Start client

```bash
python3 client.py
```

When prompted, enter a filename (example):

```text
myfile.txt
```

## What Happens

1. Server generates RSA key pair.
2. Client receives server public key.
3. Client generates random 32-byte AES key.
4. Client encrypts AES key with RSA and sends it.
5. Client sends filename.
6. Client encrypts file bytes with AES-CFB and sends encrypted bytes.
7. Server decrypts and writes file to `uploads/<filename>`.

## Verify Transfer

After a successful run, verify output file exists:

```bash
ls -l uploads/
```

You can also compare source and received file:

```bash
cmp myfile.txt uploads/myfile.txt && echo "Files match"
```
