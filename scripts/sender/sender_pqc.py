#!/usr/bin/env python3

import socket
import os
import hashlib
import oqs

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BOB_IP = "192.168.10.230"
PRIVATE_KEY_PATH = os.path.join(SCRIPT_DIR, "private.key")
SIG_ALG = "ML-DSA-65"

with open(PRIVATE_KEY_PATH, "rb") as f:
    private_key = f.read()
print(f"Loaded Dilithium private key: {len(private_key)} bytes")

message = b"TOP SECRET: This message is signed with PQC ML-DSA-65 (Dilithium) at the application layer, then encrypted with AES-256-CTR using QKD keys at the network layer by CN4010 hardware encryptor."
print(f"Message: {message.decode()}")
print(f"Size: {len(message)} bytes")
print(f"MD5:  {hashlib.md5(message).hexdigest()}")

signer = oqs.Signature(SIG_ALG, private_key)
signature = signer.sign(message)
print(f"Signed with {SIG_ALG}: {len(signature)} bytes signature")

packet = len(signature).to_bytes(4, 'big') + signature + message

s = socket.socket()
s.connect((BOB_IP, 5201))
print(f"Connected to Bob, sending PQC-signed message...")
s.send(packet)

print(f"Sent: {len(packet)} bytes total (sig={len(signature)}, msg={len(message)})")
s.close()
