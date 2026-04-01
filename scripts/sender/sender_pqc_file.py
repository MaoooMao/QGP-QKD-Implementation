#!/usr/bin/env python3

import socket
import os
import hashlib
import oqs

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BOB_IP = "192.168.10.230"  # Bob's IP via CN4010 Local port
PRIVATE_KEY_PATH = os.path.join(SCRIPT_DIR, "private.key")
SIG_ALG = "ML-DSA-65"

# Load Dilithium private key
with open(PRIVATE_KEY_PATH, "rb") as f:
    private_key = f.read()
print(f"Loaded Dilithium private key: {len(private_key)} bytes")

# Sign the message
with open(os.path.join(SCRIPT_DIR, "qgppaper.pdf"), "rb") as mf:
    message = mf.read()
print(f"File: qgppaper.pdf")
print(f"Size: {len(message)} bytes")
print(f"MD5:  {hashlib.md5(message).hexdigest()}")
signer = oqs.Signature(SIG_ALG, private_key)
signature = signer.sign(message)
print(f"Signed with {SIG_ALG}: {len(signature)} bytes signature")

# Pack: [4-byte sig length][signature][message]
packet = len(signature).to_bytes(4, 'big') + signature + message

# Send
s = socket.socket()
s.connect((BOB_IP, 5201))
print(f"Connected to Bob, sending PQC-signed message...")
s.send(packet)

print(f"Sent: {len(packet)} bytes total (sig={len(signature)}, msg={len(message)})")
print(f"Message: qgppaper.pdf ({len(message)} bytes)")
s.close()
