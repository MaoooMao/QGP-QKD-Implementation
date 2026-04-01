import socket
import hashlib
import os
import oqs

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_KEY_PATH = os.path.join(SCRIPT_DIR, "public.key")
SIG_ALG = "ML-DSA-65"

with open(PUBLIC_KEY_PATH, "rb") as f:
    public_key = f.read()

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 5201))
s.listen(1)

while True:
    print("Waiting for Alice to connect...")
    conn, addr = s.accept()
    print(f"Alice connected: {addr}")

    received = b''
    while True:
        data = conn.recv(65536)
        if not data:
            break
        received += data
    conn.close()

    sig_len = int.from_bytes(received[:4], 'big')
    signature = received[4:4+sig_len]
    message = received[4+sig_len:]

    verifier = oqs.Signature(SIG_ALG)
    is_valid = verifier.verify(message, signature, public_key)
    status = "PASSED" if is_valid else "FAILED"

    out_path = os.path.join(SCRIPT_DIR, "received_file.pdf")
    with open(out_path, "wb") as f:
        f.write(message)

    print(f"Received {len(received)} bytes (sig={sig_len}, msg={len(message)})")
    print(f"MD5:  {hashlib.md5(message).hexdigest()}")
    print(f"PQC Verification: {status} ({SIG_ALG})")
    print(f"Saved to: {out_path}")
    print()
