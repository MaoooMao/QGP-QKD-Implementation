#!/usr/bin/env python3

import json
import hashlib
import urllib.request
import urllib.error
import uuid
import argparse
import os
import sys
from datetime import datetime, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "client_log.txt")

class Tee:
    
    def __init__(self, log_path):
        self.terminal = sys.stdout
        self.log = open(log_path, "a", encoding="utf-8")
        self.log.write(f"\n{'='*60}\n")
        self.log.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] New run: {' '.join(sys.argv)}\n")
        self.log.write(f"{'='*60}\n")
    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)
        self.log.flush()
    def flush(self):
        self.terminal.flush()
        self.log.flush()

sys.stdout = Tee(LOG_FILE)
sys.stderr = Tee(LOG_FILE)

try:
    import oqs
except ImportError:
    print("ERROR: liboqs-python not installed")
    print("Run: pip install liboqs-python")
    exit(1)

GATEWAY_URL = "http://192.168.10.200:8080/verify"

ALGORITHM = "ML-DSA-65"

PRIVATE_KEY_PATH = "keys/private.key"

DEFAULT_SAE_ID = "192.168.10.116"

def load_private_key() -> bytes:
    
    if not os.path.exists(PRIVATE_KEY_PATH):
        print(f"ERROR: Private key not found at {PRIVATE_KEY_PATH}")
        print("Run keygen.py first to generate keys")
        exit(1)

    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key = f.read()

    print(f"[*] Loaded private key: {len(private_key)} bytes")
    return private_key

def sign_message(message: bytes, private_key: bytes) -> bytes:
    
    signer = oqs.Signature(ALGORITHM, private_key)
    signature = signer.sign(message)
    return signature

def build_signed_request(method: str, path: str, body: dict, private_key: bytes) -> dict:
    
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    nonce = str(uuid.uuid4())

    body_str = json.dumps(body or {}, sort_keys=True)
    message = f"{method}|{path}|{body_str}|{timestamp}|{nonce}"

    print(f"[*] Message to sign:")
    print(f"    Method:    {method}")
    print(f"    Path:      {path}")
    print(f"    Body:      {body_str}")
    print(f"    Timestamp: {timestamp}")
    print(f"    Nonce:     {nonce[:8]}...")

    message_hash = hashlib.sha256(message.encode()).digest()
    print(f"[*] Message hash: {message_hash.hex()[:32]}...")

    import time
    start = time.time()
    signature = sign_message(message_hash, private_key)
    sign_time = (time.time() - start) * 1000
    print(f"[*] Signature: {signature.hex()[:32]}... ({len(signature)} bytes)")
    print(f"[*] Signing time: {sign_time:.2f} ms")

    request = {
        "method": method,
        "path": path,
        "body": body,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": signature.hex()
    }

    return request

def send_to_gateway(signed_request: dict) -> tuple[int, dict]:
    
    print(f"\n[*] Sending to Gateway: {GATEWAY_URL}")

    try:
        data = json.dumps(signed_request).encode()
        req = urllib.request.Request(
            GATEWAY_URL,
            data=data,
            method="POST",
            headers={"Content-Type": "application/json"}
        )

        import time
        start = time.time()
        with urllib.request.urlopen(req, timeout=30) as response:
            response_data = json.loads(response.read().decode())
            elapsed = (time.time() - start) * 1000
            print(f"[*] Response received in {elapsed:.2f} ms")
            return response.status, response_data

    except urllib.error.HTTPError as e:
        error_body = e.read().decode() if e.fp else "{}"
        try:
            error_data = json.loads(error_body)
        except:
            error_data = {"error": str(e), "raw": error_body}
        return e.code, error_data

    except urllib.error.URLError as e:
        return 0, {"error": f"Gateway unreachable: {e.reason}"}

    except Exception as e:
        return 0, {"error": f"Request failed: {str(e)}"}

def get_status(sae_id: str, private_key: bytes) -> dict:
    
    path = f"/api/v1/keys/{sae_id}/status"
    signed_request = build_signed_request("GET", path, None, private_key)
    status_code, response = send_to_gateway(signed_request)
    return {"status_code": status_code, "response": response}

def get_encryption_keys(sae_id: str, number: int, size: int, private_key: bytes) -> dict:
    
    path = f"/api/v1/keys/{sae_id}/enc_keys"
    body = {"number": number, "size": size}
    signed_request = build_signed_request("POST", path, body, private_key)
    status_code, response = send_to_gateway(signed_request)
    return {"status_code": status_code, "response": response}

def get_decryption_keys(sae_id: str, key_ids: list, private_key: bytes) -> dict:
    
    path = f"/api/v1/keys/{sae_id}/dec_keys"
    body = {"key_IDs": [{"key_ID": kid} for kid in key_ids]}
    signed_request = build_signed_request("POST", path, body, private_key)
    status_code, response = send_to_gateway(signed_request)
    return {"status_code": status_code, "response": response}

def print_response(result: dict):
    
    print("\n" + "=" * 60)
    print("RESPONSE")
    print("=" * 60)

    status_code = result["status_code"]
    response = result["response"]

    if status_code == 200:
        print(f"Status: {status_code} OK")
    elif status_code == 401:
        print(f"Status: {status_code} UNAUTHORIZED (signature rejected)")
    elif status_code == 0:
        print(f"Status: CONNECTION ERROR")
    else:
        print(f"Status: {status_code}")

    print()
    print(json.dumps(response, indent=2))
    print("=" * 60)

def main():
    parser = argparse.ArgumentParser(
        description="PQC Client - Send signed requests to QKD via PQC Gateway"
    )

    parser.add_argument(
        "command",
        choices=["status", "get-key", "get-dec-key"],
        help="Command to execute"
    )

    parser.add_argument(
        "--sae-id",
        default=DEFAULT_SAE_ID,
        help=f"Application ID (default: {DEFAULT_SAE_ID})"
    )

    parser.add_argument(
        "--number", "-n",
        type=int,
        default=1,
        help="Number of keys to request (default: 1)"
    )

    parser.add_argument(
        "--size", "-s",
        type=int,
        default=256,
        choices=[64, 128, 256, 512, 1024],
        help="Key size in bits (default: 256)"
    )

    parser.add_argument(
        "--key-id",
        action="append",
        help="Key ID for dec_keys (can specify multiple)"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("PQC Client")
    print("=" * 60)
    print(f"Gateway:   {GATEWAY_URL}")
    print(f"Algorithm: {ALGORITHM}")
    print(f"SAE ID:    {args.sae_id}")
    print("=" * 60)

    private_key = load_private_key()
    print()

    if args.command == "status":
        print("[>] Requesting key status...")
        result = get_status(args.sae_id, private_key)

    elif args.command == "get-key":
        print(f"[>] Requesting {args.number} encryption key(s), size={args.size} bits...")
        result = get_encryption_keys(args.sae_id, args.number, args.size, private_key)

    elif args.command == "get-dec-key":
        if not args.key_id:
            print("ERROR: --key-id required for get-dec-key command")
            exit(1)
        print(f"[>] Requesting decryption key(s) for {len(args.key_id)} ID(s)...")
        result = get_decryption_keys(args.sae_id, args.key_id, private_key)

    print_response(result)

if __name__ == "__main__":
    main()
