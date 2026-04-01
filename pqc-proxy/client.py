#!/usr/bin/env python3
"""
PQC Client

This client sends signed requests to the PQC Gateway.
It uses Dilithium (ML-DSA-65) to sign each request, ensuring
post-quantum secure authentication.

Flow:
    1. Build request (method, path, body)
    2. Add timestamp and nonce
    3. Sign with Dilithium private key
    4. Send to PQC Gateway
    5. Receive response (from ETSI via Gateway)

Usage:
    python client.py status              # Get key status
    python client.py get-key             # Get one encryption key
    python client.py get-key --number 3  # Get multiple keys
"""

import json
import hashlib
import urllib.request
import urllib.error
import uuid
import argparse
import os
import sys
from datetime import datetime, timezone

# =============================================================================
# Auto-save: tee all output to log file
# =============================================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "client_log.txt")

class Tee:
    """Write to both stdout and a log file."""
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

# Import liboqs for PQC signing
try:
    import oqs
except ImportError:
    print("ERROR: liboqs-python not installed")
    print("Run: pip install liboqs-python")
    exit(1)

# =============================================================================
# Configuration
# =============================================================================

GATEWAY_URL = "http://192.168.10.200:8080/verify"  # PQC Gateway on QMS

ALGORITHM = "ML-DSA-65"  # Must match keygen.py and gateway.py

PRIVATE_KEY_PATH = "keys/private.key"  # For signing requests

DEFAULT_SAE_ID = "192.168.10.116"  # Bob SAE (slave KME)

# =============================================================================
# Load Private Key
# =============================================================================

def load_private_key() -> bytes:
    """Load the private key for signing"""
    if not os.path.exists(PRIVATE_KEY_PATH):
        print(f"ERROR: Private key not found at {PRIVATE_KEY_PATH}")
        print("Run keygen.py first to generate keys")
        exit(1)

    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key = f.read()

    print(f"[*] Loaded private key: {len(private_key)} bytes")
    return private_key


# =============================================================================
# Sign Message
# =============================================================================

def sign_message(message: bytes, private_key: bytes) -> bytes:
    """
    Sign a message using Dilithium.

    Args:
        message: The message to sign (typically a hash)
        private_key: The Dilithium private key

    Returns:
        The signature bytes
    """
    signer = oqs.Signature(ALGORITHM, private_key)
    signature = signer.sign(message)
    return signature


# =============================================================================
# Build and Sign Request
# =============================================================================

def build_signed_request(method: str, path: str, body: dict, private_key: bytes) -> dict:
    """
    Build a signed request for the PQC Gateway.

    The request includes:
    - method: HTTP method (GET/POST)
    - path: API path
    - body: Request body (for POST)
    - timestamp: Current time in ISO format
    - nonce: Unique random string
    - signature: Dilithium signature of all above fields

    Args:
        method: HTTP method
        path: API path (e.g., /api/v1/keys/app1/status)
        body: Request body dict (can be None for GET)
        private_key: Dilithium private key for signing

    Returns:
        Complete signed request dict
    """
    # 1. Generate timestamp (ISO 8601 format with UTC)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # 2. Generate unique nonce
    nonce = str(uuid.uuid4())

    # 3. Build the message to sign
    # Format: method|path|body_json|timestamp|nonce
    body_str = json.dumps(body or {}, sort_keys=True)
    message = f"{method}|{path}|{body_str}|{timestamp}|{nonce}"

    print(f"[*] Message to sign:")
    print(f"    Method:    {method}")
    print(f"    Path:      {path}")
    print(f"    Body:      {body_str}")
    print(f"    Timestamp: {timestamp}")
    print(f"    Nonce:     {nonce[:8]}...")

    # 4. Hash the message
    message_hash = hashlib.sha256(message.encode()).digest()
    print(f"[*] Message hash: {message_hash.hex()[:32]}...")

    # 5. Sign the hash
    import time
    start = time.time()
    signature = sign_message(message_hash, private_key)
    sign_time = (time.time() - start) * 1000
    print(f"[*] Signature: {signature.hex()[:32]}... ({len(signature)} bytes)")
    print(f"[*] Signing time: {sign_time:.2f} ms")

    # 6. Build complete request
    request = {
        "method": method,
        "path": path,
        "body": body,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": signature.hex()  # Convert to hex string for JSON
    }

    return request


# =============================================================================
# Send Request to Gateway
# =============================================================================

def send_to_gateway(signed_request: dict) -> tuple[int, dict]:
    """
    Send a signed request to the PQC Gateway.

    Args:
        signed_request: The complete signed request dict

    Returns:
        (status_code, response_data)
    """
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


# =============================================================================
# API Functions
# =============================================================================

def get_status(sae_id: str, private_key: bytes) -> dict:
    """
    Get key status from QKD system.

    ETSI 014: GET /api/v1/keys/{slave_SAE_ID}/status
    """
    path = f"/api/v1/keys/{sae_id}/status"
    signed_request = build_signed_request("GET", path, None, private_key)
    status_code, response = send_to_gateway(signed_request)
    return {"status_code": status_code, "response": response}


def get_encryption_keys(sae_id: str, number: int, size: int, private_key: bytes) -> dict:
    """
    Get encryption keys from QKD system.

    ETSI 014: POST /api/v1/keys/{slave_SAE_ID}/enc_keys
    Body: {"number": N, "size": S}
    """
    path = f"/api/v1/keys/{sae_id}/enc_keys"
    body = {"number": number, "size": size}
    signed_request = build_signed_request("POST", path, body, private_key)
    status_code, response = send_to_gateway(signed_request)
    return {"status_code": status_code, "response": response}


def get_decryption_keys(sae_id: str, key_ids: list, private_key: bytes) -> dict:
    """
    Get decryption keys by ID from QKD system.

    ETSI 014: POST /api/v1/keys/{slave_SAE_ID}/dec_keys
    Body: {"key_IDs": [{"key_ID": "..."}, ...]}
    """
    path = f"/api/v1/keys/{sae_id}/dec_keys"
    body = {"key_IDs": [{"key_ID": kid} for kid in key_ids]}
    signed_request = build_signed_request("POST", path, body, private_key)
    status_code, response = send_to_gateway(signed_request)
    return {"status_code": status_code, "response": response}


# =============================================================================
# Pretty Print Response
# =============================================================================

def print_response(result: dict):
    """Pretty print the response"""
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


# =============================================================================
# Main
# =============================================================================

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

    # Header
    print("=" * 60)
    print("PQC Client")
    print("=" * 60)
    print(f"Gateway:   {GATEWAY_URL}")
    print(f"Algorithm: {ALGORITHM}")
    print(f"SAE ID:    {args.sae_id}")
    print("=" * 60)

    # Load private key
    private_key = load_private_key()
    print()

    # Execute command
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

    # Print response
    print_response(result)


if __name__ == "__main__":
    main()
