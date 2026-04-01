#!/usr/bin/env python3
"""
PQC Gateway Server

This gateway sits between clients and the ETSI QKD API.
It verifies Dilithium (ML-DSA-65) signatures on incoming requests
before forwarding them to the backend ETSI server.

Flow:
    Client --> [PQC Gateway] --> ETSI API
           signed request    verified & forwarded

The gateway:
1. Receives requests with PQC signatures
2. Verifies the signature using the client's public key
3. If valid, forwards the original request to ETSI API
4. Returns the ETSI response to the client
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import hashlib
import urllib.request
import urllib.error
import ssl
import time
import os
import sys
from datetime import datetime

# =============================================================================
# Auto-save: tee all output to log file
# =============================================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "gateway_log.txt")

class Tee:
    """Write to both stdout and a log file."""
    def __init__(self, log_path):
        self.terminal = sys.stdout
        self.log = open(log_path, "a", encoding="utf-8")
        self.log.write(f"\n{'='*60}\n")
        self.log.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Gateway started\n")
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

# Import liboqs for PQC verification
try:
    import oqs
except ImportError:
    print("ERROR: liboqs-python not installed")
    print("Run: pip install liboqs-python")
    exit(1)

# =============================================================================
# Configuration
# =============================================================================

GATEWAY_HOST = "0.0.0.0"
GATEWAY_PORT = 8080          # Gateway listens here

# Backend mode: "mock" or "real"
# Set to "real" to connect to actual ETSI QKD API
BACKEND_MODE = "real"

# Mock ETSI backend (for testing without QKD)
MOCK_ETSI_BACKEND = "http://127.0.0.1:8443"

# Real ETSI backend (QKD system)
REAL_ETSI_BACKEND = "https://192.168.10.101:443"
ETSI_CERT = "ETSIA.pem"           # Client certificate
ETSI_KEY = "ETSIA-key.pem"        # Client private key
ETSI_CA = "ChrisCA.pem"           # CA certificate

ALGORITHM = "ML-DSA-65"      # Dilithium3, NIST Level 3

PUBLIC_KEY_PATH = "keys/public.key"  # Client's public key for verification

# Replay protection: reject requests older than this (seconds)
MAX_REQUEST_AGE = 60

# Track used nonces to prevent replay attacks
used_nonces = set()

# =============================================================================
# Load Public Key
# =============================================================================

def load_public_key():
    """Load the client's public key for signature verification"""
    if not os.path.exists(PUBLIC_KEY_PATH):
        print(f"ERROR: Public key not found at {PUBLIC_KEY_PATH}")
        print("Run keygen.py first to generate keys")
        exit(1)

    with open(PUBLIC_KEY_PATH, "rb") as f:
        public_key = f.read()

    print(f"Loaded public key: {len(public_key)} bytes")
    return public_key


# =============================================================================
# Signature Verification
# =============================================================================

def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verify a Dilithium signature.

    Args:
        message: The original message that was signed (bytes)
        signature: The signature to verify (bytes)
        public_key: The signer's public key (bytes)

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        verifier = oqs.Signature(ALGORITHM)
        return verifier.verify(message, signature, public_key)
    except Exception as e:
        print(f"Verification error: {e}")
        return False


def verify_request(request_data: dict, public_key: bytes) -> tuple[bool, str]:
    """
    Verify a signed request from the client.

    Expected request format:
    {
        "method": "GET" or "POST",
        "path": "/api/v1/keys/...",
        "body": { ... } or null,
        "timestamp": "2026-02-03T10:00:00Z",
        "nonce": "random-unique-string",
        "signature": "hex-encoded-signature"
    }

    Returns:
        (is_valid, error_message)
    """
    # 1. Check required fields
    required_fields = ["method", "path", "timestamp", "nonce", "signature"]
    for field in required_fields:
        if field not in request_data:
            return False, f"Missing field: {field}"

    # 2. Check timestamp (replay protection)
    try:
        # Parse ISO format timestamp
        timestamp_str = request_data["timestamp"]
        # Simple parsing: "2026-02-03T10:00:00Z"
        from datetime import datetime
        request_time = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        now = datetime.now(request_time.tzinfo)
        age = (now - request_time).total_seconds()

        if age > MAX_REQUEST_AGE:
            return False, f"Request too old: {age:.1f} seconds"
        if age < -5:  # Allow 5 seconds clock skew
            return False, f"Request from future: {age:.1f} seconds"
    except Exception as e:
        return False, f"Invalid timestamp: {e}"

    # 3. Check nonce (prevent replay)
    nonce = request_data["nonce"]
    if nonce in used_nonces:
        return False, "Nonce already used (replay attack?)"
    used_nonces.add(nonce)

    # Clean old nonces periodically (simple implementation)
    if len(used_nonces) > 10000:
        used_nonces.clear()

    # 4. Reconstruct the signed message
    # The client signs: method + path + body + timestamp + nonce
    body_str = json.dumps(request_data.get("body") or {}, sort_keys=True)
    message = f"{request_data['method']}|{request_data['path']}|{body_str}|{timestamp_str}|{nonce}"
    message_hash = hashlib.sha256(message.encode()).digest()

    # 5. Decode and verify signature
    try:
        signature = bytes.fromhex(request_data["signature"])
    except ValueError:
        return False, "Invalid signature format (not hex)"

    if not verify_signature(message_hash, signature, public_key):
        return False, "Signature verification failed"

    return True, "OK"


# =============================================================================
# Forward Request to ETSI Backend
# =============================================================================

def create_ssl_context():
    """Create SSL context with client certificate for real ETSI"""
    ctx = ssl.create_default_context()
    ctx.load_cert_chain(certfile=ETSI_CERT, keyfile=ETSI_KEY)
    ctx.load_verify_locations(cafile=ETSI_CA)
    # Disable hostname verification for internal network
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # Self-signed certs on QKD system
    return ctx


def forward_to_etsi(method: str, path: str, body: dict = None) -> tuple[int, dict]:
    """
    Forward a verified request to the ETSI backend.

    Args:
        method: HTTP method (GET or POST)
        path: API path (e.g., /api/v1/keys/app1/status)
        body: Request body for POST requests

    Returns:
        (status_code, response_data)
    """
    # Select backend based on mode
    if BACKEND_MODE == "real":
        backend_url = REAL_ETSI_BACKEND
        ssl_context = create_ssl_context()
    else:
        backend_url = MOCK_ETSI_BACKEND
        ssl_context = None

    url = f"{backend_url}{path}"

    try:
        if method == "GET":
            req = urllib.request.Request(url, method="GET")
        else:  # POST
            data = json.dumps(body or {}).encode()
            req = urllib.request.Request(
                url,
                data=data,
                method="POST",
                headers={"Content-Type": "application/json"}
            )

        with urllib.request.urlopen(req, timeout=10, context=ssl_context) as response:
            response_data = json.loads(response.read().decode())
            return response.status, response_data

    except urllib.error.HTTPError as e:
        error_body = e.read().decode() if e.fp else "{}"
        try:
            error_data = json.loads(error_body)
        except:
            error_data = {"error": str(e)}
        return e.code, error_data

    except urllib.error.URLError as e:
        return 502, {"error": f"Backend unreachable: {e.reason}"}

    except Exception as e:
        return 500, {"error": f"Forward error: {str(e)}"}


# =============================================================================
# Gateway HTTP Handler
# =============================================================================

class GatewayHandler(BaseHTTPRequestHandler):
    """
    HTTP handler for the PQC Gateway.

    All requests should be POST to /verify with a signed request body.
    """

    public_key = None  # Set after loading

    def _set_headers(self, status_code=200):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

    def _send_json(self, data: dict, status_code=200):
        self._set_headers(status_code)
        self.wfile.write(json.dumps(data, indent=2).encode())

    def do_POST(self):
        """
        Handle POST requests.

        Endpoint: POST /verify
        Body: Signed request from client
        """
        # Only accept /verify endpoint
        if self.path != "/verify":
            self._send_json({"error": "Use POST /verify"}, 404)
            return

        # Read request body
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self._send_json({"error": "Empty request body"}, 400)
            return

        try:
            body = self.rfile.read(content_length)
            request_data = json.loads(body)
        except json.JSONDecodeError as e:
            self._send_json({"error": f"Invalid JSON: {e}"}, 400)
            return

        # Verify signature
        start_time = time.time()
        is_valid, error_msg = verify_request(request_data, self.public_key)
        verify_time = (time.time() - start_time) * 1000

        if not is_valid:
            print(f"[REJECTED] {error_msg}")
            self._send_json({
                "error": "Verification failed",
                "detail": error_msg,
                "verify_time_ms": round(verify_time, 2)
            }, 401)
            return

        print(f"[VERIFIED] {request_data['method']} {request_data['path']} ({verify_time:.2f}ms)")

        # Forward to ETSI backend
        forward_start = time.time()
        status_code, response_data = forward_to_etsi(
            request_data["method"],
            request_data["path"],
            request_data.get("body")
        )
        forward_time = (time.time() - forward_start) * 1000

        print(f"[FORWARD] -> ETSI returned {status_code} ({forward_time:.2f}ms)")

        # Add timing info to response
        response_data["_gateway_info"] = {
            "verify_time_ms": round(verify_time, 2),
            "forward_time_ms": round(forward_time, 2),
            "total_time_ms": round(verify_time + forward_time, 2)
        }

        self._send_json(response_data, status_code)

    def do_GET(self):
        """Health check endpoint"""
        if self.path == "/health":
            self._send_json({
                "status": "ok",
                "algorithm": ALGORITHM,
                "backend": REAL_ETSI_BACKEND
            })
        else:
            self._send_json({"error": "Use POST /verify"}, 404)

    def log_message(self, format, *args):
        """Custom log format"""
        pass  # Suppress default logging, we do our own


# =============================================================================
# Main
# =============================================================================

def main():
    # Load public key
    public_key = load_public_key()
    GatewayHandler.public_key = public_key

    # Start server
    server = HTTPServer((GATEWAY_HOST, GATEWAY_PORT), GatewayHandler)

    # Determine backend URL for display
    if BACKEND_MODE == "real":
        backend_display = f"{REAL_ETSI_BACKEND} (with TLS cert)"
    else:
        backend_display = f"{MOCK_ETSI_BACKEND} (mock)"

    print("=" * 60)
    print("PQC Gateway Server")
    print("=" * 60)
    print(f"Algorithm:      {ALGORITHM}")
    print(f"Gateway:        http://{GATEWAY_HOST}:{GATEWAY_PORT}")
    print(f"Backend Mode:   {BACKEND_MODE}")
    print(f"ETSI Backend:   {backend_display}")
    print(f"Max request age: {MAX_REQUEST_AGE} seconds")
    print()
    print("Endpoint:")
    print(f"  POST http://{GATEWAY_HOST}:{GATEWAY_PORT}/verify")
    print()
    print("Press Ctrl+C to stop")
    print("=" * 60)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
