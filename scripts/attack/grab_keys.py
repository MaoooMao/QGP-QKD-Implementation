#!/usr/bin/env python3
"""Grab QKD keys from QNC B enc_keys API.
Run on QMS server: python3 grab_keys.py
Certs expected in same directory as this script (QKDserver/).
Press Ctrl+C to stop and save.
"""
import ssl, json, time, os, signal, sys
from urllib.request import Request, urlopen

CERT_DIR = os.path.dirname(os.path.abspath(__file__))
QNC_B = "https://192.168.10.106:443/api/v1/keys/192.168.10.111/enc_keys"
KEYS_FILE = os.path.join(CERT_DIR, "grabbed_keys.json")

ctx = ssl.create_default_context(cafile=os.path.join(CERT_DIR, "ChrisCA.pem"))
ctx.load_cert_chain(os.path.join(CERT_DIR, "ETSIB.pem"),
                    os.path.join(CERT_DIR, "ETSIB-key.pem"))
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

keys = []

def save_and_exit(*args):
    with open(KEYS_FILE, "w") as f:
        json.dump(keys, f, indent=2)
    print(f"\nSaved {len(keys)} keys to {KEYS_FILE}")
    sys.exit(0)

signal.signal(signal.SIGINT, save_and_exit)

body = json.dumps({"number": 1, "size": 256}).encode()

print(f"Grabbing keys from QNC B...")
print(f"Certs: {CERT_DIR}")
print(f"Press Ctrl+C to stop and save.\n")

while True:
    req = Request(QNC_B, data=body, method='POST',
                  headers={'Content-Type': 'application/json'})
    try:
        resp = urlopen(req, context=ctx, timeout=5)
        data = json.loads(resp.read())
        key = data["keys"][0]
        keys.append({"uuid": key["key_ID"], "key": key["key"],
                      "time": time.strftime('%H:%M:%S')})
        print(f"#{len(keys)} [{keys[-1]['time']}] GOT: {key['key_ID'][:8]}... key={key['key'][:20]}...")
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] Error: {e}")
    time.sleep(0.5)
