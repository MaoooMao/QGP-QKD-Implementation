#!/usr/bin/env python3
"""
QGP Key Generation Script

Generates two keypairs for the Quantum Good Authentication Protocol:
  1. ML-DSA-65 (Dilithium) — Alice signs, Bob verifies
  2. ML-KEM-768 (Kyber)    — Alice encrypts to Bob, Bob decrypts
"""

import oqs
import os
import argparse

LEVELS = {
    1: ("ML-DSA-44", "ML-KEM-512"),
    3: ("ML-DSA-65", "ML-KEM-768"),
    5: ("ML-DSA-87", "ML-KEM-1024"),
}


def generate_keypair(level=3):
    """Generate and save Dilithium + Kyber keypairs"""
    sig_alg, kem_alg = LEVELS[level]
    print(f"Security Level: {level}")
    print(f"Signature: {sig_alg}, KEM: {kem_alg}\n")

    os.makedirs("keys", exist_ok=True)

    # --- Dilithium (signing) ---
    signer = oqs.Signature(sig_alg)
    sig_public = signer.generate_keypair()
    sig_private = signer.export_secret_key()

    with open("keys/public.key", "wb") as f:
        f.write(sig_public)
    with open("keys/private.key", "wb") as f:
        f.write(sig_private)

    print(f"=== Dilithium ({sig_alg}) ===")
    print(f"  Public key:  {len(sig_public)} bytes -> keys/public.key")
    print(f"  Private key: {len(sig_private)} bytes -> keys/private.key")

    # --- Kyber (encryption) ---
    kem = oqs.KeyEncapsulation(kem_alg)
    kem_public = kem.generate_keypair()
    kem_private = kem.export_secret_key()

    with open("keys/kyber_public.key", "wb") as f:
        f.write(kem_public)
    with open("keys/kyber_private.key", "wb") as f:
        f.write(kem_private)

    print(f"\n=== Kyber ({kem_alg}) ===")
    print(f"  Public key:  {len(kem_public)} bytes -> keys/kyber_public.key")
    print(f"  Private key: {len(kem_private)} bytes -> keys/kyber_private.key")

    print("\nKey distribution:")
    print("  Alice needs: keys/private.key + keys/kyber_public.key")
    print("  Bob needs:   keys/public.key  + keys/kyber_private.key")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate QGP keypairs")
    parser.add_argument("--level", "-l", type=int, choices=[1, 3, 5], default=3,
                        help="NIST security level: 1, 3, or 5 (default: 3)")
    args = parser.parse_args()
    generate_keypair(args.level)
