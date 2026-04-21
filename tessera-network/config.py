#!/usr/bin/env python3
"""Shared configuration and cryptographic utilities for Tessera VCR agents.

Handles keypair generation/storage and Ed25519 signing/verification.

Requirements: pip install cryptography
"""

import hashlib
import json
import os
import sys

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("Missing dependency. Run:\n  pip install cryptography")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Default log server URLs
# ---------------------------------------------------------------------------
LOG_SERVERS = [
    "https://log1.tesseravcr.org",
    "https://log2.tesseravcr.org",
    "https://log3.tesseravcr.org",
]

# ---------------------------------------------------------------------------
# Keypair storage path
# ---------------------------------------------------------------------------
TESSERA_DIR = os.path.expanduser("~/.tessera")
KEY_PATH = os.path.join(TESSERA_DIR, "key.json")

# ---------------------------------------------------------------------------
# Provider defaults
# ---------------------------------------------------------------------------
DEFAULT_PORT = 8900
ANNOUNCE_INTERVAL = 1800  # 30 minutes


# ---------------------------------------------------------------------------
# Cryptographic helpers
# ---------------------------------------------------------------------------

def load_or_create_keypair():
    """Load keypair from ~/.tessera/key.json or generate a new Ed25519 pair.

    Returns:
        (private_key, public_key, pubkey_hex)
    """
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "r") as f:
            data = json.load(f)
        priv_bytes = bytes.fromhex(data["private_key_hex"])
        private_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
        public_key = private_key.public_key()
        pubkey_hex = public_key.public_bytes_raw().hex()
        return private_key, public_key, pubkey_hex

    # Generate new keypair
    os.makedirs(TESSERA_DIR, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Ed25519 private key raw bytes (32 bytes seed)
    priv_bytes = private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    pub_bytes = public_key.public_bytes_raw()
    pubkey_hex = pub_bytes.hex()

    data = {
        "private_key_hex": priv_bytes.hex(),
        "public_key_hex": pubkey_hex,
    }
    with open(KEY_PATH, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(KEY_PATH, 0o600)

    return private_key, public_key, pubkey_hex


def sign_bytes(private_key, data: bytes) -> str:
    """Sign data with Ed25519 private key.

    Args:
        private_key: Ed25519PrivateKey instance
        data: bytes to sign

    Returns:
        Hex-encoded signature string
    """
    signature = private_key.sign(data)
    return signature.hex()


def verify_signature(pubkey_bytes: bytes, signature_bytes: bytes, message: bytes) -> bool:
    """Verify an Ed25519 signature.

    Args:
        pubkey_bytes: 32-byte raw public key
        signature_bytes: 64-byte signature
        message: original message bytes

    Returns:
        True if valid, False otherwise
    """
    try:
        public_key = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
        public_key.verify(signature_bytes, message)
        return True
    except (InvalidSignature, Exception):
        return False


if __name__ == "__main__":
    print("Tessera VCR Configuration")
    print("=========================")
    print(f"  Config dir:  {TESSERA_DIR}")
    print(f"  Key path:    {KEY_PATH}")
    print(f"  Log servers: {LOG_SERVERS}")
    print()
    private_key, public_key, pubkey_hex = load_or_create_keypair()
    print(f"  Your pubkey: {pubkey_hex}")
    print()
    # Quick self-test
    msg = b"test message"
    sig_hex = sign_bytes(private_key, msg)
    sig_bytes = bytes.fromhex(sig_hex)
    pub_bytes = public_key.public_bytes_raw()
    valid = verify_signature(pub_bytes, sig_bytes, msg)
    print(f"  Self-test sign/verify: {'PASS' if valid else 'FAIL'}")
