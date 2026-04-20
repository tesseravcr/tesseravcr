#!/usr/bin/env python3
"""Join the Tessera VCR network and submit a verified compute receipt.

Generates a keypair, creates a receipt, and submits a transfer to the
live network. Your transfer appears on the dashboard within seconds.

Requirements: pip install requests cryptography
Usage:        python3 join_network.py
"""

import hashlib
import struct
import sys
import time

try:
    import requests
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    print("Missing dependencies. Run:\n  pip install requests cryptography")
    sys.exit(1)

LOG_URLS = [
    "https://log1.tesseravcr.org",
    "https://log2.tesseravcr.org",
    "https://log3.tesseravcr.org",
]

TASKS = [
    ("code-review-v1", "Code review and vulnerability scan", 600, 2000),
    ("summarise-v3", "Executive summary generation", 400, 1500),
    ("translate-v2", "Technical document translation", 300, 1200),
    ("sentiment-v1", "Market sentiment analysis", 500, 1800),
]


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def encode_field(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def build_receipt(model_id, input_hash, output_hash, provider_pub, price, timestamp):
    out = b""
    out += encode_field(struct.pack(">H", 1))
    out += encode_field(model_id)
    out += encode_field(b"\x00" * 32)
    out += encode_field(input_hash)
    out += encode_field(output_hash)
    out += encode_field(b"")
    out += encode_field(b"")
    out += encode_field(b"tee-nitro-v1")
    out += encode_field(struct.pack(">Q", timestamp))
    out += struct.pack(">I", 0)
    out += encode_field(struct.pack(">H", 0))
    out += encode_field(provider_pub)
    out += encode_field(struct.pack(">Q", price))
    out += encode_field(b"USD-cents")
    out += encode_field(struct.pack(">H", 500))
    out += encode_field(struct.pack(">H", 300))
    out += encode_field(struct.pack(">?", True))
    out += encode_field(b"ed25519")
    out += struct.pack(">I", 0)
    return out


def build_transfer(receipt_id, from_key, to_key, price, timestamp):
    out = b""
    out += encode_field(receipt_id)
    out += encode_field(from_key)
    out += encode_field(to_key)
    out += encode_field(struct.pack(">Q", price))
    out += encode_field(b"USD-cents")
    out += encode_field(struct.pack(">Q", timestamp))
    out += struct.pack(">I", 0)
    return out


def main():
    import random

    print()
    print("  tessera vcr — join the network")
    print("  ================================")
    print()

    print("  Generating Ed25519 keypair...")
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw()
    buyer_key = Ed25519PrivateKey.generate()
    buyer_pub = buyer_key.public_key().public_bytes_raw()
    print(f"  Your key:  {pub.hex()[:16]}...")
    print(f"  Buyer key: {buyer_pub.hex()[:16]}...")
    print()

    task = random.choice(TASKS)
    model_name, desc, price_lo, price_hi = task
    price = random.randint(price_lo, price_hi)

    print(f"  Task: {desc}")
    print(f"  Model: {model_name}")
    print(f"  Price: ${price/100:.2f}")
    print()

    timestamp = int(time.time())
    input_hash = sha256(f"{desc} input {random.randint(1000,9999)} {time.time()}".encode())
    output_hash = sha256(f"{desc} output {random.randint(1000,9999)} {time.time()}".encode())
    model_id = sha256(model_name.encode())

    canonical = build_receipt(model_id, input_hash, output_hash, pub, price, timestamp)
    receipt_id = sha256(canonical)

    print(f"  Receipt ID: {receipt_id.hex()[:16]}...")

    transfer_ts = int(time.time())
    transfer_canonical = build_transfer(receipt_id, pub, buyer_pub, price, transfer_ts)
    transfer_hash = sha256(transfer_canonical)
    signature = key.sign(transfer_hash)

    payload = {
        "receipt_id": receipt_id.hex(),
        "from_key": pub.hex(),
        "to_key": buyer_pub.hex(),
        "price": price,
        "currency": "USD-cents",
        "timestamp": transfer_ts,
        "royalties_paid": [],
        "seller_signature": signature.hex(),
        "canonical_bytes": transfer_canonical.hex(),
    }

    log_url = random.choice(LOG_URLS)
    print(f"  Submitting to {log_url.split('//')[1]}...")
    print()

    try:
        resp = requests.post(f"{log_url}/v1/submit", json=payload, timeout=10)
        data = resp.json()

        if resp.status_code == 200:
            witnesses = len(data.get("checkpoint", {}).get("witnesses", []))
            print(f"  Submitted to log index {data.get('index')}")
            print(f"  Witnesses: {witnesses}")
            print(f"  Merkle root: {data.get('checkpoint',{}).get('root','—')[:16]}...")
            print()
            print(f"  Your transfer is live on the network.")
            print(f"  View it: https://log1.tesseravcr.org/network.html")
        else:
            print(f"  Failed ({resp.status_code}): {data.get('error', 'unknown')}")
    except Exception as e:
        print(f"  Error: {e}")

    print()


if __name__ == "__main__":
    main()
