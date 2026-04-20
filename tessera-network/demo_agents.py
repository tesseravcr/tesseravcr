#!/usr/bin/env python3
"""Demo agents that generate real VCR activity on the live network.

3 agents with different specialties create receipts, build provenance chains,
and transfer ownership. Runs continuously, generating a new transaction
every 30-60 seconds.

Usage:
    python3 demo_agents.py --once              # single round
    python3 demo_agents.py --rounds=20         # 20 rounds then exit
    python3 demo_agents.py                     # run forever
"""

import hashlib
import json
import os
import random
import struct
import sys
import time

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

LOG_URLS = [
    os.environ.get("LOG_URL", "https://log1.tesseravcr.org"),
    "https://log2.tesseravcr.org",
    "https://log3.tesseravcr.org",
]

TASKS = [
    {"model": "legal-risk-v2", "desc": "Legal clause risk analysis", "price_range": (800, 3500)},
    {"model": "summarise-v3", "desc": "Executive summary generation", "price_range": (400, 1500)},
    {"model": "code-review-v1", "desc": "Code review and vulnerability scan", "price_range": (600, 2000)},
    {"model": "translate-v2", "desc": "Technical document translation", "price_range": (300, 1200)},
    {"model": "sentiment-v1", "desc": "Market sentiment analysis", "price_range": (500, 1800)},
    {"model": "med-triage-v1", "desc": "Medical symptom triage", "price_range": (1000, 5000)},
    {"model": "fin-forecast-v1", "desc": "Financial trend forecasting", "price_range": (700, 3000)},
    {"model": "image-classify-v2", "desc": "Image classification and labeling", "price_range": (200, 800)},
]

RELATIONSHIPS = ["input", "reference", "aggregation"]


class Agent:
    def __init__(self, name):
        self.name = name
        self.key = Ed25519PrivateKey.generate()
        self.pub = self.key.public_key().public_bytes_raw()
        self.receipts = []

    def pub_hex(self):
        return self.pub.hex()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def encode_field(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def build_receipt_canonical(
    model_id, input_hash, output_hash, proving_backend, timestamp,
    parent_receipts, provenance_depth, provider, original_price,
    currency, royalty_terms, signature_scheme, extensions
):
    out = b""
    out += encode_field(struct.pack(">H", 1))  # schema_version
    out += encode_field(model_id)
    out += encode_field(b"\x00" * 32)  # verification_key_id
    out += encode_field(input_hash)
    out += encode_field(output_hash)
    out += encode_field(b"")  # proof (empty for demo)
    out += encode_field(b"")  # public_inputs
    out += encode_field(proving_backend.encode())
    out += encode_field(struct.pack(">Q", timestamp))
    # parent_receipts list
    out += struct.pack(">I", len(parent_receipts))
    for p in parent_receipts:
        out += encode_field(p["receipt_id"])
        out += encode_field(p["receipt_hash"])
        out += encode_field(p["relationship"].encode())
    out += encode_field(struct.pack(">H", provenance_depth))
    out += encode_field(provider)
    out += encode_field(struct.pack(">Q", original_price))
    out += encode_field(currency.encode())
    # royalty_terms (no outer wrapper)
    out += encode_field(struct.pack(">H", royalty_terms[0]))
    out += encode_field(struct.pack(">H", royalty_terms[1]))
    out += encode_field(struct.pack(">?", royalty_terms[2]))
    out += encode_field(signature_scheme.encode())
    # extensions
    out += struct.pack(">I", len(extensions))
    return out


def transfer_canonical(receipt_id, from_key, to_key, price, currency, timestamp, royalties):
    out = b""
    out += encode_field(receipt_id)
    out += encode_field(from_key)
    out += encode_field(to_key)
    out += encode_field(struct.pack(">Q", price))
    out += encode_field(currency.encode())
    out += encode_field(struct.pack(">Q", timestamp))
    out += struct.pack(">I", len(royalties))
    for r in royalties:
        out += encode_field(r["recipient"])
        out += encode_field(struct.pack(">Q", r["amount"]))
        out += encode_field(r["receipt_id"])
    return out


def create_receipt(agent, task, parents=None):
    input_data = f"{task['desc']} input {random.randint(1000,9999)} {time.time()}"
    output_data = f"{task['desc']} output {random.randint(1000,9999)} {time.time()}"

    input_hash = sha256(input_data.encode())
    output_hash = sha256(output_data.encode())
    model_id = sha256(task["model"].encode())
    timestamp = int(time.time())
    price = random.randint(*task["price_range"])
    parent_refs = []
    depth = 0

    if parents:
        for p in parents:
            parent_refs.append({
                "receipt_id": p["receipt_id"],
                "receipt_hash": p["receipt_id"],
                "relationship": random.choice(RELATIONSHIPS),
            })
            depth = max(depth, p["depth"] + 1)

    canonical = build_receipt_canonical(
        model_id=model_id,
        input_hash=input_hash,
        output_hash=output_hash,
        proving_backend="tee-nitro-v1",
        timestamp=timestamp,
        parent_receipts=parent_refs,
        provenance_depth=depth,
        provider=agent.pub,
        original_price=price,
        currency="USD-cents",
        royalty_terms=(500, 300, True),
        signature_scheme="ed25519",
        extensions=[],
    )

    receipt_id = sha256(canonical)
    signature = agent.key.sign(sha256(canonical))

    receipt = {
        "receipt_id": receipt_id,
        "model": task["model"],
        "price": price,
        "depth": depth,
        "agent": agent.name,
        "parents": [p["receipt_id"] for p in (parents or [])],
    }
    agent.receipts.append(receipt)
    return receipt


def submit_transfer(from_agent, to_agent, receipt, log_url=None):
    if log_url is None:
        log_url = random.choice(LOG_URLS)

    timestamp = int(time.time())
    price = receipt["price"]

    canonical = transfer_canonical(
        receipt_id=receipt["receipt_id"],
        from_key=from_agent.pub,
        to_key=to_agent.pub,
        price=price,
        currency="USD-cents",
        timestamp=timestamp,
        royalties=[],
    )

    transfer_hash = sha256(canonical)
    signature = from_agent.key.sign(transfer_hash)

    payload = {
        "receipt_id": receipt["receipt_id"].hex(),
        "from_key": from_agent.pub.hex(),
        "to_key": to_agent.pub.hex(),
        "price": price,
        "currency": "USD-cents",
        "timestamp": timestamp,
        "royalties_paid": [],
        "seller_signature": signature.hex(),
        "canonical_bytes": canonical.hex(),
    }

    try:
        resp = requests.post(f"{log_url}/v1/submit", json=payload, timeout=10)
        return resp.status_code, resp.json()
    except Exception as e:
        return 0, {"error": str(e)}


def run_round(agents, round_num):
    print(f"\n{'='*50}")
    print(f"Round {round_num}")
    print(f"{'='*50}")

    # Pick random task
    task = random.choice(TASKS)
    provider = random.choice(agents)
    buyer = random.choice([a for a in agents if a is not provider])

    # Decide if this builds on existing work
    parents = None
    available_parents = [r for a in agents for r in a.receipts]
    if available_parents and random.random() > 0.4:
        num_parents = random.randint(1, min(3, len(available_parents)))
        parents = random.sample(available_parents, num_parents)

    # Create receipt
    receipt = create_receipt(provider, task, parents)
    print(f"  {provider.name} computed: {task['desc']}")
    print(f"  receipt_id: {receipt['receipt_id'].hex()[:16]}...")
    print(f"  price: ${receipt['price']/100:.2f}")
    print(f"  depth: {receipt['depth']}")
    if parents:
        print(f"  parents: {len(parents)} receipts")

    # Submit transfer
    log_url = random.choice(LOG_URLS)
    status, data = submit_transfer(provider, buyer, receipt, log_url)

    if status == 200:
        witnesses = len(data.get("checkpoint", {}).get("witnesses", []))
        print(f"  -> transferred to {buyer.name}")
        print(f"  -> log: {log_url.split('//')[1]}, index: {data.get('index')}")
        print(f"  -> witnesses: {witnesses}")
    else:
        print(f"  -> FAILED ({status}): {data.get('error', 'unknown')}")

    # Occasionally do a resale
    if status == 200 and random.random() > 0.6:
        resale_buyer = random.choice([a for a in agents if a is not buyer])
        receipt["price"] = int(receipt["price"] * random.uniform(0.8, 1.5))
        status2, data2 = submit_transfer(buyer, resale_buyer, receipt, log_url)
        if status2 == 200:
            print(f"  -> resold to {resale_buyer.name} for ${receipt['price']/100:.2f}")
            print(f"     witnesses: {len(data2.get('checkpoint', {}).get('witnesses', []))}")
        else:
            print(f"  -> resale failed ({status2})")

    return status == 200


def main():
    print("Tessera VCR Demo Agents")
    print("=======================")
    print(f"Log servers: {', '.join(LOG_URLS)}")

    agents = [Agent("Alpha"), Agent("Beta"), Agent("Gamma")]
    for a in agents:
        print(f"  {a.name}: {a.pub_hex()[:16]}...")

    max_rounds = 1 if "--once" in sys.argv else None
    for arg in sys.argv[1:]:
        if arg.startswith("--rounds="):
            max_rounds = int(arg.split("=")[1])

    round_num = 0
    while max_rounds is None or round_num < max_rounds:
        round_num += 1
        try:
            run_round(agents, round_num)
        except Exception as e:
            print(f"  ERROR: {e}")

        if max_rounds and round_num >= max_rounds:
            break

        delay = random.randint(3, 8)
        print(f"\n  Next round in {delay}s...")
        time.sleep(delay)

    print(f"\nDone. {round_num} rounds completed.")


if __name__ == "__main__":
    main()
