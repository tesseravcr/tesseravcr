#!/usr/bin/env python3
"""Tessera VCR Provider Agent.

Wraps Ollama or OpenAI to serve inference requests, create verifiable compute
receipts, and submit transfers to the Tessera log servers.

On startup:
  - Loads or generates an Ed25519 keypair
  - Announces itself to all log servers via POST /v1/announce
  - Starts a Flask HTTP server with /v1/inference and /v1/info endpoints
  - Re-announces every 30 minutes in a background thread

Usage:
    python provider.py --model llama3.2:1b --port 8900           # Ollama mode
    python provider.py --openai --model gpt-4o-mini --port 8900  # OpenAI mode

Requirements: pip install requests cryptography flask
"""

import argparse
import hashlib
import json
import os
import random
import struct
import sys
import threading
import time

try:
    import requests
    from flask import Flask, jsonify, request as flask_request
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    print("Missing dependencies. Run:\n  pip install requests cryptography flask")
    sys.exit(1)

from config import (
    LOG_SERVERS,
    DEFAULT_PORT,
    ANNOUNCE_INTERVAL,
    load_or_create_keypair,
    sign_bytes,
)
from ledger import record_earning
from royalties import compute_royalties, format_royalties_for_submission

# ---------------------------------------------------------------------------
# Globals set at startup
# ---------------------------------------------------------------------------
PRIVATE_KEY = None
PUBLIC_KEY = None
PUBKEY_HEX = None
MODEL = None
PORT = DEFAULT_PORT
USE_OPENAI = False
OPENAI_API_KEY = None
PRICE_PER_1K_TOKENS = 1  # USD-cents per 1000 tokens

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Crypto / encoding helpers (matching join_network.py patterns)
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def encode_field(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def build_receipt_canonical(model_id, input_hash, output_hash, provider_pub, price, timestamp):
    """Build canonical receipt bytes for receipt_id computation."""
    out = b""
    out += encode_field(struct.pack(">H", 1))       # schema_version
    out += encode_field(model_id)                    # model_id
    out += encode_field(b"\x00" * 32)               # verification_key_id
    out += encode_field(input_hash)                  # input_hash
    out += encode_field(output_hash)                 # output_hash
    out += encode_field(b"")                         # proof
    out += encode_field(b"")                         # public_inputs
    out += encode_field(b"tee-nitro-v1")            # proving_backend
    out += encode_field(struct.pack(">Q", timestamp))
    out += struct.pack(">I", 0)                     # parent_receipts count
    out += encode_field(struct.pack(">H", 0))       # provenance_depth
    out += encode_field(provider_pub)                # provider pubkey
    out += encode_field(struct.pack(">Q", price))   # original_price
    out += encode_field(b"USD-cents")               # currency
    out += encode_field(struct.pack(">H", 500))     # provider_royalty_bps
    out += encode_field(struct.pack(">H", 300))     # parent_royalty_bps
    out += encode_field(struct.pack(">?", True))    # cascade
    out += encode_field(b"ed25519")                 # signature_scheme
    out += struct.pack(">I", 0)                     # extensions count
    return out


def build_transfer_canonical(receipt_id, from_key, to_key, price, currency, timestamp, royalties):
    """Build canonical transfer bytes matching the log server's expected format."""
    out = b""
    out += encode_field(receipt_id)
    out += encode_field(from_key)
    out += encode_field(to_key)
    out += encode_field(struct.pack(">Q", price))
    out += encode_field(currency.encode())
    out += encode_field(struct.pack(">Q", timestamp))
    out += struct.pack(">I", len(royalties))
    for r in royalties:
        out += encode_field(bytes.fromhex(r["recipient"]))
        out += encode_field(struct.pack(">Q", r["amount"]))
        out += encode_field(bytes.fromhex(r["receipt_id"]))
    return out


# ---------------------------------------------------------------------------
# Inference backends
# ---------------------------------------------------------------------------

def run_ollama(prompt: str, model: str, max_tokens: int = 256) -> str:
    """Run inference via Ollama local server."""
    resp = requests.post(
        "http://localhost:11434/api/generate",
        json={"model": model, "prompt": prompt, "stream": False},
        timeout=120,
    )
    resp.raise_for_status()
    data = resp.json()
    return data.get("response", "")


def run_openai(prompt: str, model: str, max_tokens: int = 256) -> str:
    """Run inference via OpenAI API."""
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
    }
    resp = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers=headers,
        json=payload,
        timeout=60,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"]


# ---------------------------------------------------------------------------
# Receipt creation and submission
# ---------------------------------------------------------------------------

def create_receipt_and_submit(prompt, output, model, price, parent_receipts=None, consumer_pubkey=None):
    """Create a VCR receipt and submit the transfer to a log server.

    Returns:
        (receipt_id_hex, receipt_dict, submission_response)
    """
    timestamp = int(time.time())
    model_id = sha256(model.encode())
    input_hash = sha256(prompt.encode())
    output_hash = sha256(output.encode())
    provider_pub = PUBLIC_KEY.public_bytes_raw()

    # Build canonical receipt and compute receipt_id
    canonical = build_receipt_canonical(
        model_id, input_hash, output_hash, provider_pub, price, timestamp
    )
    receipt_id = sha256(canonical)
    receipt_id_hex = receipt_id.hex()

    # Determine to_key
    if consumer_pubkey:
        to_key = bytes.fromhex(consumer_pubkey)
    else:
        to_key = provider_pub  # self-transfer if no consumer specified

    # Compute royalties if parent receipts exist
    royalties_list = []
    parent_receipts_payload = []
    if parent_receipts:
        for pr in parent_receipts:
            parent_receipts_payload.append({
                "parent_receipt_id": pr,
                "relationship": "input",
            })
        royalties_list = compute_royalties(parent_receipts_payload, price)

    # Build transfer canonical bytes
    transfer_ts = int(time.time())
    transfer_canonical = build_transfer_canonical(
        receipt_id, provider_pub, to_key, price, "USD-cents", transfer_ts,
        format_royalties_for_submission(royalties_list)
    )
    transfer_hash = sha256(transfer_canonical)
    signature = sign_bytes(PRIVATE_KEY, transfer_hash)

    # Build submission payload
    payload = {
        "receipt_id": receipt_id_hex,
        "from_key": PUBKEY_HEX,
        "to_key": to_key.hex(),
        "price": price,
        "currency": "USD-cents",
        "timestamp": transfer_ts,
        "royalties_paid": format_royalties_for_submission(royalties_list),
        "seller_signature": signature,
        "canonical_bytes": transfer_canonical.hex(),
        "parent_receipts": parent_receipts_payload,
    }

    # Submit to a log server
    log_url = random.choice(LOG_SERVERS)
    submit_resp = None
    try:
        resp = requests.post(f"{log_url}/v1/submit", json=payload, timeout=10)
        submit_resp = resp.json()
    except Exception as e:
        submit_resp = {"error": str(e)}

    # Build receipt object to return
    receipt = {
        "receipt_id": receipt_id_hex,
        "model_id": model_id.hex(),
        "input_hash": input_hash.hex(),
        "output_hash": output_hash.hex(),
        "provider": PUBKEY_HEX,
        "price": price,
        "currency": "USD-cents",
        "timestamp": timestamp,
        "transfer_timestamp": transfer_ts,
        "signature": signature,
        "parent_receipts": parent_receipts or [],
        "royalties_paid": format_royalties_for_submission(royalties_list),
    }

    # Record earning in local ledger
    record_earning(to_key.hex(), price, receipt_id_hex)

    return receipt_id_hex, receipt, submit_resp


# ---------------------------------------------------------------------------
# Announcement
# ---------------------------------------------------------------------------

def announce(model: str, port: int):
    """Announce this provider to all log servers."""
    provider_pub = PUBLIC_KEY.public_bytes_raw()
    timestamp = int(time.time())

    # Build announcement message
    message = json.dumps({
        "pubkey": PUBKEY_HEX,
        "endpoint": f"http://localhost:{port}",
        "models": [model],
        "price_per_1k_tokens": PRICE_PER_1K_TOKENS,
        "timestamp": timestamp,
    }, separators=(",", ":"), sort_keys=True).encode()

    signature = sign_bytes(PRIVATE_KEY, sha256(message))

    payload = {
        "pubkey": PUBKEY_HEX,
        "endpoint": f"http://localhost:{port}",
        "models": [model],
        "price_per_1k_tokens": PRICE_PER_1K_TOKENS,
        "timestamp": timestamp,
        "signature": signature,
    }

    for url in LOG_SERVERS:
        try:
            resp = requests.post(f"{url}/v1/announce", json=payload, timeout=10)
            if resp.status_code == 200:
                print(f"  Announced to {url}")
            else:
                print(f"  Announce failed at {url}: {resp.status_code}")
        except Exception as e:
            print(f"  Announce error at {url}: {e}")


def announce_loop(model: str, port: int):
    """Background thread that re-announces periodically."""
    while True:
        time.sleep(ANNOUNCE_INTERVAL)
        try:
            announce(model, port)
        except Exception as e:
            print(f"  Re-announce error: {e}")


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.route("/v1/inference", methods=["POST"])
def inference():
    """Handle inference requests from consumers."""
    data = flask_request.get_json()
    if not data:
        return jsonify({"error": "missing JSON body"}), 400

    prompt = data.get("prompt", "")
    model = data.get("model", MODEL)
    max_tokens = data.get("max_tokens", 256)
    parent_receipts = data.get("parent_receipts", [])
    consumer_pubkey = data.get("consumer_pubkey")

    if not prompt:
        return jsonify({"error": "prompt is required"}), 400

    # Run inference
    try:
        if USE_OPENAI:
            output = run_openai(prompt, model, max_tokens)
        else:
            output = run_ollama(prompt, model, max_tokens)
    except Exception as e:
        return jsonify({"error": f"inference failed: {e}"}), 500

    # Estimate token count (rough: 1 token per 4 chars)
    token_count = (len(prompt) + len(output)) // 4
    price = max(1, (token_count * PRICE_PER_1K_TOKENS) // 1000)

    # Create receipt and submit transfer
    receipt_id_hex, receipt, submit_resp = create_receipt_and_submit(
        prompt, output, model, price, parent_receipts, consumer_pubkey
    )

    return jsonify({
        "output": output,
        "receipt_id": receipt_id_hex,
        "receipt": receipt,
    })


@app.route("/v1/info", methods=["GET"])
def info():
    """Return provider information."""
    return jsonify({
        "pubkey": PUBKEY_HEX,
        "models": [MODEL],
        "price_per_1k_tokens": PRICE_PER_1K_TOKENS,
    })


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok", "pubkey": PUBKEY_HEX, "model": MODEL})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global PRIVATE_KEY, PUBLIC_KEY, PUBKEY_HEX, MODEL, PORT, USE_OPENAI, OPENAI_API_KEY, PRICE_PER_1K_TOKENS

    parser = argparse.ArgumentParser(description="Tessera VCR Provider Agent")
    parser.add_argument("--model", default="llama3.2:1b", help="Model to serve (default: llama3.2:1b)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port to listen on (default: {DEFAULT_PORT})")
    parser.add_argument("--openai", action="store_true", help="Use OpenAI API instead of Ollama")
    parser.add_argument("--price", type=int, default=1, help="Price per 1k tokens in USD-cents (default: 1)")
    parser.add_argument("--no-announce", action="store_true", help="Skip network announcement")
    args = parser.parse_args()

    MODEL = args.model
    PORT = args.port
    USE_OPENAI = args.openai
    PRICE_PER_1K_TOKENS = args.price

    if USE_OPENAI:
        OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
        if not OPENAI_API_KEY:
            print("ERROR: OPENAI_API_KEY environment variable required for --openai mode")
            sys.exit(1)

    # Load keypair
    print()
    print("  Tessera VCR Provider Agent")
    print("  ==========================")
    PRIVATE_KEY, PUBLIC_KEY, PUBKEY_HEX = load_or_create_keypair()
    print(f"  Pubkey:  {PUBKEY_HEX[:16]}...")
    print(f"  Model:   {MODEL}")
    print(f"  Mode:    {'OpenAI' if USE_OPENAI else 'Ollama'}")
    print(f"  Port:    {PORT}")
    print(f"  Price:   {PRICE_PER_1K_TOKENS} USD-cents/1k tokens")
    print()

    # Announce to network
    if not args.no_announce:
        print("  Announcing to network...")
        announce(MODEL, PORT)
        print()

        # Start re-announce background thread
        t = threading.Thread(target=announce_loop, args=(MODEL, PORT), daemon=True)
        t.start()

    # Start Flask server
    print(f"  Starting server on port {PORT}...")
    print(f"  Endpoints:")
    print(f"    POST /v1/inference")
    print(f"    GET  /v1/info")
    print(f"    GET  /health")
    print()
    app.run(host="0.0.0.0", port=PORT, debug=False)


if __name__ == "__main__":
    main()
