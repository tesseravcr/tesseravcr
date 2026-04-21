#!/usr/bin/env python3
"""Tessera VCR Consumer Agent / Client Library.

Discovers providers, requests inference, verifies receipts, and handles payments
including royalty cascades for provenance chains.

Usage:
    python consumer.py --prompt "What is 2+2" --model llama3.2:1b
    python consumer.py --discover --model llama3.2:1b
    python consumer.py --verify --receipt-id <hex>

Requirements: pip install requests cryptography
"""

import argparse
import hashlib
import json
import random
import struct
import sys
import time

try:
    import requests
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    print("Missing dependencies. Run:\n  pip install requests cryptography")
    sys.exit(1)

from config import (
    LOG_SERVERS,
    load_or_create_keypair,
    sign_bytes,
    verify_signature,
)
from ledger import record_spending
from royalties import compute_royalties, format_royalties_for_submission


# ---------------------------------------------------------------------------
# Crypto / encoding helpers
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def encode_field(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


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
# Discovery
# ---------------------------------------------------------------------------

def discover(model=None, log_servers=None):
    """Query log servers for available providers.

    Args:
        model: optional model name to filter by
        log_servers: list of log server URLs to query

    Returns:
        List of provider dicts with keys: pubkey, endpoint, models, price_per_1k_tokens
    """
    servers = log_servers or LOG_SERVERS
    params = {}
    if model:
        params["model"] = model

    for url in servers:
        try:
            resp = requests.get(f"{url}/v1/providers", params=params, timeout=10)
            if resp.status_code == 200:
                providers = resp.json()
                if isinstance(providers, list) and len(providers) > 0:
                    return providers
        except Exception:
            continue

    return []


# ---------------------------------------------------------------------------
# Inference request
# ---------------------------------------------------------------------------

def request_inference(provider_endpoint, prompt, model, parent_receipts=None, consumer_pubkey=None):
    """Call a provider's /v1/inference endpoint.

    Args:
        provider_endpoint: base URL of the provider (e.g. http://localhost:8900)
        prompt: the text prompt
        model: model name to use
        parent_receipts: list of parent receipt ID hex strings
        consumer_pubkey: consumer's public key hex (for the receipt's to_key)

    Returns:
        Dict with keys: output, receipt_id, receipt
    """
    payload = {
        "prompt": prompt,
        "model": model,
        "max_tokens": 256,
        "parent_receipts": parent_receipts or [],
    }
    if consumer_pubkey:
        payload["consumer_pubkey"] = consumer_pubkey

    resp = requests.post(
        f"{provider_endpoint}/v1/inference",
        json=payload,
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Receipt verification
# ---------------------------------------------------------------------------

def verify_receipt(receipt):
    """Verify a receipt's signature locally.

    Args:
        receipt: dict with keys: provider (pubkey hex), signature (hex),
                 receipt_id, input_hash, output_hash, etc.

    Returns:
        True if the signature is valid
    """
    provider_pubkey_hex = receipt.get("provider", "")
    signature_hex = receipt.get("signature", "")

    if not provider_pubkey_hex or not signature_hex:
        return False

    try:
        pubkey_bytes = bytes.fromhex(provider_pubkey_hex)
        signature_bytes = bytes.fromhex(signature_hex)

        # The signature is over the sha256 of the transfer canonical bytes
        # We reconstruct what was signed: sha256(transfer_canonical)
        receipt_id = bytes.fromhex(receipt["receipt_id"])
        from_key = bytes.fromhex(receipt["provider"])
        to_key_hex = receipt.get("to_key", receipt["provider"])
        to_key = bytes.fromhex(to_key_hex)
        price = receipt["price"]
        timestamp = receipt.get("transfer_timestamp", receipt.get("timestamp", 0))
        royalties = receipt.get("royalties_paid", [])

        transfer_canonical = build_transfer_canonical(
            receipt_id, from_key, to_key, price, "USD-cents", timestamp, royalties
        )
        transfer_hash = sha256(transfer_canonical)

        return verify_signature(pubkey_bytes, signature_bytes, transfer_hash)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Payment
# ---------------------------------------------------------------------------

def pay(receipt, provider_pubkey_hex, private_key, consumer_pubkey_hex, parent_receipts=None, log_servers=None):
    """Submit a transfer record to the log server (consumer pays provider).

    Args:
        receipt: the receipt dict from inference
        provider_pubkey_hex: provider's public key hex
        private_key: consumer's Ed25519 private key
        consumer_pubkey_hex: consumer's public key hex
        parent_receipts: list of parent receipt ID hex strings for royalty computation
        log_servers: list of log server URLs

    Returns:
        (status_code, response_dict)
    """
    servers = log_servers or LOG_SERVERS
    receipt_id = bytes.fromhex(receipt["receipt_id"])
    from_key = bytes.fromhex(consumer_pubkey_hex)
    to_key = bytes.fromhex(provider_pubkey_hex)
    price = receipt["price"]
    timestamp = int(time.time())

    # Compute royalties if parent receipts exist
    royalties_list = []
    parent_receipts_payload = []
    if parent_receipts:
        for pr in parent_receipts:
            parent_receipts_payload.append({
                "parent_receipt_id": pr,
                "relationship": "input",
            })
        royalties_list = compute_royalties(parent_receipts_payload, price, servers)

    formatted_royalties = format_royalties_for_submission(royalties_list)

    # Build canonical transfer
    transfer_canonical = build_transfer_canonical(
        receipt_id, from_key, to_key, price, "USD-cents", timestamp, formatted_royalties
    )
    transfer_hash = sha256(transfer_canonical)
    signature = sign_bytes(private_key, transfer_hash)

    payload = {
        "receipt_id": receipt["receipt_id"],
        "from_key": consumer_pubkey_hex,
        "to_key": provider_pubkey_hex,
        "price": price,
        "currency": "USD-cents",
        "timestamp": timestamp,
        "royalties_paid": formatted_royalties,
        "seller_signature": signature,
        "canonical_bytes": transfer_canonical.hex(),
        "parent_receipts": parent_receipts_payload,
    }

    # Submit to a log server
    log_url = random.choice(servers)
    try:
        resp = requests.post(f"{log_url}/v1/submit", json=payload, timeout=10)
        result = resp.json()
        if resp.status_code == 200:
            record_spending(provider_pubkey_hex, price, receipt["receipt_id"])
        return resp.status_code, result
    except Exception as e:
        return 0, {"error": str(e)}


# ---------------------------------------------------------------------------
# TesseraClient class
# ---------------------------------------------------------------------------

class TesseraClient:
    """High-level client for interacting with the Tessera VCR network.

    Wraps discovery, inference, verification, and payment with a stored keypair.
    """

    def __init__(self, log_servers=None):
        """Initialize client, loading or creating a keypair."""
        self.private_key, self.public_key, self.pubkey_hex = load_or_create_keypair()
        self.log_servers = log_servers or LOG_SERVERS
        self.receipt_chain = []  # Track receipt IDs for provenance chains

    def discover(self, model=None):
        """Find available providers on the network.

        Args:
            model: optional model name to filter by

        Returns:
            List of provider info dicts
        """
        return discover(model=model, log_servers=self.log_servers)

    def infer(self, provider_endpoint, prompt, model, use_chain=True):
        """Request inference from a provider.

        Args:
            provider_endpoint: provider's base URL
            prompt: the text prompt
            model: model name
            use_chain: if True, pass previous receipt IDs as parent_receipts

        Returns:
            Dict with output, receipt_id, receipt
        """
        parent_receipts = self.receipt_chain if use_chain else []
        result = request_inference(
            provider_endpoint, prompt, model,
            parent_receipts=parent_receipts,
            consumer_pubkey=self.pubkey_hex,
        )

        # Add to chain
        if result.get("receipt_id"):
            self.receipt_chain.append(result["receipt_id"])

        return result

    def verify(self, receipt):
        """Verify a receipt's signature.

        Args:
            receipt: receipt dict

        Returns:
            True if valid
        """
        return verify_receipt(receipt)

    def pay_provider(self, receipt, provider_pubkey_hex):
        """Submit payment transfer for a receipt.

        Args:
            receipt: receipt dict from inference
            provider_pubkey_hex: provider's public key hex

        Returns:
            (status_code, response_dict)
        """
        return pay(
            receipt, provider_pubkey_hex,
            self.private_key, self.pubkey_hex,
            parent_receipts=self.receipt_chain[:-1] if len(self.receipt_chain) > 1 else None,
            log_servers=self.log_servers,
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Tessera VCR Consumer Agent")
    parser.add_argument("--prompt", help="Prompt to send for inference")
    parser.add_argument("--model", default="llama3.2:1b", help="Model to request (default: llama3.2:1b)")
    parser.add_argument("--provider", help="Provider endpoint URL (e.g. http://localhost:8900)")
    parser.add_argument("--discover", action="store_true", help="Discover available providers")
    parser.add_argument("--verify", action="store_true", help="Verify a receipt")
    parser.add_argument("--receipt-id", help="Receipt ID hex for verification")
    parser.add_argument("--log-server", help="Log server URL override")
    parser.add_argument("--parent-receipts", nargs="*", default=[], help="Parent receipt IDs for provenance")
    args = parser.parse_args()

    log_servers = [args.log_server] if args.log_server else LOG_SERVERS

    print()
    print("  Tessera VCR Consumer")
    print("  ====================")

    # Load keypair
    private_key, public_key, pubkey_hex = load_or_create_keypair()
    print(f"  Your pubkey: {pubkey_hex[:16]}...")
    print()

    # Discovery mode
    if args.discover:
        print(f"  Discovering providers for model: {args.model or 'any'}...")
        providers = discover(model=args.model, log_servers=log_servers)
        if not providers:
            print("  No providers found.")
            return
        print(f"  Found {len(providers)} provider(s):")
        for p in providers:
            print(f"    - {p.get('pubkey', '?')[:16]}... @ {p.get('endpoint', '?')}")
            print(f"      models: {p.get('models', [])}, price: {p.get('price_per_1k_tokens', '?')}/1k tokens")
        return

    # Inference mode
    if args.prompt:
        # Find provider endpoint
        provider_endpoint = args.provider
        if not provider_endpoint:
            # Try to discover one
            providers = discover(model=args.model, log_servers=log_servers)
            if providers:
                provider_endpoint = providers[0].get("endpoint")
                print(f"  Auto-discovered provider: {provider_endpoint}")
            else:
                print("  No provider found. Specify --provider URL or ensure a provider is announced.")
                sys.exit(1)

        print(f"  Provider: {provider_endpoint}")
        print(f"  Model:    {args.model}")
        print(f"  Prompt:   {args.prompt[:60]}{'...' if len(args.prompt) > 60 else ''}")
        if args.parent_receipts:
            print(f"  Parents:  {len(args.parent_receipts)} receipt(s)")
        print()
        print("  Requesting inference...")

        try:
            result = request_inference(
                provider_endpoint, args.prompt, args.model,
                parent_receipts=args.parent_receipts,
                consumer_pubkey=pubkey_hex,
            )
        except Exception as e:
            print(f"  ERROR: {e}")
            sys.exit(1)

        output = result.get("output", "")
        receipt_id = result.get("receipt_id", "")
        receipt = result.get("receipt", {})

        print(f"  Output: {output}")
        print()
        print(f"  Receipt ID: {receipt_id[:16]}..." if receipt_id else "  No receipt")
        print(f"  Price: {receipt.get('price', '?')} USD-cents")

        # Verify receipt
        if receipt:
            valid = verify_receipt(receipt)
            print(f"  Signature valid: {valid}")

            # Submit payment transfer
            provider_pub = receipt.get("provider", "")
            if provider_pub:
                print()
                print("  Submitting payment transfer...")
                status, resp = pay(
                    receipt, provider_pub,
                    private_key, pubkey_hex,
                    parent_receipts=args.parent_receipts or None,
                    log_servers=log_servers,
                )
                if status == 200:
                    print(f"  Payment submitted. Log index: {resp.get('index')}")
                else:
                    print(f"  Payment submission: {status} - {resp.get('error', 'unknown')}")

        return

    # Verify mode
    if args.verify and args.receipt_id:
        print(f"  Fetching receipt {args.receipt_id[:16]}...")
        for url in log_servers:
            try:
                resp = requests.get(f"{url}/v1/receipt/{args.receipt_id}", timeout=10)
                if resp.status_code == 200:
                    receipt_data = resp.json()
                    print(f"  Receipt found on {url}")
                    print(f"  From: {receipt_data.get('from_key', '?')[:16]}...")
                    print(f"  To:   {receipt_data.get('to_key', '?')[:16]}...")
                    print(f"  Price: {receipt_data.get('price', '?')} USD-cents")
                    return
            except Exception:
                continue
        print("  Receipt not found on any log server.")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
