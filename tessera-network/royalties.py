#!/usr/bin/env python3
"""Runtime royalty cascade execution for Tessera VCR.

When a consumer submits a transfer that references parent receipts, this module
computes the royalty splits owed to upstream providers in the provenance chain.

Royalty terms (hardcoded for now):
  - provider_royalty: 500 bps (5%) — paid to the original provider of each parent
  - parent_royalty:   300 bps (3%) — cascaded to grandparents if they exist
  - cascade: True — royalties propagate up the chain

Usage:
    python royalties.py --receipt-id <hex>    # compute royalties for a given receipt
"""

import argparse
import hashlib
import random
import sys

try:
    import requests
except ImportError:
    print("Missing dependency. Run:\n  pip install requests")
    sys.exit(1)

from config import LOG_SERVERS

# Hardcoded royalty terms (basis points)
PROVIDER_ROYALTY_BPS = 500  # 5%
PARENT_ROYALTY_BPS = 300    # 3%
CASCADE = True


def fetch_receipt(receipt_id_hex: str, log_servers=None) -> dict:
    """Fetch receipt info from a log server.

    Args:
        receipt_id_hex: hex-encoded receipt ID
        log_servers: list of log server URLs to try

    Returns:
        Receipt data dict, or None if not found
    """
    servers = log_servers or LOG_SERVERS
    for url in servers:
        try:
            resp = requests.get(f"{url}/v1/receipt/{receipt_id_hex}", timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            continue
    return None


def compute_royalties(parent_receipts: list, price: int, log_servers=None) -> list:
    """Compute royalty payments for a set of parent receipts.

    For each parent receipt referenced by the current transfer:
    - The parent's provider gets provider_royalty_bps of the current price
    - If the parent itself has parents (grandparents), they get parent_royalty_bps

    Args:
        parent_receipts: list of dicts with "parent_receipt_id" (hex) and "relationship"
        price: the price of the current transfer (used as base for royalty calculation)
        log_servers: list of log server URLs

    Returns:
        List of royalty payment dicts:
        [{"recipient": pubkey_hex, "amount": int, "receipt_id": parent_receipt_id_hex}]
    """
    if not parent_receipts:
        return []

    royalties = []

    for parent_ref in parent_receipts:
        parent_id = parent_ref.get("parent_receipt_id", "")
        if not parent_id:
            continue

        # Fetch parent receipt details from log server
        parent_data = fetch_receipt(parent_id, log_servers)
        if not parent_data:
            # Cannot compute royalty without parent data; skip
            continue

        # Provider royalty: 5% of current price to the parent's provider
        provider_pubkey = parent_data.get("from_key") or parent_data.get("provider", "")
        if provider_pubkey:
            provider_amount = (price * PROVIDER_ROYALTY_BPS) // 10000
            if provider_amount > 0:
                royalties.append({
                    "recipient": provider_pubkey,
                    "amount": provider_amount,
                    "receipt_id": parent_id,
                })

        # Cascade: if the parent has its own parents, pay 3% to grandparent providers
        if CASCADE:
            grandparent_refs = parent_data.get("parent_receipts", [])
            for gp_ref in grandparent_refs:
                gp_id = gp_ref.get("parent_receipt_id", "")
                if not gp_id:
                    continue
                gp_data = fetch_receipt(gp_id, log_servers)
                if not gp_data:
                    continue
                gp_provider = gp_data.get("from_key") or gp_data.get("provider", "")
                if gp_provider:
                    gp_amount = (price * PARENT_ROYALTY_BPS) // 10000
                    if gp_amount > 0:
                        royalties.append({
                            "recipient": gp_provider,
                            "amount": gp_amount,
                            "receipt_id": gp_id,
                        })

    return royalties


def format_royalties_for_submission(royalties: list) -> list:
    """Format royalty list for the transfer submission payload.

    Converts to the format expected by the log server's /v1/submit endpoint:
    [{"recipient": hex, "amount": int, "receipt_id": hex}]

    Args:
        royalties: list from compute_royalties()

    Returns:
        Formatted list ready for JSON submission
    """
    return [
        {
            "recipient": r["recipient"],
            "amount": r["amount"],
            "receipt_id": r["receipt_id"],
        }
        for r in royalties
    ]


def main():
    parser = argparse.ArgumentParser(description="Tessera VCR Royalty Calculator")
    parser.add_argument("--receipt-id", required=True, help="Receipt ID (hex) to compute royalties for")
    parser.add_argument("--price", type=int, default=1000, help="Price of current transfer (USD-cents)")
    parser.add_argument("--log-server", help="Log server URL to query")
    args = parser.parse_args()

    log_servers = [args.log_server] if args.log_server else LOG_SERVERS

    print("Tessera VCR Royalty Calculator")
    print("==============================")
    print(f"  Receipt ID: {args.receipt_id[:16]}...")
    print(f"  Price: ${args.price/100:.2f}")
    print()

    # Fetch the receipt to find its parents
    receipt_data = fetch_receipt(args.receipt_id, log_servers)
    if not receipt_data:
        print("  ERROR: Could not fetch receipt from any log server.")
        sys.exit(1)

    parent_receipts = receipt_data.get("parent_receipts", [])
    if not parent_receipts:
        print("  No parent receipts found. No royalties owed.")
        return

    print(f"  Found {len(parent_receipts)} parent receipt(s).")
    print()

    royalties = compute_royalties(parent_receipts, args.price, log_servers)

    if not royalties:
        print("  No royalties computed (parent data unavailable).")
        return

    print(f"  Royalties ({len(royalties)} payments):")
    total = 0
    for r in royalties:
        print(f"    -> {r['recipient'][:16]}... : {r['amount']} USD-cents (ref: {r['receipt_id'][:16]}...)")
        total += r["amount"]
    print(f"  Total royalties: {total} USD-cents (${total/100:.2f})")


if __name__ == "__main__":
    main()
