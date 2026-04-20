#!/usr/bin/env python3
"""
Full network test — nodes + log operator + DAG queries.

Spins up 3 compute nodes and 1 log operator. Agents do work,
receipts get submitted to the log, and we query the provenance DAG.
"""

import json
import os
import shutil
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tessera-py"))

import requests

from node import Node
from log_server import app as log_app
from transparency import TransparencyLog


def tag(s):
    return s[:12]


def section(title):
    w = 64
    print(f"\n{'=' * w}")
    print(f"  {title}")
    print(f"{'=' * w}\n")


def main():
    # Clean slate
    data_dir = os.path.join(os.path.dirname(__file__), "data")
    if os.path.exists(data_dir):
        shutil.rmtree(data_dir)
    db_path = os.path.join(os.path.dirname(__file__), "test_log.db")
    if os.path.exists(db_path):
        os.remove(db_path)

    section("TESSERA NETWORK — FULL STACK TEST")
    print("  3 compute nodes + 1 transparency log operator")
    print("  Receipts → provenance DAG → Merkle proofs")

    # ── Start nodes ─────────────────────────────────────────────

    section("1. STARTING NODES")

    alpha = Node("alpha", 9101, ["supply-chain-intel"])
    beta  = Node("beta",  9102, ["biotech-analysis"])
    gamma = Node("gamma", 9103, ["portfolio-strategy"])

    alpha.run_background()
    beta.run_background()
    gamma.run_background()

    print(f"  Alpha  :9101  [{tag(alpha.pubkey.hex())}...]  model: supply-chain-intel")
    print(f"  Beta   :9102  [{tag(beta.pubkey.hex())}...]  model: biotech-analysis")
    print(f"  Gamma  :9103  [{tag(gamma.pubkey.hex())}...]  model: portfolio-strategy")

    # ── Start log operator ──────────────────────────────────────

    section("2. STARTING LOG OPERATOR")

    import log_server
    log_server.log = TransparencyLog(db_path)

    def run_log():
        log_app.run(host="127.0.0.1", port=7101, use_reloader=False)

    t = threading.Thread(target=run_log, daemon=True)
    t.start()

    # Wait for log to be ready
    for _ in range(50):
        try:
            requests.get("http://127.0.0.1:7101/stats", timeout=0.5)
            break
        except Exception:
            time.sleep(0.1)

    stats = requests.get("http://127.0.0.1:7101/stats").json()
    print(f"  Log operator on :7101  (root: {stats['root'][:24]}...)")
    print(f"  Receipts: {stats['receipts']}  DAG edges: {stats['dag_edges']}")

    LOG = "http://127.0.0.1:7101"

    # ── Compute: two root receipts ──────────────────────────────

    section("3. COMPUTE — TWO ROOT RECEIPTS")

    r_alpha = requests.post("http://127.0.0.1:9101/compute", json={
        "input_data": "Analyse supply chain disruption in East Asia",
        "model": "supply-chain-intel",
        "price": 2000,
        "provider_royalty": 1500,
        "parent_royalty": 1000,
    }).json()

    r_beta = requests.post("http://127.0.0.1:9102/compute", json={
        "input_data": "Clinical trial analysis: BioTarget compound X",
        "model": "biotech-analysis",
        "price": 5000,
        "provider_royalty": 1500,
        "parent_royalty": 1000,
    }).json()

    print(f"  Alpha computed → [{tag(r_alpha['receipt_id'])}]  ${r_alpha['receipt']['original_price']/100:.0f}")
    print(f"  Beta  computed → [{tag(r_beta['receipt_id'])}]  ${r_beta['receipt']['original_price']/100:.0f}")

    # ── Submit root receipts to log ─────────────────────────────

    section("4. SUBMIT TO LOG — RECEIPTS ENTER THE MERKLE TREE")

    log_a = requests.post(f"{LOG}/receipt", json={
        "receipt": r_alpha["receipt"],
        "receipt_id": r_alpha["receipt_id"],
    }).json()

    log_b = requests.post(f"{LOG}/receipt", json={
        "receipt": r_beta["receipt"],
        "receipt_id": r_beta["receipt_id"],
    }).json()

    print(f"  Alpha receipt → log  (leaf: {tag(log_a.get('leaf_hash', 'n/a'))}  size: {log_a.get('log_size', '?')})")
    print(f"  Beta  receipt → log  (leaf: {tag(log_b.get('leaf_hash', 'n/a'))}  size: {log_b.get('log_size', '?')})")

    # ── Compute: derivative that references both ────────────────

    section("5. DERIVE — GAMMA BUILDS ON ALPHA + BETA")

    r_gamma = requests.post("http://127.0.0.1:9103/compute", json={
        "input_data": "Due diligence synthesis: BioTarget acquisition",
        "model": "portfolio-strategy",
        "price": 8000,
        "provider_royalty": 1500,
        "parent_royalty": 1000,
        "parents": [
            {
                "receipt_id": r_alpha["receipt_id"],
                "receipt_hash": r_alpha["receipt_id"],
                "relationship": "input",
            },
            {
                "receipt_id": r_beta["receipt_id"],
                "receipt_hash": r_beta["receipt_id"],
                "relationship": "input",
            },
        ],
    }).json()

    print(f"  Gamma computed → [{tag(r_gamma['receipt_id'])}]  ${r_gamma['receipt']['original_price']/100:.0f}")
    print(f"  Parents: Alpha [{tag(r_alpha['receipt_id'])}] + Beta [{tag(r_beta['receipt_id'])}]")
    print()
    print(f"    [{tag(r_alpha['receipt_id'])}] Alpha    $20")
    print(f"           \\")
    print(f"            →  [{tag(r_gamma['receipt_id'])}] Gamma  $80")
    print(f"           /")
    print(f"    [{tag(r_beta['receipt_id'])}] Beta     $50")

    # Submit derivative to log
    log_g = requests.post(f"{LOG}/receipt", json={
        "receipt": r_gamma["receipt"],
        "receipt_id": r_gamma["receipt_id"],
    }).json()

    print(f"\n  Gamma receipt → log  (leaf: {tag(log_g.get('leaf_hash', 'n/a'))}  size: {log_g.get('log_size', '?')})")

    # ── DAG queries ─────────────────────────────────────────────

    section("6. DAG QUERIES — THE PROVENANCE GRAPH IS LIVE")

    # Full DAG for the derivative
    dag = requests.get(f"{LOG}/dag/{r_gamma['receipt_id']}").json()

    print(f"  GET /dag/{tag(r_gamma['receipt_id'])}...")
    print(f"    Parents:     {len(dag['parents'])} — {[tag(p['receipt_id']) for p in dag['parents']]}")
    print(f"    Ancestors:   {len(dag['ancestors'])} — {[tag(a['receipt_id']) for a in dag['ancestors']]}")
    print(f"    Children:    {len(dag['children'])}")
    print(f"    Descendants: {len(dag['descendants'])}")

    # Check Alpha's children
    dag_a = requests.get(f"{LOG}/dag/{r_alpha['receipt_id']}").json()
    print(f"\n  GET /dag/{tag(r_alpha['receipt_id'])}...")
    print(f"    Parents:     {len(dag_a['parents'])} (root receipt)")
    print(f"    Children:    {len(dag_a['children'])} — {[tag(c['receipt_id']) for c in dag_a['children']]}")
    print(f"    Descendants: {len(dag_a['descendants'])}")

    # ── Search ──────────────────────────────────────────────────

    section("7. SEARCH — QUERY BY PROVIDER, MODEL, PRICE")

    results = requests.get(f"{LOG}/search", params={
        "min_price": 3000,
    }).json()

    print(f"  GET /search?min_price=3000")
    print(f"    Found {results['count']} receipts priced >= $30:")
    for r in results["results"]:
        print(f"      [{tag(r['receipt_id'])}]  price=${r['price']/100:.0f}  depth={r['provenance_depth']}")

    # ── Merkle proofs ───────────────────────────────────────────

    section("8. MERKLE PROOFS — CRYPTOGRAPHIC INCLUSION")

    proof = requests.get(f"{LOG}/proof/{r_gamma['receipt_id']}").json()
    root = requests.get(f"{LOG}/root").json()

    print(f"  GET /proof/{tag(r_gamma['receipt_id'])}...")
    print(f"    Index:     {proof.get('index')}")
    print(f"    Leaf:      {tag(proof.get('leaf_hash', 'n/a'))}")
    print(f"    Path len:  {len(proof.get('path', []))} hashes")
    print(f"    Root:      {tag(root['root'])}")
    print(f"    Log size:  {root['size']} entries")

    # Verify proof locally
    from merkle import hash_leaf, verify_proof
    path = [(bytes.fromhex(h), d) for h, d in proof["path"]]
    leaf = bytes.fromhex(proof["leaf_hash"])
    root_hash = bytes.fromhex(root["root"])
    valid = verify_proof(leaf, path, root_hash)
    print(f"\n  Local verification: {'VALID' if valid else 'INVALID'}")

    # ── Transfer with royalty cascade ───────────────────────────

    section("9. TRANSFER — BUYER PURCHASES GAMMA'S DERIVATIVE")

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    buyer_key = Ed25519PrivateKey.generate()
    buyer_pub = buyer_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # Gamma needs Alpha and Beta's receipts locally for royalty resolution
    from protocol.receipt import Receipt
    gamma.store.save_receipt(Receipt.from_json(json.dumps(r_alpha["receipt"])))
    gamma.store.save_receipt(Receipt.from_json(json.dumps(r_beta["receipt"])))

    sale_price = 15000
    xfer = requests.post("http://127.0.0.1:9103/transfer", json={
        "receipt_id": r_gamma["receipt_id"],
        "to_key": buyer_pub.hex(),
        "price": sale_price,
    }).json()

    print(f"  Sale price: ${sale_price/100:.0f}")
    print(f"  Transfer hash: {tag(xfer['transfer_hash'])}")
    print(f"  Signature valid: {xfer['signature_valid']}")
    print()
    print(f"  Royalty cascade:")
    for pk, amount in sorted(xfer["payments"].items(), key=lambda x: -x[1]):
        name = "?"
        for n, node in [("Alpha", alpha), ("Beta", beta), ("Gamma", gamma)]:
            if pk == node.pubkey.hex():
                name = n
        print(f"    {name:>8}: ${amount/100:>7.2f}")
    print(f"    {'Total':>8}: ${xfer['total_distributed']/100:.2f}")

    # ── Ownership check ─────────────────────────────────────────

    section("10. OWNERSHIP — LOG TRACKS THE CHAIN")

    owner = requests.get(f"{LOG}/owner/{r_alpha['receipt_id']}").json()
    print(f"  Alpha receipt owner: {tag(owner.get('owner', 'unknown'))}")

    owner_g = requests.get(f"{LOG}/owner/{r_gamma['receipt_id']}").json()
    print(f"  Gamma receipt owner: {tag(owner_g.get('owner', 'unknown'))}")

    # ── Algorithmic trust ───────────────────────────────────────

    section("11. ALGORITHMIC TRUST — STAKE FROM WORK HISTORY")

    # Update nodes to know about the log
    alpha.log_url = LOG
    beta.log_url = LOG
    gamma.log_url = LOG

    # Query trust for Alpha (has 1 receipt, $20 value)
    trust_alpha_resp = requests.get(f"http://127.0.0.1:9101/trust/{alpha.pubkey.hex()}", params={
        "transaction_value": 5000,
    })
    if trust_alpha_resp.status_code != 200:
        print(f"ERROR: Trust query failed: {trust_alpha_resp.status_code}")
        print(f"Response: {trust_alpha_resp.text}")
    trust_alpha = trust_alpha_resp.json()

    print(f"  Alpha's trust metrics:")
    print(f"    Effective stake:   ${trust_alpha.get('effective_stake', 0)/100:.2f}")
    print(f"    Receipt count:     {trust_alpha.get('receipt_count', 0)}")
    print(f"    Direct value:      ${trust_alpha.get('direct_value', 0)/100:.2f}")
    print(f"    Trust quotient:    {trust_alpha.get('trust_quotient', 0):.3f}")
    print(f"    Recommendation:    {trust_alpha.get('settlement_recommendation', 'N/A')}")

    # Query trust for Gamma (has 1 receipt, $80 value)
    trust_gamma = requests.get(f"http://127.0.0.1:9103/trust/{gamma.pubkey.hex()}", params={
        "transaction_value": 5000,
    }).json()

    print(f"\n  Gamma's trust metrics:")
    print(f"    Effective stake:   ${trust_gamma.get('effective_stake', 0)/100:.2f}")
    print(f"    Receipt count:     {trust_gamma.get('receipt_count', 0)}")
    print(f"    Direct value:      ${trust_gamma.get('direct_value', 0)/100:.2f}")
    print(f"    Trust quotient:    {trust_gamma.get('trust_quotient', 0):.3f}")
    print(f"    Recommendation:    {trust_gamma.get('settlement_recommendation', 'N/A')}")

    print(f"\n  Trust computed from public work history.")
    print(f"  No platform. No human ratings. Just receipts.")

    # ── Vouching ────────────────────────────────────────────────

    section("12. VOUCHING — ESTABLISHED AGENT STAKES FOR NEWCOMER")

    # Create a newcomer with no work history
    delta = Node("delta", 9104, ["risk-analysis"])
    delta.run_background()
    delta.log_url = LOG

    print(f"  Delta (newcomer) :9104  [{tag(delta.pubkey.hex())}...]")

    # Check Delta's trust before vouching (should be near zero)
    trust_delta_before = requests.get(f"http://127.0.0.1:9104/trust/{delta.pubkey.hex()}", params={
        "transaction_value": 5000,
    }).json()

    print(f"\n  Delta's trust (before vouch):")
    print(f"    Effective stake:   ${trust_delta_before.get('effective_stake', 0)/100:.2f}")
    print(f"    Vouched stake:     ${trust_delta_before.get('vouched_stake', 0)/100:.2f}")

    # Gamma vouches for Delta (stakes $30 on newcomer)
    vouch_result = requests.post(f"http://127.0.0.1:9103/vouch", json={
        "vouchee": delta.pubkey.hex(),
        "amount": 3000,  # $30
    }).json()

    print(f"\n  Gamma vouches for Delta: ${vouch_result.get('amount', 0)/100:.2f}")
    print(f"    Status: {vouch_result.get('status', 'unknown')}")

    # Check Delta's trust after vouching
    trust_delta_after = requests.get(f"http://127.0.0.1:9104/trust/{delta.pubkey.hex()}", params={
        "transaction_value": 5000,
    }).json()

    print(f"\n  Delta's trust (after vouch):")
    print(f"    Effective stake:   ${trust_delta_after.get('effective_stake', 0)/100:.2f}")
    print(f"    Vouched stake:     ${trust_delta_after.get('vouched_stake', 0)/100:.2f}")
    print(f"    Trust quotient:    {trust_delta_after.get('trust_quotient', 0):.3f}")
    print(f"    Recommendation:    {trust_delta_after.get('settlement_recommendation', 'N/A')}")

    print(f"\n  Cold start solved: Established agents vouch for newcomers.")
    print(f"  Voucher's reputation at stake if vouchee frauds.")

    # ── Final stats ─────────────────────────────────────────────

    section("13. LOG STATS")

    stats = requests.get(f"{LOG}/stats").json()
    print(f"  Receipts:   {stats['receipts']}")
    print(f"  DAG edges:  {stats['dag_edges']}")
    print(f"  Transfers:  {stats['transfers']}")
    print(f"  Providers:  {stats['providers']}")
    print(f"  Models:     {stats['models']}")
    print(f"  Root:       {tag(stats['root'])}")

    # Query vouches in the log
    vouches_count = requests.get(f"{LOG}/vouches/{delta.pubkey.hex()}").json().get("count", 0)
    print(f"  Vouches:    {vouches_count}")

    # ── Summary ─────────────────────────────────────────────────

    section("DONE")

    print("""\
  Full stack exercised:

    Nodes      → compute with provenance, transfer with royalties
    Log        → receipt indexing, DAG edges, Merkle tree, vouches
    DAG        → parents, children, ancestors, descendants
    Search     → by provider, model, price range
    Proofs     → Merkle inclusion, locally verified
    Royalties  → automatic cascade through provenance DAG
    Ownership  → tracked per receipt across transfers
    Trust      → algorithmic stake from work history
    Vouching   → established agents stake for newcomers
    Settlement → recommendations based on trust quotient

  4 nodes. 1 log operator. 3 receipts. 2 DAG edges. 1 vouch.
  Trust computed from public receipts. Zero platform dependency.
""")

    # Cleanup
    if os.path.exists(db_path):
        os.remove(db_path)
    if os.path.exists(data_dir):
        shutil.rmtree(data_dir)


if __name__ == "__main__":
    main()
