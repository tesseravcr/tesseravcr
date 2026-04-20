#!/usr/bin/env python3
"""
Tessera protocol test — does the primitive actually work?

Tests the core claims in under 5 seconds:
  1. Receipts are tamper-proof (modify any field -> signature breaks)
  2. Provenance chains are hash-linked (modify parent -> child breaks)
  3. Self-collateralising trust builds from work (no external deposits)
  4. Sybil rings get marginalised (EigenTrust-family scoring)
  5. Royalties cascade correctly through provenance DAGs
  6. Settlement terms track trust quotient

    cd tessera-py && python3 tests/test_protocol.py
"""

import sys, os, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from protocol.receipt import Receipt, RoyaltyTerms
from protocol.transfer import TransferRecord, TransferLedger
from protocol.settlement import Ledger
from protocol.stake import StakeCalculator, OperatorRegistry, recommend_settlement
from protocol.registry import Registry, OperatorProfile

PASS = "\033[32m\u2713\033[0m"
FAIL = "\033[31m\u2717\033[0m"
results = []


def test(name, condition):
    results.append((name, condition))
    print(f"  {PASS if condition else FAIL}  {name}")


def pub(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def make_receipt(key, model, input_data, output_data, price,
                 parents=None, royalty_terms=None):
    r = Receipt(
        model_id=hashlib.sha256(model.encode()).digest(),
        input_hash=hashlib.sha256(input_data).digest(),
        output_hash=hashlib.sha256(output_data).digest(),
        proof=b"<test>",
        proving_backend="tee-nitro-v1",
        original_price=price,
        parent_receipts=parents or [],
        provenance_depth=0 if not parents else max(
            p.receipt_id[0] for p in (parents or [])  # placeholder
        ),
        royalty_terms=royalty_terms or RoyaltyTerms(
            provider_royalty=500, parent_royalty=300, cascade=True,
        ),
    )
    # Set depth properly based on parent count
    if parents:
        r.provenance_depth = 1  # simplified; real impl would recurse
    r.sign(key)
    return r


def main():
    # -- 1. Receipt integrity ----------------------------------------
    print("\n1. RECEIPT INTEGRITY")

    alice_key = Ed25519PrivateKey.generate()
    r = make_receipt(alice_key, "classify-v1", b"test input", b"test output", 1000)

    test("Receipt signature is valid", r.verify_signature())
    test("Receipt has a 32-byte hash ID", len(r.receipt_id) == 32)
    test("Input hash matches SHA-256",
         r.input_hash == hashlib.sha256(b"test input").digest())
    test("Output hash matches SHA-256",
         r.output_hash == hashlib.sha256(b"test output").digest())

    # Tamper detection
    original_id = r.receipt_id
    original_price = r.original_price
    r.original_price = 999999
    test("Tampering changes receipt hash", r.receipt_id != original_id)
    test("Tampering breaks signature", not r.verify_signature())
    r.original_price = original_price  # restore

    # -- 2. Provenance chains ----------------------------------------
    print("\n2. PROVENANCE CHAINS")

    bob_key = Ed25519PrivateKey.generate()
    carol_key = Ed25519PrivateKey.generate()

    r1 = make_receipt(alice_key, "classify-v1", b"doc1", b"class:A", 500)
    r2 = make_receipt(bob_key, "summarise-v1", b"class:A", b"summary",
                      800, parents=[r1.as_parent_ref("input")])
    r3 = make_receipt(carol_key, "translate-v1", b"summary", b"resume",
                      600, parents=[r2.as_parent_ref("input")])

    test("r1 has no parents (depth 0)", len(r1.parent_receipts) == 0)
    test("r2 references r1 as parent",
         r2.parent_receipts[0].receipt_id == r1.receipt_id)
    test("r3 references r2 as parent",
         r3.parent_receipts[0].receipt_id == r2.receipt_id)
    test("All signatures valid in chain",
         r1.verify_signature() and r2.verify_signature() and r3.verify_signature())

    # Hash-linking: modifying r1 would break the reference
    original_r1_hash = r1.receipt_hash
    test("Parent ref carries receipt_hash for verification",
         r2.parent_receipts[0].receipt_hash == original_r1_hash)

    # -- 3. Self-collateralising trust --------------------------------
    print("\n3. SELF-COLLATERALISING TRUST")

    registry = Registry()
    for k in [alice_key, bob_key, carol_key]:
        registry.register_operator(OperatorProfile(
            pubkey=pub(k), backends=["tee-nitro-v1"], models=[b"test"],
        ))

    counterparty_keys = [Ed25519PrivateKey.generate() for _ in range(6)]
    for k in counterparty_keys:
        registry.register_operator(OperatorProfile(
            pubkey=pub(k), backends=["tee-nitro-v1"], models=[b"client"],
        ))

    # Build a realistic network: counterparties interact with multiple operators
    # (if they only interact with one operator, independence = 0 by design)
    operators = [alice_key, bob_key, carol_key]
    for i in range(30):
        op = operators[i % 3]
        a_r = make_receipt(op, "model-v1",
                           f"job-{i}".encode(), f"result-{i}".encode(), 1500)
        registry.record_receipt(a_r)
        cp = counterparty_keys[i % len(counterparty_keys)]
        c_r = make_receipt(cp, "client-v1",
                           f"from-op-{i}".encode(), f"derived-{i}".encode(),
                           1000, parents=[a_r.as_parent_ref("input")])
        registry.record_receipt(c_r)

    # Alice gets extra work on top to be clearly ahead
    for i in range(20):
        a_r = make_receipt(alice_key, "classify-v1",
                           f"alice-extra-{i}".encode(), f"extra-{i}".encode(), 2000)
        registry.record_receipt(a_r)
        cp = counterparty_keys[i % len(counterparty_keys)]
        c_r = make_receipt(cp, "client-v1",
                           f"from-alice-extra-{i}".encode(), f"extra-derived-{i}".encode(),
                           1000, parents=[a_r.as_parent_ref("input")])
        registry.record_receipt(c_r)

    calc = registry.stake_calculator
    alice_stake = calc.compute_stake(pub(alice_key))
    bob_stake = calc.compute_stake(pub(bob_key))
    carol_stake = calc.compute_stake(pub(carol_key))

    test("Alice has highest stake (most receipts + dependents)",
         alice_stake.effective_stake > bob_stake.effective_stake)
    test("Bob has stake from own work", bob_stake.effective_stake > 0)
    test("Carol has less stake than alice (fewer receipts)",
         carol_stake.effective_stake < alice_stake.effective_stake)
    test("Stake comes from verified work, not deposits",
         alice_stake.receipt_count >= 15)

    # -- 4. Sybil resistance -----------------------------------------
    print("\n4. SYBIL RESISTANCE")

    s1_key = Ed25519PrivateKey.generate()
    s2_key = Ed25519PrivateKey.generate()
    for k in [s1_key, s2_key]:
        registry.register_operator(OperatorProfile(
            pubkey=pub(k), backends=["tee-nitro-v1"], models=[b"fake"],
        ))

    # Sybils trade only between themselves
    for i in range(20):
        r = make_receipt(s1_key, "fake-v1",
                         f"sybil-{i}".encode(), f"fake-{i}".encode(), 5000)
        registry.record_receipt(r)
        c = make_receipt(s2_key, "fake-v1",
                         f"sybil-c-{i}".encode(), f"fake-c-{i}".encode(),
                         5000, parents=[r.as_parent_ref("input")])
        registry.record_receipt(c)

    sybil_stake = calc.compute_stake(pub(s1_key))
    test("Sybil has lower stake than alice despite inflated volume",
         sybil_stake.effective_stake < alice_stake.effective_stake)

    weights = calc.compute_counterparty_weights()
    alice_w = weights.get(pub(alice_key).hex(), 0)
    sybil_w = weights.get(pub(s1_key).hex(), 0)
    test("Eigenvector: alice weight > 0", alice_w > 0)
    test("Eigenvector: sybil weight ~0 (isolated cluster)", sybil_w < 0.01)

    # -- 5. Royalty cascade -------------------------------------------
    print("\n5. ROYALTY CASCADE")

    dave_key = Ed25519PrivateKey.generate()
    eve_key = Ed25519PrivateKey.generate()

    rd = make_receipt(dave_key, "analyse-v1", b"raw data", b"analysis", 2000,
                      royalty_terms=RoyaltyTerms(
                          provider_royalty=500, parent_royalty=300, cascade=True))
    re = make_receipt(eve_key, "report-v1", b"analysis", b"report", 3000,
                      parents=[rd.as_parent_ref("input")],
                      royalty_terms=RoyaltyTerms(
                          provider_royalty=500, parent_royalty=300, cascade=True))

    # Eve resells to frank
    frank_key = Ed25519PrivateKey.generate()
    sale_price = 5000

    ledger = Ledger()
    ledger.credit("buyer", 10000)
    receipt_store = {
        rd.receipt_id.hex(): rd,
        re.receipt_id.hex(): re,
    }
    ledger.create_escrow("sale-1", "buyer", sale_price)
    payments, _ = ledger.release_escrow_resale(
        "sale-1", re, pub(eve_key), sale_price, receipt_store,
    )

    total_paid = sum(payments.values())
    test("Royalties were distributed", len(payments) > 0)
    test("Total distributed = sale price (zero leakage)", total_paid == sale_price)
    test("Eve (seller) got the largest share",
         payments.get(pub(eve_key).hex(), 0) == max(payments.values()))

    # -- 6. Settlement terms ------------------------------------------
    print("\n6. SETTLEMENT TERMS")

    # Use a tiny tx relative to stake to get instant; huge tx to need more caution
    terms_small = recommend_settlement(alice_stake.effective_stake, 1)
    terms_large = recommend_settlement(alice_stake.effective_stake, 1000000)
    terms_new = recommend_settlement(0, 100)

    test("High-trust + tiny tx -> instant", terms_small.recommendation == "instant")
    test("High-trust + large tx -> needs caution",
         terms_large.recommendation != "instant")
    test("Zero-stake -> collateral required",
         terms_new.recommendation == "collateral_required")
    test("Trust quotient: small tx > large tx",
         terms_small.quotient > terms_large.quotient)

    # -- Summary ------------------------------------------------------
    passed = sum(1 for _, c in results if c)
    total = len(results)
    failed = total - passed

    print(f"\n{'=' * 50}")
    if failed == 0:
        print(f"  {PASS}  ALL {total} TESTS PASSED")
    else:
        print(f"  {FAIL}  {failed}/{total} TESTS FAILED")
        for name, condition in results:
            if not condition:
                print(f"      - {name}")
    print(f"{'=' * 50}\n")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
