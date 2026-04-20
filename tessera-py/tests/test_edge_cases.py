#!/usr/bin/env python3
"""
Edge case coverage — proves the spec handles every ambiguous boundary.

Tests the six edge cases identified in the hardening checklist:
  1. Royalty rates summing above 10000 bps
  2. Zero-length proofs
  3. Empty parent lists in cascade mode
  4. Self-referencing parent receipts
  5. Duplicate parent entries
  6. Maximum provenance depth

Each edge case has a defined behaviour: either valid (with deterministic output)
or rejected with ReceiptValidationError. No ambiguity.

    cd tessera-py && python3 tests/test_edge_cases.py
"""

import hashlib
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from protocol.receipt import (
    Receipt, RoyaltyTerms, ParentRef, Extension,
    ReceiptValidationError, MAX_PROVENANCE_DEPTH,
)
from protocol.settlement import Ledger

PASS = "\033[32m\u2713\033[0m"
FAIL = "\033[31m\u2717\033[0m"
results = []

# Deterministic test keys
KEY_A = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"tessera-test-key-a").digest())
KEY_B = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"tessera-test-key-b").digest())
KEY_C = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"tessera-test-key-c").digest())


def test(name, condition):
    results.append((name, condition))
    print(f"  {PASS if condition else FAIL}  {name}")


def pub(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def make_receipt(**overrides):
    defaults = dict(
        schema_version=1,
        model_id=b"\x00" * 32,
        verification_key_id=b"\x00" * 32,
        input_hash=hashlib.sha256(b"edge-input").digest(),
        output_hash=hashlib.sha256(b"edge-output").digest(),
        proof=b"proof-bytes",
        public_inputs=b"public-inputs",
        proving_backend="ezkl-halo2",
        timestamp=1714500000,
        parent_receipts=[],
        provenance_depth=0,
        original_price=2000,
        currency="USD-cents",
        royalty_terms=RoyaltyTerms(provider_royalty=500, parent_royalty=300, cascade=True),
        signature_scheme="ed25519",
    )
    defaults.update(overrides)
    return Receipt(**defaults)


def main():
    print("\n  Edge case coverage: 6 categories\n")

    # ── 1. Royalty rates summing above 10000 bps ──────────────
    print("  1. ROYALTY RATE BOUNDS")

    # 1a. Exactly 10000 bps — should be valid
    r = make_receipt(royalty_terms=RoyaltyTerms(provider_royalty=7000, parent_royalty=3000))
    r.sign(KEY_A)
    test("Royalty sum = 10000 bps is valid", r.verify_signature())

    # 1b. Over 10000 bps — must reject
    r_bad = make_receipt(royalty_terms=RoyaltyTerms(provider_royalty=7000, parent_royalty=5000))
    rejected = False
    try:
        r_bad.sign(KEY_A)
    except ReceiptValidationError:
        rejected = True
    test("Royalty sum = 12000 bps rejected at sign()", rejected)

    # 1c. provider_royalty alone > 10000
    r_bad2 = make_receipt(royalty_terms=RoyaltyTerms(provider_royalty=10001))
    rejected2 = False
    try:
        r_bad2.sign(KEY_A)
    except ReceiptValidationError:
        rejected2 = True
    test("provider_royalty = 10001 rejected", rejected2)

    # 1d. Negative royalty (if somehow constructed)
    r_bad3 = make_receipt(royalty_terms=RoyaltyTerms(provider_royalty=-1))
    rejected3 = False
    try:
        r_bad3.validate()
    except ReceiptValidationError:
        rejected3 = True
    test("Negative provider_royalty rejected", rejected3)

    # 1e. Zero royalties — valid (no royalties owed)
    r_zero = make_receipt(royalty_terms=RoyaltyTerms(provider_royalty=0, parent_royalty=0))
    r_zero.sign(KEY_A)
    test("Zero royalties is valid", r_zero.verify_signature())

    # ── 2. Zero-length proofs ─────────────────────────────────
    print("\n  2. ZERO-LENGTH PROOFS")

    r_empty_proof = make_receipt(proof=b"")
    r_empty_proof.sign(KEY_A)
    test("Empty proof is valid (backend verifies later)", r_empty_proof.verify_signature())
    test("Empty proof receipt has valid hash", len(r_empty_proof.receipt_id) == 32)

    # Non-empty proof for comparison — different receipt_id
    r_with_proof = make_receipt(proof=b"actual-proof")
    r_with_proof.sign(KEY_A)
    test("Different proof → different receipt_id",
         r_empty_proof.receipt_id != r_with_proof.receipt_id)

    # ── 3. Empty parent lists in cascade mode ─────────────────
    print("\n  3. EMPTY PARENTS WITH CASCADE=TRUE")

    r_root_cascade = make_receipt(
        parent_receipts=[],
        provenance_depth=0,
        royalty_terms=RoyaltyTerms(provider_royalty=500, parent_royalty=300, cascade=True),
    )
    r_root_cascade.sign(KEY_A)
    test("Root receipt with cascade=true is valid", r_root_cascade.verify_signature())

    # Settlement: resale of root receipt with cascade=true
    # parent_royalty has no effect (no parents to pay)
    ledger = Ledger()
    ledger.credit("buyer", 100000)
    ledger.create_escrow("test-root", "buyer", 5000)
    payments, _ = ledger.release_escrow_resale(
        "test-root", r_root_cascade, pub(KEY_A), 5000, {},
    )
    # provider_cut = 5000 * 500/10000 = 250, no parents → parent_royalty is not deducted,
    # seller (=provider here) gets remainder: 5000 - 250 = 4750. Total to KEY_A = 5000.
    provider_got = payments.get(pub(KEY_A).hex(), 0)
    test("Root cascade: no parent_royalty deducted (no parents to pay)",
         provider_got == 5000)
    total_paid = sum(payments.values())
    test("Root cascade: total distributed = sale price (no leakage)", total_paid == 5000)

    # ── 4. Self-referencing parent receipts ────────────────────
    print("\n  4. SELF-REFERENCING PARENTS")

    # A receipt cannot reference itself as a parent because the receipt_id
    # is SHA-256(canonical_bytes) which includes parent_receipts.
    # To self-reference, you'd need receipt_id = SHA-256(...receipt_id...),
    # which requires finding a SHA-256 fixed point — computationally infeasible.
    # The protocol is safe by construction. We verify this property:

    r_base = make_receipt()
    r_base.sign(KEY_A)

    # Try to create a "self-referencing" receipt by using its own computed ID
    # This produces a different receipt (different parent_receipts → different hash)
    fake_self_ref = make_receipt(
        parent_receipts=[ParentRef(
            receipt_id=r_base.receipt_id,
            receipt_hash=r_base.receipt_hash,
            relationship="input",
        )],
        provenance_depth=1,
    )
    fake_self_ref.sign(KEY_B)
    test("Adding parent changes receipt_id (no fixed point)",
         fake_self_ref.receipt_id != r_base.receipt_id)

    # Even if someone sets receipt_id in parent_ref to their own computed hash,
    # the resulting receipt will have a DIFFERENT hash
    attempt = make_receipt()
    # Compute what the hash would be with no parents
    no_parent_id = attempt.receipt_id
    # Now add self as parent
    attempt_with_self = make_receipt(
        parent_receipts=[ParentRef(
            receipt_id=no_parent_id,
            receipt_hash=no_parent_id,
            relationship="input",
        )],
        provenance_depth=1,
    )
    test("Self-reference attempt: hash changes (cryptographically impossible)",
         attempt_with_self.receipt_id != no_parent_id)

    # ── 5. Duplicate parent entries ───────────────────────────
    print("\n  5. DUPLICATE PARENT ENTRIES")

    r_parent = make_receipt()
    r_parent.sign(KEY_A)
    parent_ref = r_parent.as_parent_ref("input")

    # Duplicate parent_receipts — must reject
    r_dup = make_receipt(
        parent_receipts=[parent_ref, parent_ref],
        provenance_depth=1,
    )
    dup_rejected = False
    try:
        r_dup.sign(KEY_B)
    except ReceiptValidationError:
        dup_rejected = True
    test("Duplicate parent receipt_id rejected at sign()", dup_rejected)

    dup_rejected2 = False
    try:
        r_dup.validate()
    except ReceiptValidationError:
        dup_rejected2 = True
    test("Duplicate parent receipt_id rejected at validate()", dup_rejected2)

    # Two different parents — valid
    r_parent2 = make_receipt(
        input_hash=hashlib.sha256(b"different-input").digest(),
    )
    r_parent2.sign(KEY_B)
    r_multi = make_receipt(
        parent_receipts=[
            r_parent.as_parent_ref("input"),
            r_parent2.as_parent_ref("reference"),
        ],
        provenance_depth=1,
    )
    r_multi.sign(KEY_C)
    test("Two distinct parents is valid", r_multi.verify_signature())
    test("Multi-parent receipt has depth 1", r_multi.provenance_depth == 1)

    # ── 6. Maximum provenance depth ───────────────────────────
    print("\n  6. PROVENANCE DEPTH LIMITS")

    test(f"MAX_PROVENANCE_DEPTH = {MAX_PROVENANCE_DEPTH}", MAX_PROVENANCE_DEPTH == 256)

    # At the boundary — valid
    r_at_max = make_receipt(provenance_depth=MAX_PROVENANCE_DEPTH)
    r_at_max.sign(KEY_A)
    test(f"provenance_depth = {MAX_PROVENANCE_DEPTH} is valid", r_at_max.verify_signature())

    # Over the boundary — rejected
    r_over = make_receipt(provenance_depth=MAX_PROVENANCE_DEPTH + 1)
    depth_rejected = False
    try:
        r_over.sign(KEY_A)
    except ReceiptValidationError:
        depth_rejected = True
    test(f"provenance_depth = {MAX_PROVENANCE_DEPTH + 1} rejected", depth_rejected)

    # Way over — rejected
    r_way_over = make_receipt(provenance_depth=65535)
    way_over_rejected = False
    try:
        r_way_over.validate()
    except ReceiptValidationError:
        way_over_rejected = True
    test("provenance_depth = 65535 rejected", way_over_rejected)

    # Depth 0 with no parents — valid
    r_root = make_receipt(provenance_depth=0, parent_receipts=[])
    r_root.sign(KEY_A)
    test("Depth 0 with no parents is valid", r_root.verify_signature())

    # ── Summary ────────────────────────────────────────────────
    passed = sum(1 for _, c in results if c)
    total_tests = len(results)
    failed = total_tests - passed

    print(f"\n{'=' * 60}")
    if failed == 0:
        print(f"  {PASS}  ALL {total_tests} TESTS PASSED")
        print()
        print(f"  6 edge case categories. Every boundary has defined behaviour.")
        print(f"  Invalid receipts are rejected at validation. Valid edge")
        print(f"  cases produce deterministic, correct output.")
    else:
        print(f"  {FAIL}  {failed}/{total_tests} TESTS FAILED")
        for name, condition in results:
            if not condition:
                print(f"      - {name}")
    print(f"{'=' * 60}\n")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
