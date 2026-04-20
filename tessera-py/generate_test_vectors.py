#!/usr/bin/env python3
"""Generate test vectors for the VCR protocol specification.

Produces TEST-VECTORS.json with known inputs and expected outputs
at each step, so any implementation can verify conformance.
"""

import base64
import hashlib
import json
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from protocol.receipt import Receipt, RoyaltyTerms, ParentRef, Extension
from protocol.transfer import TransferRecord, RoyaltyPayment, TransferLedger
from protocol.settlement import Ledger

# Fixed deterministic keys for reproducible test vectors.
# Anyone can derive these: SHA-256("tessera-test-key-a"), etc.
# In real usage, keys are random. These are for test vectors only.
KEY_A = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"tessera-test-key-a").digest())
KEY_B = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"tessera-test-key-b").digest())
KEY_C = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"tessera-test-key-c").digest())


def pub(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def generate():
    vectors = {}

    # ── Vector 1: Minimal receipt (defaults) ───────────────────
    key_a = KEY_A
    r1 = Receipt(
        schema_version=1,
        model_id=b"\x00" * 32,
        verification_key_id=b"\x00" * 32,
        input_hash=hashlib.sha256(b"test input").digest(),
        output_hash=hashlib.sha256(b"test output").digest(),
        proof=b"proof-bytes",
        public_inputs=b"public-inputs",
        proving_backend="ezkl-halo2",
        timestamp=1714500000,
        parent_receipts=[],
        provenance_depth=0,
        original_price=2000,
        currency="USD-cents",
        royalty_terms=RoyaltyTerms(provider_royalty=500, parent_royalty=300, cascade=True),
        transfer_count=0,
        signature_scheme="ed25519",
        extensions=[],
    )
    r1.sign(key_a)

    canonical = r1.canonical_bytes()

    vectors["minimal_receipt"] = {
        "description": "A root receipt with no parents and default royalty terms.",
        "inputs": {
            "schema_version": 1,
            "model_id": "00" * 32,
            "verification_key_id": "00" * 32,
            "input_hash": hashlib.sha256(b"test input").hexdigest(),
            "output_hash": hashlib.sha256(b"test output").hexdigest(),
            "proof": base64.b64encode(b"proof-bytes").decode(),
            "public_inputs": base64.b64encode(b"public-inputs").decode(),
            "proving_backend": "ezkl-halo2",
            "timestamp": 1714500000,
            "parent_receipts": [],
            "provenance_depth": 0,
            "provider": pub(key_a).hex(),
            "original_price": 2000,
            "currency": "USD-cents",
            "royalty_terms": {
                "provider_royalty": 500,
                "parent_royalty": 300,
                "cascade": True,
            },
            "signature_scheme": "ed25519",
            "extensions": [],
        },
        "expected": {
            "canonical_bytes_hex": canonical.hex(),
            "canonical_bytes_length": len(canonical),
            "receipt_id": r1.receipt_id.hex(),
            "receipt_hash": r1.receipt_hash.hex(),
            "receipt_id_equals_receipt_hash": r1.receipt_id == r1.receipt_hash,
            "signature": base64.b64encode(r1.signature).decode(),
            "signature_valid": r1.verify_signature(),
        },
    }

    # ── Vector 2: Receipt with parent references ───────────────
    key_b = KEY_B

    parent_ref = ParentRef(
        receipt_id=r1.receipt_id,
        receipt_hash=r1.receipt_hash,
        relationship="input",
    )

    r2 = Receipt(
        schema_version=1,
        model_id=hashlib.sha256(b"derivative-model-v1").digest(),
        verification_key_id=hashlib.sha256(b"derivative-vk").digest(),
        input_hash=hashlib.sha256(b"derived input").digest(),
        output_hash=hashlib.sha256(b"derived output").digest(),
        proof=b"derivative-proof",
        public_inputs=b"derivative-public",
        proving_backend="ezkl-halo2",
        timestamp=1714503600,
        parent_receipts=[parent_ref],
        provenance_depth=1,
        original_price=5000,
        currency="USD-cents",
        royalty_terms=RoyaltyTerms(provider_royalty=500, parent_royalty=300, cascade=True),
        transfer_count=0,
        signature_scheme="ed25519",
        extensions=[],
    )
    r2.sign(key_b)

    vectors["receipt_with_parent"] = {
        "description": "A derivative receipt referencing Vector 1 as parent. Provenance depth 1.",
        "inputs": {
            "schema_version": 1,
            "model_id": hashlib.sha256(b"derivative-model-v1").hexdigest(),
            "verification_key_id": hashlib.sha256(b"derivative-vk").hexdigest(),
            "input_hash": hashlib.sha256(b"derived input").hexdigest(),
            "output_hash": hashlib.sha256(b"derived output").hexdigest(),
            "proof": base64.b64encode(b"derivative-proof").decode(),
            "public_inputs": base64.b64encode(b"derivative-public").decode(),
            "proving_backend": "ezkl-halo2",
            "timestamp": 1714503600,
            "parent_receipts": [
                {
                    "receipt_id": r1.receipt_id.hex(),
                    "receipt_hash": r1.receipt_hash.hex(),
                    "relationship": "input",
                }
            ],
            "provenance_depth": 1,
            "provider": pub(key_b).hex(),
            "original_price": 5000,
            "currency": "USD-cents",
            "royalty_terms": {
                "provider_royalty": 500,
                "parent_royalty": 300,
                "cascade": True,
            },
            "signature_scheme": "ed25519",
            "extensions": [],
        },
        "expected": {
            "canonical_bytes_hex": r2.canonical_bytes().hex(),
            "canonical_bytes_length": len(r2.canonical_bytes()),
            "receipt_id": r2.receipt_id.hex(),
            "signature": base64.b64encode(r2.signature).decode(),
            "signature_valid": r2.verify_signature(),
            "parent_ref_canonical_hex": parent_ref.canonical_bytes().hex(),
        },
    }

    # ── Vector 3: Canonical serialisation breakdown ────────────
    # Show each field's contribution to the canonical bytes

    field_breakdown = []

    def len_prefixed_hex(data):
        return (struct.pack(">I", len(data)) + data).hex()

    field_breakdown.append({
        "field": "schema_version",
        "value": 1,
        "encoded_hex": len_prefixed_hex(struct.pack(">H", 1)),
        "note": "BE16(1) = 00 01, length-prefixed",
    })
    field_breakdown.append({
        "field": "model_id",
        "value": "00" * 32,
        "encoded_hex": len_prefixed_hex(b"\x00" * 32),
        "note": "32 zero bytes, length-prefixed",
    })
    field_breakdown.append({
        "field": "verification_key_id",
        "value": "00" * 32,
        "encoded_hex": len_prefixed_hex(b"\x00" * 32),
        "note": "32 zero bytes, length-prefixed",
    })
    field_breakdown.append({
        "field": "input_hash",
        "value": hashlib.sha256(b"test input").hexdigest(),
        "encoded_hex": len_prefixed_hex(hashlib.sha256(b"test input").digest()),
        "note": "SHA-256('test input'), length-prefixed",
    })
    field_breakdown.append({
        "field": "output_hash",
        "value": hashlib.sha256(b"test output").hexdigest(),
        "encoded_hex": len_prefixed_hex(hashlib.sha256(b"test output").digest()),
        "note": "SHA-256('test output'), length-prefixed",
    })
    field_breakdown.append({
        "field": "proof",
        "value": base64.b64encode(b"proof-bytes").decode(),
        "encoded_hex": len_prefixed_hex(b"proof-bytes"),
        "note": "Raw bytes, length-prefixed",
    })
    field_breakdown.append({
        "field": "public_inputs",
        "value": base64.b64encode(b"public-inputs").decode(),
        "encoded_hex": len_prefixed_hex(b"public-inputs"),
        "note": "Raw bytes, length-prefixed",
    })
    field_breakdown.append({
        "field": "proving_backend",
        "value": "ezkl-halo2",
        "encoded_hex": len_prefixed_hex(b"ezkl-halo2"),
        "note": "UTF-8, length-prefixed",
    })
    field_breakdown.append({
        "field": "timestamp",
        "value": 1714500000,
        "encoded_hex": len_prefixed_hex(struct.pack(">Q", 1714500000)),
        "note": "BE64(1714500000), length-prefixed",
    })
    field_breakdown.append({
        "field": "parent_receipts",
        "value": "[] (empty list)",
        "encoded_hex": struct.pack(">I", 0).hex(),
        "note": "BE32(0) — zero items",
    })
    field_breakdown.append({
        "field": "provenance_depth",
        "value": 0,
        "encoded_hex": len_prefixed_hex(struct.pack(">H", 0)),
        "note": "BE16(0), length-prefixed",
    })
    field_breakdown.append({
        "field": "provider",
        "value": pub(key_a).hex(),
        "encoded_hex": len_prefixed_hex(pub(key_a)),
        "note": "Ed25519 public key (32 bytes), length-prefixed",
    })
    field_breakdown.append({
        "field": "original_price",
        "value": 2000,
        "encoded_hex": len_prefixed_hex(struct.pack(">Q", 2000)),
        "note": "BE64(2000), length-prefixed",
    })
    field_breakdown.append({
        "field": "currency",
        "value": "USD-cents",
        "encoded_hex": len_prefixed_hex(b"USD-cents"),
        "note": "UTF-8, length-prefixed",
    })
    field_breakdown.append({
        "field": "royalty_terms.provider_royalty",
        "value": 500,
        "encoded_hex": len_prefixed_hex(struct.pack(">H", 500)),
        "note": "BE16(500), length-prefixed. Nested — no outer wrapper.",
    })
    field_breakdown.append({
        "field": "royalty_terms.parent_royalty",
        "value": 300,
        "encoded_hex": len_prefixed_hex(struct.pack(">H", 300)),
        "note": "BE16(300), length-prefixed",
    })
    field_breakdown.append({
        "field": "royalty_terms.cascade",
        "value": True,
        "encoded_hex": len_prefixed_hex(struct.pack(">?", True)),
        "note": "0x01 (true), length-prefixed",
    })
    field_breakdown.append({
        "field": "signature_scheme",
        "value": "ed25519",
        "encoded_hex": len_prefixed_hex(b"ed25519"),
        "note": "UTF-8, length-prefixed",
    })
    field_breakdown.append({
        "field": "extensions",
        "value": "[] (empty list)",
        "encoded_hex": struct.pack(">I", 0).hex(),
        "note": "BE32(0) — zero items",
    })

    vectors["canonical_serialisation_breakdown"] = {
        "description": "Field-by-field canonical byte encoding for the minimal receipt (Vector 1). Concatenate all encoded_hex values to get the full canonical bytes.",
        "fields": field_breakdown,
        "concatenated_hex": canonical.hex(),
        "sha256_of_concatenated": r1.receipt_id.hex(),
    }

    # ── Vector 4: Transfer record ──────────────────────────────
    key_c = KEY_C

    xfer = TransferRecord(
        receipt_id=r2.receipt_id,
        from_key=pub(key_b),
        to_key=pub(key_c),
        price=8000,
        currency="USD-cents",
        timestamp=1714510000,
        royalties_paid=[
            RoyaltyPayment(
                recipient=pub(key_b),
                amount=400,
                receipt_id=r2.receipt_id,
            ),
            RoyaltyPayment(
                recipient=pub(key_a),
                amount=120,
                receipt_id=r1.receipt_id,
            ),
        ],
    )
    xfer.sign(key_b)

    vectors["transfer_record"] = {
        "description": "Transfer of Vector 2's receipt from key_b to key_c at $80.00 with royalty payments.",
        "inputs": {
            "receipt_id": r2.receipt_id.hex(),
            "from_key": pub(key_b).hex(),
            "to_key": pub(key_c).hex(),
            "price": 8000,
            "currency": "USD-cents",
            "timestamp": 1714510000,
            "royalties_paid": [
                {
                    "recipient": pub(key_b).hex(),
                    "amount": 400,
                    "receipt_id": r2.receipt_id.hex(),
                },
                {
                    "recipient": pub(key_a).hex(),
                    "amount": 120,
                    "receipt_id": r1.receipt_id.hex(),
                },
            ],
        },
        "expected": {
            "canonical_bytes_hex": xfer.canonical_bytes().hex(),
            "transfer_hash": xfer.transfer_hash.hex(),
            "signature": base64.b64encode(xfer.seller_signature).decode(),
            "signature_valid": xfer.verify_signature(),
        },
    }

    # ── Vector 5: Royalty cascade ──────────────────────────────
    ledger = Ledger()
    ledger.credit("buyer", 100000)

    receipt_store = {
        r1.receipt_id.hex(): r1,
        r2.receipt_id.hex(): r2,
    }

    ledger.create_escrow("test-escrow", "buyer", 8000)
    payments, royalty_records = ledger.release_escrow_resale(
        "test-escrow", r2, pub(key_b), 8000, receipt_store,
    )

    vectors["royalty_cascade"] = {
        "description": "Resale of Vector 2 for 8000 cents ($80). Royalties cascade through provenance DAG.",
        "inputs": {
            "receipt": r2.receipt_id.hex(),
            "sale_price": 8000,
            "seller": pub(key_b).hex(),
            "receipt_royalty_terms": {
                "provider_royalty": 500,
                "parent_royalty": 300,
                "cascade": True,
            },
            "parent_receipt": r1.receipt_id.hex(),
            "parent_royalty_terms": {
                "provider_royalty": 500,
                "parent_royalty": 300,
                "cascade": True,
            },
        },
        "expected": {
            "payments": {k: v for k, v in sorted(payments.items(), key=lambda x: -x[1])},
            "explanation": {
                "step_1": "provider_cut = 8000 × 500/10000 = 400 → to r2.provider (key_b)",
                "step_2": "parent_cut_total = 8000 × 300/10000 = 240",
                "step_3": "per_parent = 240 / 1 parent = 240",
                "step_4": "cascade=true, so DISTRIBUTE(r1, 240):",
                "step_4a": "  r1.provider_cut = 240 × 500/10000 = 12 → to r1.provider (key_a)",
                "step_4b": "  r1.parent_cut = 240 × 300/10000 = 7.2 → no parents (root), so nothing",
                "step_5": "seller_cut = 8000 - 400 - 240 = 7360 → to seller (key_b)",
                "note": "key_b receives 400 (as provider) + 7360 (as seller) = 7760 total",
            },
        },
    }

    # ── Vector 6: Tamper detection ─────────────────────────────
    original_id = r1.receipt_id.hex()
    original_sig_valid = r1.verify_signature()

    tampered = Receipt(
        schema_version=r1.schema_version,
        model_id=r1.model_id,
        verification_key_id=r1.verification_key_id,
        input_hash=r1.input_hash,
        output_hash=hashlib.sha256(b"TAMPERED OUTPUT").digest(),
        proof=r1.proof,
        public_inputs=r1.public_inputs,
        proving_backend=r1.proving_backend,
        timestamp=r1.timestamp,
        parent_receipts=[],
        provenance_depth=0,
        provider=r1.provider,
        original_price=r1.original_price,
        currency=r1.currency,
        royalty_terms=r1.royalty_terms,
        signature=r1.signature,
        signature_scheme=r1.signature_scheme,
    )

    vectors["tamper_detection"] = {
        "description": "Modify output_hash of Vector 1. Receipt ID changes, signature breaks.",
        "original": {
            "receipt_id": original_id,
            "output_hash": r1.output_hash.hex(),
            "signature_valid": original_sig_valid,
        },
        "tampered": {
            "receipt_id": tampered.receipt_id.hex(),
            "output_hash": tampered.output_hash.hex(),
            "signature_valid": tampered.verify_signature(),
        },
        "receipt_id_changed": original_id != tampered.receipt_id.hex(),
        "signature_broken": not tampered.verify_signature(),
    }

    # ── Vector 7: Edge cases ─────────────────────────────────────
    from protocol.receipt import ReceiptValidationError, MAX_PROVENANCE_DEPTH

    # 7a. Royalty sum at boundary (exactly 10000 bps) — valid
    r_royalty_max = Receipt(
        schema_version=1,
        model_id=b"\x00" * 32,
        verification_key_id=b"\x00" * 32,
        input_hash=hashlib.sha256(b"edge-royalty-max").digest(),
        output_hash=hashlib.sha256(b"edge-royalty-max-out").digest(),
        proof=b"proof",
        public_inputs=b"",
        proving_backend="ezkl-halo2",
        timestamp=1714500000,
        parent_receipts=[],
        provenance_depth=0,
        original_price=1000,
        currency="USD-cents",
        royalty_terms=RoyaltyTerms(provider_royalty=7000, parent_royalty=3000, cascade=False),
        signature_scheme="ed25519",
    )
    r_royalty_max.sign(key_a)

    # 7b. Zero-length proof — valid
    r_empty_proof = Receipt(
        schema_version=1,
        model_id=b"\x00" * 32,
        verification_key_id=b"\x00" * 32,
        input_hash=hashlib.sha256(b"edge-empty-proof").digest(),
        output_hash=hashlib.sha256(b"edge-empty-proof-out").digest(),
        proof=b"",
        public_inputs=b"",
        proving_backend="ezkl-halo2",
        timestamp=1714500000,
        parent_receipts=[],
        provenance_depth=0,
        original_price=500,
        currency="USD-cents",
        royalty_terms=RoyaltyTerms(provider_royalty=500, parent_royalty=300, cascade=True),
        signature_scheme="ed25519",
    )
    r_empty_proof.sign(key_a)

    # 7c. Empty parents with cascade=true — valid root receipt
    r_root_cascade = Receipt(
        schema_version=1,
        model_id=b"\x00" * 32,
        verification_key_id=b"\x00" * 32,
        input_hash=hashlib.sha256(b"edge-root-cascade").digest(),
        output_hash=hashlib.sha256(b"edge-root-cascade-out").digest(),
        proof=b"root-proof",
        public_inputs=b"",
        proving_backend="ezkl-halo2",
        timestamp=1714500000,
        parent_receipts=[],
        provenance_depth=0,
        original_price=2000,
        currency="USD-cents",
        royalty_terms=RoyaltyTerms(provider_royalty=500, parent_royalty=300, cascade=True),
        signature_scheme="ed25519",
    )
    r_root_cascade.sign(key_a)

    # 7d. Max provenance depth — valid
    r_max_depth = Receipt(
        schema_version=1,
        model_id=b"\x00" * 32,
        verification_key_id=b"\x00" * 32,
        input_hash=hashlib.sha256(b"edge-max-depth").digest(),
        output_hash=hashlib.sha256(b"edge-max-depth-out").digest(),
        proof=b"deep-proof",
        public_inputs=b"",
        proving_backend="ezkl-halo2",
        timestamp=1714500000,
        parent_receipts=[ParentRef(
            receipt_id=r1.receipt_id,
            receipt_hash=r1.receipt_hash,
            relationship="input",
        )],
        provenance_depth=MAX_PROVENANCE_DEPTH,
        original_price=3000,
        currency="USD-cents",
        royalty_terms=RoyaltyTerms(provider_royalty=500, parent_royalty=300, cascade=True),
        signature_scheme="ed25519",
    )
    r_max_depth.sign(key_b)

    # 7e. Multi-parent DAG — two distinct parents
    r_multi_parent = Receipt(
        schema_version=1,
        model_id=hashlib.sha256(b"multi-parent-model").digest(),
        verification_key_id=b"\x00" * 32,
        input_hash=hashlib.sha256(b"edge-multi-parent").digest(),
        output_hash=hashlib.sha256(b"edge-multi-parent-out").digest(),
        proof=b"dag-proof",
        public_inputs=b"",
        proving_backend="ezkl-halo2",
        timestamp=1714503600,
        parent_receipts=[
            ParentRef(receipt_id=r1.receipt_id, receipt_hash=r1.receipt_hash, relationship="input"),
            ParentRef(receipt_id=r2.receipt_id, receipt_hash=r2.receipt_hash, relationship="reference"),
        ],
        provenance_depth=2,
        original_price=7000,
        currency="USD-cents",
        royalty_terms=RoyaltyTerms(provider_royalty=500, parent_royalty=400, cascade=True),
        signature_scheme="ed25519",
    )
    r_multi_parent.sign(KEY_C)

    # Rejection cases — these MUST fail validation
    royalty_overflow_rejects = False
    try:
        RoyaltyTerms(provider_royalty=7000, parent_royalty=5000).validate()
    except ReceiptValidationError:
        royalty_overflow_rejects = True

    duplicate_parent_rejects = False
    try:
        r_dup = Receipt(
            parent_receipts=[
                ParentRef(receipt_id=r1.receipt_id, receipt_hash=r1.receipt_hash, relationship="input"),
                ParentRef(receipt_id=r1.receipt_id, receipt_hash=r1.receipt_hash, relationship="input"),
            ],
            provenance_depth=1,
        )
        r_dup.validate()
    except ReceiptValidationError:
        duplicate_parent_rejects = True

    depth_overflow_rejects = False
    try:
        Receipt(provenance_depth=MAX_PROVENANCE_DEPTH + 1).validate()
    except ReceiptValidationError:
        depth_overflow_rejects = True

    vectors["edge_cases"] = {
        "description": "Edge case coverage: royalty bounds, zero-length proofs, empty parents, depth limits, multi-parent DAG, and rejection cases.",
        "valid_cases": {
            "royalty_sum_10000_bps": {
                "description": "Royalty sum exactly 10000 bps (boundary) — valid",
                "royalty_terms": {"provider_royalty": 7000, "parent_royalty": 3000, "cascade": False},
                "receipt_id": r_royalty_max.receipt_id.hex(),
                "canonical_bytes_hex": r_royalty_max.canonical_bytes().hex(),
                "signature": base64.b64encode(r_royalty_max.signature).decode(),
                "signature_valid": r_royalty_max.verify_signature(),
            },
            "zero_length_proof": {
                "description": "Empty proof field — valid (backend verifies proof, not receipt layer)",
                "proof_length": 0,
                "receipt_id": r_empty_proof.receipt_id.hex(),
                "canonical_bytes_hex": r_empty_proof.canonical_bytes().hex(),
                "signature": base64.b64encode(r_empty_proof.signature).decode(),
                "signature_valid": r_empty_proof.verify_signature(),
            },
            "empty_parents_cascade_true": {
                "description": "Root receipt with cascade=true and parent_royalty=300 — valid. Parent royalty is a no-op with no parents.",
                "parent_receipts": [],
                "cascade": True,
                "parent_royalty": 300,
                "receipt_id": r_root_cascade.receipt_id.hex(),
                "canonical_bytes_hex": r_root_cascade.canonical_bytes().hex(),
                "signature_valid": r_root_cascade.verify_signature(),
            },
            "max_provenance_depth": {
                "description": f"provenance_depth = {MAX_PROVENANCE_DEPTH} (maximum allowed) — valid",
                "provenance_depth": MAX_PROVENANCE_DEPTH,
                "receipt_id": r_max_depth.receipt_id.hex(),
                "canonical_bytes_hex": r_max_depth.canonical_bytes().hex(),
                "signature_valid": r_max_depth.verify_signature(),
            },
            "multi_parent_dag": {
                "description": "Receipt with two distinct parents (DAG, not chain) — valid",
                "parent_count": 2,
                "parent_receipt_ids": [r1.receipt_id.hex(), r2.receipt_id.hex()],
                "receipt_id": r_multi_parent.receipt_id.hex(),
                "canonical_bytes_hex": r_multi_parent.canonical_bytes().hex(),
                "signature": base64.b64encode(r_multi_parent.signature).decode(),
                "signature_valid": r_multi_parent.verify_signature(),
            },
        },
        "rejection_cases": {
            "royalty_sum_over_10000": {
                "description": "provider_royalty=7000 + parent_royalty=5000 = 12000 bps — MUST reject",
                "provider_royalty": 7000,
                "parent_royalty": 5000,
                "sum_bps": 12000,
                "rejected": royalty_overflow_rejects,
            },
            "duplicate_parent_entries": {
                "description": "Same receipt_id appears twice in parent_receipts — MUST reject",
                "duplicate_receipt_id": r1.receipt_id.hex(),
                "rejected": duplicate_parent_rejects,
            },
            "provenance_depth_overflow": {
                "description": f"provenance_depth = {MAX_PROVENANCE_DEPTH + 1} (exceeds maximum) — MUST reject",
                "provenance_depth": MAX_PROVENANCE_DEPTH + 1,
                "max_allowed": MAX_PROVENANCE_DEPTH,
                "rejected": depth_overflow_rejects,
            },
            "self_referencing_parent": {
                "description": "Self-referencing is cryptographically impossible. receipt_id = SHA-256(canonical_bytes) includes parent_receipts, so adding yourself as parent changes the hash. Finding a fixed point requires breaking SHA-256.",
                "property": "cryptographically_impossible",
            },
        },
    }

    # ── Vector 8: Receipt with extensions ──────────────────────
    r_ext = Receipt(
        schema_version=1,
        model_id=bytes(32),
        verification_key_id=bytes(32),
        input_hash=hashlib.sha256(b"extension test input").digest(),
        output_hash=hashlib.sha256(b"extension test output").digest(),
        proof=b"ext-proof",
        public_inputs=b"",
        proving_backend="ezkl-halo2",
        timestamp=1714500000,
        parent_receipts=[],
        provenance_depth=0,
        original_price=1500,
        currency="USD-cents",
        royalty_terms=RoyaltyTerms(
            provider_royalty=500,
            parent_royalty=300,
            cascade=True,
        ),
        signature_scheme="ed25519",
        extensions=[
            Extension(type="metadata", data=b"agent-v1.2.0"),
            Extension(type="capability", data=b"text-generation"),
        ],
    )
    r_ext.sign(KEY_A)

    vectors["receipt_with_extensions"] = {
        "description": "Receipt with two populated extensions — exercises non-empty extensions list serialisation",
        "inputs": {
            "schema_version": r_ext.schema_version,
            "model_id": r_ext.model_id.hex(),
            "verification_key_id": r_ext.verification_key_id.hex(),
            "input_hash": r_ext.input_hash.hex(),
            "output_hash": r_ext.output_hash.hex(),
            "proof": base64.b64encode(r_ext.proof).decode(),
            "public_inputs": base64.b64encode(r_ext.public_inputs).decode(),
            "proving_backend": r_ext.proving_backend,
            "timestamp": r_ext.timestamp,
            "parent_receipts": [],
            "provenance_depth": r_ext.provenance_depth,
            "provider": r_ext.provider.hex(),
            "original_price": r_ext.original_price,
            "currency": r_ext.currency,
            "royalty_terms": {
                "provider_royalty": r_ext.royalty_terms.provider_royalty,
                "parent_royalty": r_ext.royalty_terms.parent_royalty,
                "cascade": r_ext.royalty_terms.cascade,
            },
            "signature_scheme": r_ext.signature_scheme,
            "extensions": [
                {
                    "type": ext.type,
                    "data": base64.b64encode(ext.data).decode(),
                }
                for ext in r_ext.extensions
            ],
        },
        "expected": {
            "canonical_bytes_hex": r_ext.canonical_bytes().hex(),
            "canonical_bytes_length": len(r_ext.canonical_bytes()),
            "receipt_id": r_ext.receipt_id.hex(),
            "signature": base64.b64encode(r_ext.signature).decode(),
            "signature_valid": r_ext.verify_signature(),
        },
    }

    # ── Write output ───────────────────────────────────────────
    output = {
        "_meta": {
            "description": "VCR Protocol Test Vectors — generated from reference implementation",
            "spec_version": "1.0",
            "generated_by": "tessera/generate_test_vectors.py",
            "hash_function": "SHA-256",
            "signature_scheme": "Ed25519 (RFC 8032)",
            "key_derivation": "Ed25519 keys from SHA-256('tessera-test-key-a'), SHA-256('tessera-test-key-b'), SHA-256('tessera-test-key-c')",
            "note": "Fully deterministic. All values including receipt IDs, signatures, and hashes are reproducible from the key derivation seeds above.",
        },
        "vectors": vectors,
    }

    out_path = os.path.join(os.path.dirname(__file__), "..", "spec", "TEST-VECTORS.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, default=str)

    print(f"Generated {len(vectors)} test vectors → {out_path}")
    for name, vec in vectors.items():
        print(f"  {name}: {vec['description'][:80]}")


if __name__ == "__main__":
    generate()
