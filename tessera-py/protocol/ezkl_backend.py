# ezkl_backend — bridge between ezkl ZK proofs and VCR receipts
#
# takes the output from an ezkl proving pipeline (proof hex, public inputs,
# verification key hash) and produces a proper Receipt that plugs into
# the rest of the protocol: stake, registry, settlement, transfer.
#
# mirrors tee_backend.py — the two-function backend abstraction:
#   wrap()   — ZK proof output -> Receipt
#   verify() — Receipt -> bool (requires ezkl + artifacts on disk)

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .receipt import Receipt, RoyaltyTerms


@dataclass
class ZKOutput:
    proof: bytes                # raw Halo2 proof bytes
    public_inputs: bytes        # JSON-encoded public inputs
    input_hash: bytes           # SHA-256 of model input
    output_hash: bytes          # SHA-256 of model output
    verification_key_id: bytes  # SHA-256 of verification key


def from_proof_artifacts(artifacts: dict) -> ZKOutput:
    """Parse sample_proof.json -> ZKOutput."""
    proof_hex = artifacts["proof_hex"]
    proof_bytes = bytes.fromhex(proof_hex.removeprefix("0x"))
    public_inputs = json.dumps(
        artifacts["public_inputs"], separators=(",", ":")
    ).encode()

    return ZKOutput(
        proof=proof_bytes,
        public_inputs=public_inputs,
        input_hash=bytes.fromhex(artifacts["input_hash"]),
        output_hash=bytes.fromhex(artifacts["output_hash"]),
        verification_key_id=bytes.fromhex(artifacts["verification_key_id"]),
    )


def wrap(
    zk_output: ZKOutput,
    model_id: bytes = b"",
    original_price: int = 0,
    currency: str = "USD-cents",
    royalty_terms: RoyaltyTerms | None = None,
    parent_receipts: list | None = None,
    provenance_depth: int = 0,
) -> Receipt:
    """ZKOutput -> Receipt with proving_backend='ezkl-halo2'."""
    if royalty_terms is None:
        royalty_terms = RoyaltyTerms(provider_royalty=500)

    return Receipt(
        model_id=model_id,
        verification_key_id=zk_output.verification_key_id,
        input_hash=zk_output.input_hash,
        output_hash=zk_output.output_hash,
        proof=zk_output.proof,
        public_inputs=zk_output.public_inputs,
        proving_backend="ezkl-halo2",
        original_price=original_price,
        currency=currency,
        royalty_terms=royalty_terms,
        parent_receipts=parent_receipts or [],
        provenance_depth=provenance_depth,
    )


def verify_proof(proof_path: str, settings_path: str,
                 vk_path: str, srs_path: str) -> bool:
    """Verify an ezkl proof against circuit artifacts on disk.

    Requires ezkl installed. This is the mathematical verification —
    the proof is unforgeable by the soundness property of Halo2.
    """
    import ezkl
    return ezkl.verify(proof_path, settings_path, vk_path, srs_path,
                       reduced_srs=False)
