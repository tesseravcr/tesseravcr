# tee_backend — bridge between TEE attestation and VCR receipts
#
# takes the raw output from a nitro enclave (attestation hex, hashes)
# and produces a proper Receipt that plugs into the rest of the protocol:
# stake, registry, settlement, transfer.
#
# this is the two-function backend abstraction described in the whitepaper:
#   wrap()   — TEE output -> Receipt
#   verify() — Receipt -> bool

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .receipt import Receipt, RoyaltyTerms


@dataclass
class TEEOutput:
    output_text: str
    input_hash: bytes       # SHA-256 of prompt
    output_hash: bytes      # SHA-256 of output
    attestation: bytes      # raw COSE Sign1 document


def from_enclave_response(response: dict) -> TEEOutput:
    return TEEOutput(
        output_text=response["output"],
        input_hash=bytes.fromhex(response["input_hash"]),
        output_hash=bytes.fromhex(response["output_hash"]),
        attestation=bytes.fromhex(response["attestation"]),
    )


def wrap(
    tee_output: TEEOutput,
    model_id: bytes = b"",
    original_price: int = 0,
    currency: str = "USD-cents",
    royalty_terms: RoyaltyTerms | None = None,
    parent_receipts: list | None = None,
    provenance_depth: int = 0,
) -> Receipt:
    if royalty_terms is None:
        royalty_terms = RoyaltyTerms(provider_royalty=500)

    return Receipt(
        model_id=model_id,
        input_hash=tee_output.input_hash,
        output_hash=tee_output.output_hash,
        proof=tee_output.attestation,
        proving_backend="tee-nitro-v1",
        original_price=original_price,
        currency=currency,
        royalty_terms=royalty_terms,
        parent_receipts=parent_receipts or [],
        provenance_depth=provenance_depth,
        output_data=tee_output.output_text.encode("utf-8"),
    )


def verify_output_binding(receipt: Receipt) -> bool:
    if not receipt.output_data:
        return False
    expected = hashlib.sha256(receipt.output_data).digest()
    return expected == receipt.output_hash


def verify_input_binding(receipt: Receipt, prompt: str) -> bool:
    expected = hashlib.sha256(prompt.encode("utf-8")).digest()
    return expected == receipt.input_hash
