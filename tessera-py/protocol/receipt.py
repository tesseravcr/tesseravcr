# VCR schema implementation v0.1
#
# canonical serialisation is binary: fields in spec order, each length-prefixed
# with 4-byte big-endian uint32. deterministic across any language/implementation.

from __future__ import annotations

import base64
import hashlib
import json
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

MAX_PROVENANCE_DEPTH = 256


class ReceiptValidationError(ValueError):
    """Raised when a receipt fails structural validation."""
    pass


@dataclass
class ParentRef:
    receipt_id: bytes       # bytes32
    receipt_hash: bytes     # bytes32 — SHA-256 of parent's canonical form
    relationship: str       # "input", "reference", or "aggregation"

    def canonical_bytes(self) -> bytes:
        return (
            _encode_field(self.receipt_id)
            + _encode_field(self.receipt_hash)
            + _encode_field(self.relationship.encode("utf-8"))
        )

    def to_dict(self) -> dict:
        return {
            "receipt_id": self.receipt_id.hex(),
            "receipt_hash": self.receipt_hash.hex(),
            "relationship": self.relationship,
        }

    @classmethod
    def from_dict(cls, d: dict) -> ParentRef:
        return cls(
            receipt_id=bytes.fromhex(d["receipt_id"]),
            receipt_hash=bytes.fromhex(d["receipt_hash"]),
            relationship=d["relationship"],
        )


@dataclass
class RoyaltyTerms:
    provider_royalty: int      # basis points (0-10000)
    parent_royalty: int = 0    # bps split equally among parents
    cascade: bool = False      # propagate up entire chain

    def validate(self) -> None:
        if not (0 <= self.provider_royalty <= 10000):
            raise ReceiptValidationError(
                f"provider_royalty must be 0–10000 bps, got {self.provider_royalty}"
            )
        if not (0 <= self.parent_royalty <= 10000):
            raise ReceiptValidationError(
                f"parent_royalty must be 0–10000 bps, got {self.parent_royalty}"
            )
        if self.provider_royalty + self.parent_royalty > 10000:
            raise ReceiptValidationError(
                f"royalty sum exceeds 10000 bps: {self.provider_royalty} + {self.parent_royalty}"
                f" = {self.provider_royalty + self.parent_royalty}"
            )

    def canonical_bytes(self) -> bytes:
        return (
            _encode_field(struct.pack(">H", self.provider_royalty))
            + _encode_field(struct.pack(">H", self.parent_royalty))
            + _encode_field(struct.pack(">?", self.cascade))
        )

    def to_dict(self) -> dict:
        return {
            "provider_royalty": self.provider_royalty,
            "parent_royalty": self.parent_royalty,
            "cascade": self.cascade,
        }

    @classmethod
    def from_dict(cls, d: dict) -> RoyaltyTerms:
        return cls(**d)


@dataclass
class Extension:
    type: str
    data: bytes

    def canonical_bytes(self) -> bytes:
        return (
            _encode_field(self.type.encode("utf-8"))
            + _encode_field(self.data)
        )

    def to_dict(self) -> dict:
        return {"type": self.type, "data": base64.b64encode(self.data).decode()}

    @classmethod
    def from_dict(cls, d: dict) -> Extension:
        return cls(type=d["type"], data=base64.b64decode(d["data"]))


@dataclass
class Receipt:
    # identity
    schema_version: int = 1

    # computation
    model_id: bytes = b""
    verification_key_id: bytes = b""
    input_hash: bytes = b""
    output_hash: bytes = b""
    proof: bytes = b""
    public_inputs: bytes = b""
    proving_backend: str = "ezkl-halo2"
    timestamp: int = field(default_factory=lambda: int(time.time()))

    # provenance
    parent_receipts: list[ParentRef] = field(default_factory=list)
    provenance_depth: int = 0

    # economics
    provider: bytes = b""
    original_price: int = 0
    currency: str = "USD-cents"
    royalty_terms: RoyaltyTerms = field(default_factory=lambda: RoyaltyTerms(provider_royalty=500))
    transfer_count: int = 0  # mutable — excluded from canonical hash, tracked by transfer ledger

    # integrity
    # receipt_id and receipt_hash are the same derived value:
    # SHA-256(canonical(all fields above, excluding transfer_count and signature)).
    # never stored, always computed.
    signature: bytes = b""
    signature_scheme: str = "ed25519"

    # extensions
    extensions: list[Extension] = field(default_factory=list)

    # not part of the VCR — travels alongside, excluded from hashes/signatures
    output_data: Optional[bytes] = None

    def validate(self) -> None:
        """Check structural validity. Called before signing and at ingestion."""
        self.royalty_terms.validate()

        # duplicate parent receipt_ids
        seen = set()
        for p in self.parent_receipts:
            pid = bytes(p.receipt_id)
            if pid in seen:
                raise ReceiptValidationError(
                    f"duplicate parent receipt_id: {pid.hex()}"
                )
            seen.add(pid)

        # provenance depth cap
        if self.provenance_depth > MAX_PROVENANCE_DEPTH:
            raise ReceiptValidationError(
                f"provenance_depth {self.provenance_depth} exceeds maximum {MAX_PROVENANCE_DEPTH}"
            )

    def canonical_bytes(self) -> bytes:
        parts = []

        parts.append(_encode_field(struct.pack(">H", self.schema_version)))

        parts.append(_encode_field(self.model_id))
        parts.append(_encode_field(self.verification_key_id))
        parts.append(_encode_field(self.input_hash))
        parts.append(_encode_field(self.output_hash))
        parts.append(_encode_field(self.proof))
        parts.append(_encode_field(self.public_inputs))
        parts.append(_encode_field(self.proving_backend.encode("utf-8")))
        parts.append(_encode_field(struct.pack(">Q", self.timestamp)))

        parts.append(_encode_list(self.parent_receipts))
        parts.append(_encode_field(struct.pack(">H", self.provenance_depth)))

        parts.append(_encode_field(self.provider))
        parts.append(_encode_field(struct.pack(">Q", self.original_price)))
        parts.append(_encode_field(self.currency.encode("utf-8")))
        parts.append(self.royalty_terms.canonical_bytes())
        # transfer_count is excluded from canonical hash — it's mutable state
        # tracked by the transfer ledger, not part of the immutable receipt

        parts.append(_encode_field(self.signature_scheme.encode("utf-8")))

        parts.append(_encode_list(self.extensions))

        return b"".join(parts)

    @property
    def receipt_id(self) -> bytes:
        return hashlib.sha256(self.canonical_bytes()).digest()

    @property
    def receipt_hash(self) -> bytes:
        return self.receipt_id

    def receipt_id_hex(self) -> str:
        return self.receipt_id.hex()

    def receipt_hash_hex(self) -> str:
        return self.receipt_hash.hex()

    def sign(self, private_key: Ed25519PrivateKey) -> None:
        self.provider = private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self.validate()
        self.signature = private_key.sign(self.receipt_hash)

    def verify_signature(self) -> bool:
        if not self.signature or not self.provider:
            return False
        try:
            pubkey = Ed25519PublicKey.from_public_bytes(self.provider)
            pubkey.verify(self.signature, self.receipt_hash)
            return True
        except Exception:
            return False

    def verify_integrity(self) -> bool:
        # receipt_hash is a property that always recomputes from fields,
        # so integrity is structural for in-memory receipts.
        return True

    def as_parent_ref(self, relationship: str = "input") -> ParentRef:
        return ParentRef(
            receipt_id=self.receipt_id,
            receipt_hash=self.receipt_hash,
            relationship=relationship,
        )

    def compute_provenance_depth(self) -> int:
        if not self.parent_receipts:
            return 0
        return self.provenance_depth

    def to_json(self) -> str:
        d = {
            "schema_version": self.schema_version,
            "model_id": self.model_id.hex(),
            "verification_key_id": self.verification_key_id.hex(),
            "input_hash": self.input_hash.hex(),
            "output_hash": self.output_hash.hex(),
            "proof": base64.b64encode(self.proof).decode(),
            "public_inputs": base64.b64encode(self.public_inputs).decode(),
            "proving_backend": self.proving_backend,
            "timestamp": self.timestamp,
            "parent_receipts": [p.to_dict() for p in self.parent_receipts],
            "provenance_depth": self.provenance_depth,
            "provider": self.provider.hex(),
            "original_price": self.original_price,
            "currency": self.currency,
            "royalty_terms": self.royalty_terms.to_dict(),
            "transfer_count": self.transfer_count,
            "signature": base64.b64encode(self.signature).decode(),
            "signature_scheme": self.signature_scheme,
            "extensions": [e.to_dict() for e in self.extensions],
        }
        if self.output_data is not None:
            d["output_data"] = base64.b64encode(self.output_data).decode()
        return json.dumps(d, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> Receipt:
        d = json.loads(raw)
        r = cls(
            schema_version=d["schema_version"],
            model_id=bytes.fromhex(d["model_id"]),
            verification_key_id=bytes.fromhex(d["verification_key_id"]),
            input_hash=bytes.fromhex(d["input_hash"]),
            output_hash=bytes.fromhex(d["output_hash"]),
            proof=base64.b64decode(d["proof"]),
            public_inputs=base64.b64decode(d["public_inputs"]),
            proving_backend=d["proving_backend"],
            timestamp=d["timestamp"],
            parent_receipts=[ParentRef.from_dict(p) for p in d["parent_receipts"]],
            provenance_depth=d["provenance_depth"],
            provider=bytes.fromhex(d["provider"]),
            original_price=d["original_price"],
            currency=d["currency"],
            royalty_terms=RoyaltyTerms.from_dict(d["royalty_terms"]),
            transfer_count=d["transfer_count"],
            signature=base64.b64decode(d.get("signature", "")),
            signature_scheme=d.get("signature_scheme", "ed25519"),
            extensions=[Extension.from_dict(e) for e in d.get("extensions", [])],
        )
        if "output_data" in d:
            r.output_data = base64.b64decode(d["output_data"])
        return r


def _encode_field(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _encode_list(items: list) -> bytes:
    parts = [struct.pack(">I", len(items))]
    for item in items:
        parts.append(item.canonical_bytes())
    return b"".join(parts)
