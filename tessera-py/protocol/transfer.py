# transfer — ownership tracking and double-sell prevention
#
# VCRs are immutable after signing. ownership changes tracked here.
# in-memory for the poc, transparency logs for production.

from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


@dataclass
class RoyaltyPayment:
    recipient: bytes        # bytes32
    amount: int             # uint64
    receipt_id: bytes       # bytes32 — which VCR in the chain they hold

    def canonical_bytes(self) -> bytes:
        return (
            _encode_field(self.recipient)
            + _encode_field(struct.pack(">Q", self.amount))
            + _encode_field(self.receipt_id)
        )


@dataclass
class TransferRecord:
    receipt_id: bytes
    from_key: bytes
    to_key: bytes
    price: int
    currency: str
    timestamp: int = field(default_factory=lambda: int(time.time()))
    royalties_paid: list[RoyaltyPayment] = field(default_factory=list)
    seller_signature: bytes = b""

    def canonical_bytes(self) -> bytes:
        parts = [
            _encode_field(self.receipt_id),
            _encode_field(self.from_key),
            _encode_field(self.to_key),
            _encode_field(struct.pack(">Q", self.price)),
            _encode_field(self.currency.encode("utf-8")),
            _encode_field(struct.pack(">Q", self.timestamp)),
        ]
        parts.append(struct.pack(">I", len(self.royalties_paid)))
        for rp in self.royalties_paid:
            parts.append(rp.canonical_bytes())
        return b"".join(parts)

    @property
    def transfer_hash(self) -> bytes:
        return hashlib.sha256(self.canonical_bytes()).digest()

    def sign(self, seller_key: Ed25519PrivateKey) -> None:
        self.from_key = seller_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self.seller_signature = seller_key.sign(self.transfer_hash)

    def verify_signature(self) -> bool:
        if not self.seller_signature or not self.from_key:
            return False
        try:
            pubkey = Ed25519PublicKey.from_public_bytes(self.from_key)
            pubkey.verify(self.seller_signature, self.transfer_hash)
            return True
        except Exception:
            return False


@dataclass
class TransferLedger:
    ownership: dict[str, str] = field(default_factory=dict)   # receipt_id_hex -> owner_pubkey_hex
    history: list[TransferRecord] = field(default_factory=list)

    def register(self, receipt_id: bytes, owner_pubkey: bytes) -> None:
        rid = receipt_id.hex()
        if rid in self.ownership:
            raise ValueError(f"Receipt {rid[:16]}... already registered")
        self.ownership[rid] = owner_pubkey.hex()

    def current_owner(self, receipt_id: bytes) -> str | None:
        return self.ownership.get(receipt_id.hex())

    def is_owner(self, receipt_id: bytes, pubkey: bytes) -> bool:
        return self.current_owner(receipt_id) == pubkey.hex()

    def transfer(self, record: TransferRecord) -> None:
        rid = record.receipt_id.hex()

        if rid not in self.ownership:
            raise ValueError(f"Receipt {rid[:16]}... not registered")

        if self.ownership[rid] != record.from_key.hex():
            raise ValueError(
                f"Seller {record.from_key.hex()[:16]}... is not current owner "
                f"(owner: {self.ownership[rid][:16]}...)"
            )

        if not record.verify_signature():
            raise ValueError("Transfer record signature invalid")

        self.ownership[rid] = record.to_key.hex()
        self.history.append(record)

    def transfer_count(self, receipt_id: bytes) -> int:
        rid = receipt_id.hex()
        return sum(1 for r in self.history if r.receipt_id.hex() == rid)


def _encode_field(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data
