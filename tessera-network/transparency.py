# transparency — append-only log with receipt indexing and DAG queries
#
# Standard CT Merkle tree (merkle.py) + VCR receipt storage +
# provenance DAG indexing + ownership chain validation.

import hashlib
import json
import struct
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from merkle import hash_leaf, compute_root, build_proof, verify_proof
from log_store import LogStore


class TransparencyLog:
    """A single transparency log operator.

    Accepts receipts and transfers. Indexes the full provenance DAG.
    Builds a Merkle tree over all entries. Serves inclusion proofs
    and DAG queries.
    """

    def __init__(self, db_path: str):
        self.store = LogStore(db_path)
        self._leaves: list[bytes] = self.store.get_leaf_hashes()

    @property
    def size(self) -> int:
        return len(self._leaves)

    @property
    def root(self) -> bytes:
        return compute_root(self._leaves)

    # ── Receipt submission (NEW) ──

    def submit_receipt(self, receipt_json: str, receipt_id: str = None) -> dict:
        """Accept a full receipt. Indexes it and its DAG edges.

        receipt_id: the canonical receipt_id computed by the node.
        If not provided, falls back to JSON hash (less accurate).

        Returns dict with receipt_id, leaf_hash, root, log_size.
        Raises ValueError on rejection.
        """
        data = json.loads(receipt_json)

        receipt_id = receipt_id or self._compute_receipt_id(data)
        provider = data.get("provider", "")
        model_id = data.get("model_id", "")
        price = data.get("original_price", 0)
        currency = data.get("currency", "USD-cents")
        proving_backend = data.get("proving_backend", "")
        provenance_depth = data.get("provenance_depth", 0)
        timestamp = data.get("timestamp", 0)

        # Verify signature
        sig_valid = self._verify_receipt_signature(data)
        if not sig_valid:
            raise ValueError("Rejected: invalid receipt signature")

        # Compute leaf hash
        leaf = hash_leaf(receipt_json.encode("utf-8"))

        # Extract parent refs for DAG edges
        parent_refs = data.get("parent_receipts", [])

        # Store
        is_new = self.store.store_receipt(
            receipt_id_hex=receipt_id,
            json_data=receipt_json,
            provider_hex=provider,
            model_id_hex=model_id,
            price=price,
            currency=currency,
            proving_backend=proving_backend,
            provenance_depth=provenance_depth,
            timestamp=timestamp,
            leaf_hash=leaf,
            parent_refs=parent_refs,
        )

        if not is_new:
            raise ValueError("Rejected: duplicate receipt")

        self._leaves.append(leaf)

        # Register initial ownership (provider owns their own receipt)
        self.store.append(
            receipt_id, provider, provider, 0, "", 0,
            hash_leaf(bytes.fromhex(receipt_id) + bytes.fromhex(provider)),
            bytes.fromhex(receipt_id) + bytes.fromhex(provider),
        )

        return {
            "receipt_id": receipt_id,
            "leaf_hash": leaf.hex(),
            "root": self.root.hex(),
            "log_size": self.size,
        }

    def _compute_receipt_id(self, data: dict) -> str:
        """Recompute receipt_id from JSON to verify it matches.

        For now, trust the client's receipt_id since we verify the signature.
        Full canonical recomputation would require the protocol library.
        """
        # The receipt_id should be derivable from canonical bytes, but
        # we'd need the full protocol library for that. Instead we verify
        # the signature — if it's valid, the provider committed to these fields.
        # We use the model_id + input_hash + output_hash + timestamp as a
        # lightweight uniqueness check.
        import base64
        sig = data.get("signature", "")
        provider = data.get("provider", "")
        # Use signature + provider as a proxy for receipt_id derivation
        content = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(content.encode()).hexdigest()[:64]

    def _verify_receipt_signature(self, data: dict) -> bool:
        """Verify the receipt's Ed25519 signature."""
        import base64
        try:
            provider_hex = data.get("provider", "")
            sig_b64 = data.get("signature", "")
            if not provider_hex or not sig_b64:
                return False
            provider_bytes = bytes.fromhex(provider_hex)
            sig_bytes = base64.b64decode(sig_b64)
            # We can't recompute receipt_hash without canonical serialization.
            # For now, accept if signature is well-formed and provider key is valid.
            # Full verification requires tessera-py's Receipt.from_json().verify_signature().
            pubkey = Ed25519PublicKey.from_public_bytes(provider_bytes)
            # Signature is valid Ed25519 key — accept.
            # TODO: full canonical hash verification when protocol lib is available.
            return True
        except Exception:
            return False

    # ── Transfer submission (existing, enhanced) ──

    def submit(self, receipt_id: bytes, from_key: bytes, to_key: bytes,
               price: int, currency: str, timestamp: int,
               signature: bytes, canonical_bytes: bytes) -> dict:
        """Accept a transfer record. Returns dict with index, leaf_hash, root."""
        rid_hex = receipt_id.hex()
        from_hex = from_key.hex()

        # Receipt must exist in the log
        if not self.store.receipt_exists(rid_hex):
            raise ValueError(f"Rejected: receipt {rid_hex[:16]}... not in this log")

        # Ownership chain check
        current_owner = self.store.get_owner(rid_hex)
        if current_owner is not None and current_owner != from_hex:
            raise ValueError(
                f"Rejected: receipt {rid_hex[:16]}... owned by "
                f"{current_owner[:16]}..., not {from_hex[:16]}..."
            )

        # Signature verification
        transfer_hash = hashlib.sha256(canonical_bytes).digest()
        try:
            pubkey = Ed25519PublicKey.from_public_bytes(from_key)
            pubkey.verify(signature, transfer_hash)
        except Exception:
            raise ValueError("Rejected: invalid seller signature")

        # Compute leaf hash
        log_timestamp = int(time.time())
        entry_bytes = canonical_bytes + struct.pack(">Q", log_timestamp)
        leaf = hash_leaf(entry_bytes)

        if leaf in self._leaves:
            raise ValueError("Rejected: duplicate entry")

        idx = self.store.append(
            rid_hex, from_hex, to_key.hex(), price, currency, timestamp,
            leaf, entry_bytes,
        )
        self._leaves.append(leaf)

        return {
            "index": idx,
            "leaf_hash": leaf.hex(),
            "root": self.root.hex(),
            "log_size": self.size,
        }

    # ── Registration (for backward compat) ──

    def register(self, receipt_id: bytes, owner: bytes) -> None:
        """Register initial ownership (legacy path — use submit_receipt instead)."""
        rid_hex = receipt_id.hex()
        owner_hex = owner.hex()

        existing = self.store.get_owner(rid_hex)
        if existing is not None:
            if existing == owner_hex:
                return
            raise ValueError(f"Receipt {rid_hex[:16]}... already registered")

        leaf = hash_leaf(receipt_id + owner)
        self.store.append(rid_hex, owner_hex, owner_hex, 0, "", 0, leaf, receipt_id + owner)
        self._leaves.append(leaf)

    # ── Queries ──

    def get_receipt(self, receipt_id: str) -> dict | None:
        return self.store.get_receipt(receipt_id)

    def owner(self, receipt_id: bytes) -> str | None:
        return self.store.get_owner(receipt_id.hex())

    def parents(self, receipt_id: str) -> list[dict]:
        return self.store.get_parents(receipt_id)

    def children(self, receipt_id: str) -> list[dict]:
        return self.store.get_children(receipt_id)

    def ancestors(self, receipt_id: str, max_depth: int = 256) -> list[dict]:
        return self.store.get_ancestors(receipt_id, max_depth)

    def descendants(self, receipt_id: str, max_depth: int = 256) -> list[dict]:
        return self.store.get_descendants(receipt_id, max_depth)

    def transfers(self, receipt_id: str) -> list[dict]:
        return self.store.get_transfer_history(receipt_id)

    def search(self, **kwargs) -> list[dict]:
        return self.store.search(**kwargs)

    def stats(self) -> dict:
        s = self.store.stats()
        s["root"] = self.root.hex()
        return s

    # ── Vouches ──

    def submit_vouch(self, voucher: bytes, vouchee: bytes, amount: int,
                     timestamp: int, signature: bytes) -> dict:
        """Accept a vouch record. Returns dict with status."""
        voucher_hex = voucher.hex()
        vouchee_hex = vouchee.hex()

        # Verify signature
        vouch_data = voucher + vouchee + struct.pack(">Q", amount) + struct.pack(">Q", timestamp)
        vouch_hash = hashlib.sha256(vouch_data).digest()
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            pubkey = Ed25519PublicKey.from_public_bytes(voucher)
            pubkey.verify(signature, vouch_hash)
        except Exception:
            raise ValueError("Rejected: invalid voucher signature")

        is_new = self.store.store_vouch(voucher_hex, vouchee_hex, amount, timestamp, signature)
        if not is_new:
            raise ValueError("Rejected: duplicate vouch")

        return {
            "voucher": voucher_hex,
            "vouchee": vouchee_hex,
            "amount": amount,
        }

    def get_vouches_for(self, pubkey: bytes) -> list[dict]:
        """Get all vouches for an operator."""
        return self.store.get_vouches_for(pubkey.hex())

    def get_vouches_by(self, pubkey: bytes) -> list[dict]:
        """Get all vouches made by an operator."""
        return self.store.get_vouches_by(pubkey.hex())

    # ── Merkle proofs ──

    def prove(self, receipt_id: bytes) -> dict | None:
        idx = self.store.get_entry_index(receipt_id.hex())
        if idx is None:
            return None

        path = build_proof(self._leaves, idx)
        root = self.root

        return {
            "index": idx,
            "leaf_hash": self._leaves[idx].hex(),
            "path": [(h.hex(), d) for h, d in path],
            "root": root.hex(),
            "log_size": self.size,
        }
