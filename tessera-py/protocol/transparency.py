# transparency — append-only Merkle tree for ownership tracking
#
# solves double-spend without blockchain. modeled on Certificate
# Transparency (RFC 6962) but applied to compute receipts.
#
# multiple independent logs. transfers published to a threshold.
# merkle inclusion proofs for O(log n) verification.
# cross-log auditing catches conflicting transfers.
#
# no mining. no tokens. no gas. no consensus protocol.
# just append-only data structures with cryptographic integrity.

from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass, field

from .transfer import TransferRecord


def _hash_leaf(data: bytes) -> bytes:
    """Hash a leaf node: H(0x00 || data)."""
    return hashlib.sha256(b"\x00" + data).digest()


def _hash_pair(left: bytes, right: bytes) -> bytes:
    """Hash an internal node: H(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


@dataclass
class InclusionProof:
    """Merkle proof that an entry exists at a given index in a log."""
    index: int
    leaf_hash: bytes
    path: list[tuple[bytes, str]]  # (sibling_hash, "left" or "right")
    root: bytes
    log_size: int

    def verify(self) -> bool:
        """Recompute the root from the leaf and path, check it matches."""
        current = self.leaf_hash
        for sibling, direction in self.path:
            if direction == "left":
                current = _hash_pair(sibling, current)
            else:
                current = _hash_pair(current, sibling)
        return current == self.root


@dataclass
class LogEntry:
    """A single entry in a transparency log."""
    transfer: TransferRecord
    timestamp: int = field(default_factory=lambda: int(time.time()))
    index: int = 0

    @property
    def entry_bytes(self) -> bytes:
        return (
            self.transfer.canonical_bytes()
            + struct.pack(">Q", self.timestamp)
        )


@dataclass
class TransparencyLog:
    """Append-only Merkle tree of transfer records.

    Each log is operated independently. In production, multiple
    independent parties run logs. Transfers are published to a
    threshold (e.g. 3-of-5) before considered confirmed.
    """
    entries: list[LogEntry] = field(default_factory=list)
    leaves: list[bytes] = field(default_factory=list)
    # receipt_id_hex -> entry index (for double-spend detection)
    ownership: dict[str, int] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return len(self.entries)

    @property
    def root(self) -> bytes:
        """Compute the Merkle root of all entries."""
        if not self.leaves:
            return hashlib.sha256(b"empty").digest()
        return self._compute_root(self.leaves)

    def append(self, transfer: TransferRecord) -> LogEntry:
        """Append a transfer record. Returns the log entry.

        Raises ValueError if this receipt has already been transferred
        in this log (double-spend detection).
        """
        rid = transfer.receipt_id.hex()

        # double-spend check: has this receipt already been transferred?
        if rid in self.ownership:
            existing = self.entries[self.ownership[rid]]
            if existing.transfer.to_key.hex() != transfer.from_key.hex():
                raise ValueError(
                    f"Double-spend detected: receipt {rid[:16]}... "
                    f"already transferred to {existing.transfer.to_key.hex()[:16]}..."
                )

        # verify transfer signature before accepting
        if not transfer.verify_signature():
            raise ValueError("Transfer signature invalid — rejected by log")

        entry = LogEntry(
            transfer=transfer,
            index=len(self.entries),
        )
        self.entries.append(entry)

        leaf = _hash_leaf(entry.entry_bytes)
        self.leaves.append(leaf)

        # update ownership index
        self.ownership[rid] = entry.index

        return entry

    def prove_inclusion(self, index: int) -> InclusionProof:
        """Generate a Merkle inclusion proof for entry at index."""
        if index < 0 or index >= len(self.leaves):
            raise ValueError(f"Index {index} out of range (log has {len(self.leaves)} entries)")

        path = self._build_path(self.leaves, index)

        return InclusionProof(
            index=index,
            leaf_hash=self.leaves[index],
            path=path,
            root=self.root,
            log_size=len(self.leaves),
        )

    def current_owner(self, receipt_id: bytes) -> bytes | None:
        """Look up current owner of a receipt from the log."""
        rid = receipt_id.hex()
        if rid not in self.ownership:
            return None
        entry = self.entries[self.ownership[rid]]
        return entry.transfer.to_key

    def get_transfer(self, receipt_id: bytes) -> TransferRecord | None:
        """Get the most recent transfer record for a receipt."""
        rid = receipt_id.hex()
        if rid not in self.ownership:
            return None
        return self.entries[self.ownership[rid]].transfer

    def _compute_root(self, leaves: list[bytes]) -> bytes:
        """Compute Merkle root from leaves."""
        if len(leaves) == 0:
            return hashlib.sha256(b"empty").digest()
        if len(leaves) == 1:
            return leaves[0]

        # pad to even
        layer = list(leaves)
        if len(layer) % 2 == 1:
            layer.append(layer[-1])

        while len(layer) > 1:
            next_layer = []
            for i in range(0, len(layer), 2):
                next_layer.append(_hash_pair(layer[i], layer[i + 1]))
            layer = next_layer
            if len(layer) > 1 and len(layer) % 2 == 1:
                layer.append(layer[-1])

        return layer[0]

    def _build_path(self, leaves: list[bytes], index: int) -> list[tuple[bytes, str]]:
        """Build Merkle proof path for a leaf at index."""
        path = []
        layer = list(leaves)
        idx = index

        while len(layer) > 1:
            if len(layer) % 2 == 1:
                layer.append(layer[-1])

            if idx % 2 == 0:
                sibling = layer[idx + 1]
                path.append((sibling, "right"))
            else:
                sibling = layer[idx - 1]
                path.append((sibling, "left"))

            # move to next layer
            next_layer = []
            for i in range(0, len(layer), 2):
                next_layer.append(_hash_pair(layer[i], layer[i + 1]))
            layer = next_layer
            idx = idx // 2

        return path


@dataclass
class LogNetwork:
    """A network of independent transparency logs.

    Transfers must be confirmed by a threshold of logs before
    considered final. Cross-log auditing detects inconsistencies.
    """
    logs: dict[str, TransparencyLog] = field(default_factory=dict)
    threshold: int = 1  # minimum logs that must confirm a transfer

    def add_log(self, name: str) -> TransparencyLog:
        """Register a new independent log operator."""
        log = TransparencyLog()
        self.logs[name] = log
        return log

    def submit_transfer(self, transfer: TransferRecord) -> dict[str, LogEntry]:
        """Submit a transfer to all logs. Returns entries from each.

        Raises ValueError if any log rejects (double-spend).
        """
        results = {}
        errors = []

        for name, log in self.logs.items():
            try:
                entry = log.append(transfer)
                results[name] = entry
            except ValueError as e:
                errors.append((name, str(e)))

        if errors:
            # roll back successful appends if threshold not met
            if len(results) < self.threshold:
                raise ValueError(
                    f"Transfer rejected by {len(errors)} log(s): "
                    + "; ".join(f"{n}: {e}" for n, e in errors)
                )

        if len(results) < self.threshold:
            raise ValueError(
                f"Only {len(results)} logs confirmed, need {self.threshold}"
            )

        return results

    def verify_transfer(self, receipt_id: bytes) -> dict[str, InclusionProof]:
        """Get inclusion proofs from all logs that have this transfer."""
        proofs = {}
        for name, log in self.logs.items():
            rid = receipt_id.hex()
            if rid in log.ownership:
                proof = log.prove_inclusion(log.ownership[rid])
                proofs[name] = proof
        return proofs

    def check_consistency(self, receipt_id: bytes) -> tuple[bool, str]:
        """Check if all logs agree on the current owner of a receipt.

        Returns (consistent, message).
        """
        owners = {}
        for name, log in self.logs.items():
            owner = log.current_owner(receipt_id)
            if owner is not None:
                owners[name] = owner.hex()

        if not owners:
            return True, "Receipt not found in any log"

        unique_owners = set(owners.values())
        if len(unique_owners) == 1:
            return True, f"All {len(owners)} logs agree on owner"
        else:
            return False, (
                f"INCONSISTENCY: {len(unique_owners)} different owners across "
                f"{len(owners)} logs — possible double-spend"
            )
