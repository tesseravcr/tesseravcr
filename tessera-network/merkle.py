# merkle — append-only Merkle tree
#
# Standard construction per RFC 6962 (Certificate Transparency).
# Domain-separated hashing prevents second-preimage attacks.
# Nothing here is VCR-specific.

import hashlib


LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def hash_leaf(data: bytes) -> bytes:
    """H(0x00 || data)"""
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def hash_pair(left: bytes, right: bytes) -> bytes:
    """H(0x01 || left || right)"""
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def compute_root(leaves: list[bytes]) -> bytes:
    """Merkle root from leaf hashes. Odd nodes are duplicated."""
    if not leaves:
        return hashlib.sha256(b"empty").digest()
    if len(leaves) == 1:
        return leaves[0]

    layer = list(leaves)
    if len(layer) % 2 == 1:
        layer.append(layer[-1])

    while len(layer) > 1:
        next_layer = []
        for i in range(0, len(layer), 2):
            next_layer.append(hash_pair(layer[i], layer[i + 1]))
        layer = next_layer
        if len(layer) > 1 and len(layer) % 2 == 1:
            layer.append(layer[-1])

    return layer[0]


def build_proof(leaves: list[bytes], index: int) -> list[tuple[bytes, str]]:
    """Build a Merkle inclusion proof for leaf at index.

    Returns list of (sibling_hash, direction) pairs.
    Direction is "left" or "right" — the sibling's position.
    """
    if index < 0 or index >= len(leaves):
        raise ValueError(f"Index {index} out of range ({len(leaves)} leaves)")

    path = []
    layer = list(leaves)
    idx = index

    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])

        if idx % 2 == 0:
            path.append((layer[idx + 1], "right"))
        else:
            path.append((layer[idx - 1], "left"))

        next_layer = []
        for i in range(0, len(layer), 2):
            next_layer.append(hash_pair(layer[i], layer[i + 1]))
        layer = next_layer
        idx = idx // 2

    return path


def verify_proof(leaf_hash: bytes, path: list[tuple[bytes, str]], root: bytes) -> bool:
    """Verify a Merkle inclusion proof."""
    current = leaf_hash
    for sibling, direction in path:
        if direction == "left":
            current = hash_pair(sibling, current)
        else:
            current = hash_pair(current, sibling)
    return current == root
