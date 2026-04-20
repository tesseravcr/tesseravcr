//! Append-only Merkle tree primitives.
//!
//! Implements Sections 11.1 and 11.2 of VCR-SPEC.md.
//! Domain-separated hashing per RFC 6962 (Certificate Transparency).
//! Byte-identical output to the Python reference `merkle.py`.

use sha2::{Digest, Sha256};

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// Direction of a sibling in an inclusion proof step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Direction {
    Left,
    Right,
}

/// One step in a Merkle inclusion proof.
#[derive(Clone, Debug)]
pub struct ProofStep {
    pub sibling: [u8; 32],
    pub direction: Direction,
}

/// Complete Merkle inclusion proof (Section 11.2).
#[derive(Clone, Debug)]
pub struct InclusionProof {
    pub index: u64,
    pub leaf_hash: [u8; 32],
    pub path: Vec<ProofStep>,
    pub root: [u8; 32],
    pub log_size: u64,
}

/// `H(0x00 || data)` — leaf hashing with domain separation (Section 11.1).
pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(data);
    hasher.finalize().into()
}

/// `H(0x01 || left || right)` — internal node hashing (Section 11.1).
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Compute Merkle root from leaf hashes.
///
/// Odd nodes are duplicated at every level. Empty tree returns `H("empty")`.
pub fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return Sha256::digest(b"empty").into();
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    if layer.len() % 2 == 1 {
        let last = *layer.last().unwrap();
        layer.push(last);
    }

    while layer.len() > 1 {
        let mut next_layer = Vec::with_capacity((layer.len() + 1) / 2);
        for pair in layer.chunks_exact(2) {
            next_layer.push(hash_pair(&pair[0], &pair[1]));
        }
        layer = next_layer;
        if layer.len() > 1 && layer.len() % 2 == 1 {
            let last = *layer.last().unwrap();
            layer.push(last);
        }
    }

    layer[0]
}

/// Build an inclusion proof for the leaf at `index` (Section 11.2).
///
/// Returns `None` if `index` is out of range.
pub fn build_proof(leaves: &[[u8; 32]], index: usize) -> Option<Vec<ProofStep>> {
    if index >= leaves.len() {
        return None;
    }

    let mut path = Vec::new();
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    let mut idx = index;

    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            let last = *layer.last().unwrap();
            layer.push(last);
        }

        if idx % 2 == 0 {
            path.push(ProofStep {
                sibling: layer[idx + 1],
                direction: Direction::Right,
            });
        } else {
            path.push(ProofStep {
                sibling: layer[idx - 1],
                direction: Direction::Left,
            });
        }

        let mut next_layer = Vec::with_capacity((layer.len() + 1) / 2);
        for pair in layer.chunks_exact(2) {
            next_layer.push(hash_pair(&pair[0], &pair[1]));
        }
        layer = next_layer;
        idx /= 2;
    }

    Some(path)
}

/// Verify a Merkle inclusion proof (Section 11.2).
pub fn verify_proof(leaf_hash: &[u8; 32], path: &[ProofStep], root: &[u8; 32]) -> bool {
    let mut current = *leaf_hash;
    for step in path {
        current = match step.direction {
            Direction::Left => hash_pair(&step.sibling, &current),
            Direction::Right => hash_pair(&current, &step.sibling),
        };
    }
    current == *root
}

/// Construct entry bytes: `canonical_bytes || BE64(log_timestamp)`.
pub fn entry_bytes(transfer_canonical: &[u8], log_timestamp: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(transfer_canonical.len() + 8);
    out.extend_from_slice(transfer_canonical);
    out.extend_from_slice(&log_timestamp.to_be_bytes());
    out
}
