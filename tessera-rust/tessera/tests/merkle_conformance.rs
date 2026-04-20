//! Merkle tree conformance tests.
//!
//! Verifies byte-for-byte match between Rust `merkle.rs` and the Python
//! reference `merkle.py`, using test vectors from spec/TEST-VECTORS.json.

use serde_json::Value;
use std::fs;

use tessera::merkle;

fn load_vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/TEST-VECTORS.json");
    let data = fs::read_to_string(path).expect("Failed to read TEST-VECTORS.json");
    serde_json::from_str(&data).expect("Failed to parse TEST-VECTORS.json")
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    hex::decode(s).expect("invalid hex")
}

fn hex_to_32(s: &str) -> [u8; 32] {
    let bytes = hex_to_bytes(s);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr
}

// ── hash_leaf ─────────────────────────────────────────────────

#[test]
fn hash_leaf_matches_python() {
    let vectors = load_vectors();
    let cases = vectors["vectors"]["merkle"]["hash_leaf"]["cases"]
        .as_array()
        .unwrap();

    for (i, case) in cases.iter().enumerate() {
        let input = hex_to_bytes(case["input_hex"].as_str().unwrap());
        let expected = hex_to_32(case["expected_hex"].as_str().unwrap());
        let got = merkle::hash_leaf(&input);
        assert_eq!(
            got, expected,
            "hash_leaf case {}: input_hex={}",
            i,
            case["input_hex"].as_str().unwrap()
        );
    }
}

// ── hash_pair ─────────────────────────────────────────────────

#[test]
fn hash_pair_matches_python() {
    let vectors = load_vectors();
    let cases = vectors["vectors"]["merkle"]["hash_pair"]["cases"]
        .as_array()
        .unwrap();

    for (i, case) in cases.iter().enumerate() {
        let left = hex_to_32(case["left_hex"].as_str().unwrap());
        let right = hex_to_32(case["right_hex"].as_str().unwrap());
        let expected = hex_to_32(case["expected_hex"].as_str().unwrap());
        let got = merkle::hash_pair(&left, &right);
        assert_eq!(got, expected, "hash_pair case {}", i);
    }
}

#[test]
fn hash_pair_not_commutative() {
    let vectors = load_vectors();
    let cases = vectors["vectors"]["merkle"]["hash_pair"]["cases"]
        .as_array()
        .unwrap();

    // cases[0] and cases[1] have swapped left/right with different results
    let result_0 = hex_to_32(cases[0]["expected_hex"].as_str().unwrap());
    let result_1 = hex_to_32(cases[1]["expected_hex"].as_str().unwrap());
    assert_ne!(result_0, result_1, "hash_pair should not be commutative");
}

// ── compute_root ──────────────────────────────────────────────

#[test]
fn compute_root_empty_tree() {
    let vectors = load_vectors();
    let case = &vectors["vectors"]["merkle"]["compute_root"]["cases"][0];
    assert_eq!(case["leaf_count"].as_u64().unwrap(), 0);

    let expected = hex_to_32(case["expected_root_hex"].as_str().unwrap());
    let got = merkle::compute_root(&[]);
    assert_eq!(got, expected, "empty tree root should be H(\"empty\")");
}

#[test]
fn compute_root_single_leaf() {
    let vectors = load_vectors();
    let case = &vectors["vectors"]["merkle"]["compute_root"]["cases"][1];
    assert_eq!(case["leaf_count"].as_u64().unwrap(), 1);

    let leaves: Vec<[u8; 32]> = case["leaf_hashes_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| hex_to_32(h.as_str().unwrap()))
        .collect();
    let expected = hex_to_32(case["expected_root_hex"].as_str().unwrap());
    let got = merkle::compute_root(&leaves);
    assert_eq!(got, expected, "single leaf should be root");
}

#[test]
fn compute_root_all_sizes() {
    let vectors = load_vectors();
    let cases = vectors["vectors"]["merkle"]["compute_root"]["cases"]
        .as_array()
        .unwrap();

    for (i, case) in cases.iter().enumerate() {
        let leaves: Vec<[u8; 32]> = case["leaf_hashes_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| hex_to_32(h.as_str().unwrap()))
            .collect();
        let expected = hex_to_32(case["expected_root_hex"].as_str().unwrap());
        let got = merkle::compute_root(&leaves);
        assert_eq!(
            got, expected,
            "compute_root case {} (leaf_count={})",
            i,
            case["leaf_count"].as_u64().unwrap()
        );
    }
}

// ── build_proof + verify_proof ────────────────────────────────

#[test]
fn inclusion_proof_roundtrip_all_cases() {
    let vectors = load_vectors();
    let cases = vectors["vectors"]["merkle"]["inclusion_proofs"]["cases"]
        .as_array()
        .unwrap();

    for (i, case) in cases.iter().enumerate() {
        let root = hex_to_32(case["root_hex"].as_str().unwrap());
        let index = case["index"].as_u64().unwrap() as usize;
        let leaf_hash = hex_to_32(case["leaf_hash_hex"].as_str().unwrap());

        // Reconstruct expected path from vectors
        let expected_path: Vec<(String, [u8; 32])> = case["path"]
            .as_array()
            .unwrap()
            .iter()
            .map(|step| {
                let dir = step["direction"].as_str().unwrap().to_string();
                let sib = hex_to_32(step["sibling_hex"].as_str().unwrap());
                (dir, sib)
            })
            .collect();

        // Verify the proof from vectors verifies correctly
        let proof_steps: Vec<merkle::ProofStep> = expected_path
            .iter()
            .map(|(dir, sib)| merkle::ProofStep {
                sibling: *sib,
                direction: match dir.as_str() {
                    "left" => merkle::Direction::Left,
                    "right" => merkle::Direction::Right,
                    _ => panic!("unknown direction"),
                },
            })
            .collect();

        assert!(
            merkle::verify_proof(&leaf_hash, &proof_steps, &root),
            "verify_proof failed for case {} (index={}, leaf_count={})",
            i,
            index,
            case["leaf_count"].as_u64().unwrap()
        );
    }
}

#[test]
fn build_proof_matches_python_vectors() {
    let vectors = load_vectors();
    let cases = vectors["vectors"]["merkle"]["inclusion_proofs"]["cases"]
        .as_array()
        .unwrap();

    for (i, case) in cases.iter().enumerate() {
        let leaf_count = case["leaf_count"].as_u64().unwrap() as usize;
        let index = case["index"].as_u64().unwrap() as usize;

        // We need the actual leaf hashes to call build_proof.
        // The compute_root vectors have the leaf hashes for each size.
        let root_cases = vectors["vectors"]["merkle"]["compute_root"]["cases"]
            .as_array()
            .unwrap();
        let root_case = root_cases
            .iter()
            .find(|c| c["leaf_count"].as_u64().unwrap() as usize == leaf_count)
            .unwrap();

        let leaves: Vec<[u8; 32]> = root_case["leaf_hashes_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| hex_to_32(h.as_str().unwrap()))
            .collect();

        let proof = merkle::build_proof(&leaves, index)
            .unwrap_or_else(|| panic!("build_proof returned None for case {}", i));

        let expected_path = case["path"].as_array().unwrap();
        assert_eq!(
            proof.len(),
            expected_path.len(),
            "proof length mismatch for case {} (index={}, leaf_count={})",
            i,
            index,
            leaf_count
        );

        for (j, (step, expected)) in proof.iter().zip(expected_path.iter()).enumerate() {
            let expected_sib = hex_to_32(expected["sibling_hex"].as_str().unwrap());
            let expected_dir = expected["direction"].as_str().unwrap();

            assert_eq!(
                step.sibling, expected_sib,
                "case {} step {}: sibling mismatch",
                i, j
            );
            let got_dir = match step.direction {
                merkle::Direction::Left => "left",
                merkle::Direction::Right => "right",
            };
            assert_eq!(
                got_dir, expected_dir,
                "case {} step {}: direction mismatch",
                i, j
            );
        }
    }
}

#[test]
fn build_proof_out_of_range_returns_none() {
    let leaf = merkle::hash_leaf(b"test");
    assert!(merkle::build_proof(&[leaf], 1).is_none());
    assert!(merkle::build_proof(&[], 0).is_none());
}

#[test]
fn verify_proof_wrong_root_fails() {
    let vectors = load_vectors();
    let case = &vectors["vectors"]["merkle"]["inclusion_proofs"]["cases"][0];
    let leaf_hash = hex_to_32(case["leaf_hash_hex"].as_str().unwrap());

    let proof_steps: Vec<merkle::ProofStep> = case["path"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| merkle::ProofStep {
            sibling: hex_to_32(step["sibling_hex"].as_str().unwrap()),
            direction: match step["direction"].as_str().unwrap() {
                "left" => merkle::Direction::Left,
                "right" => merkle::Direction::Right,
                _ => panic!("unknown direction"),
            },
        })
        .collect();

    let wrong_root = [0xffu8; 32];
    assert!(
        !merkle::verify_proof(&leaf_hash, &proof_steps, &wrong_root),
        "verify_proof should fail with wrong root"
    );
}

#[test]
fn verify_proof_wrong_leaf_fails() {
    let vectors = load_vectors();
    let case = &vectors["vectors"]["merkle"]["inclusion_proofs"]["cases"][0];
    let root = hex_to_32(case["root_hex"].as_str().unwrap());

    let proof_steps: Vec<merkle::ProofStep> = case["path"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| merkle::ProofStep {
            sibling: hex_to_32(step["sibling_hex"].as_str().unwrap()),
            direction: match step["direction"].as_str().unwrap() {
                "left" => merkle::Direction::Left,
                "right" => merkle::Direction::Right,
                _ => panic!("unknown direction"),
            },
        })
        .collect();

    let wrong_leaf = [0xaau8; 32];
    assert!(
        !merkle::verify_proof(&wrong_leaf, &proof_steps, &root),
        "verify_proof should fail with wrong leaf"
    );
}

// ── entry_bytes ───────────────────────────────────────────────

#[test]
fn entry_bytes_matches_python() {
    let vectors = load_vectors();
    let case = &vectors["vectors"]["merkle"]["entry_bytes"]["cases"][0];

    let transfer_canonical = hex_to_bytes(case["transfer_canonical_hex"].as_str().unwrap());
    let log_ts = case["log_timestamp"].as_u64().unwrap();

    let entry = merkle::entry_bytes(&transfer_canonical, log_ts);
    let expected_entry = hex_to_bytes(case["entry_bytes_hex"].as_str().unwrap());
    assert_eq!(entry, expected_entry, "entry_bytes mismatch");

    let leaf = merkle::hash_leaf(&entry);
    let expected_leaf = hex_to_32(case["leaf_hash_hex"].as_str().unwrap());
    assert_eq!(leaf, expected_leaf, "entry leaf_hash mismatch");
}

// ── build_proof + compute_root consistency ────────────────────

#[test]
fn proof_verifies_against_computed_root() {
    // Build a tree from scratch and verify every proof against computed root
    let data: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d", b"e", b"f", b"g"];
    let leaves: Vec<[u8; 32]> = data.iter().map(|d| merkle::hash_leaf(d)).collect();
    let root = merkle::compute_root(&leaves);

    for i in 0..leaves.len() {
        let proof = merkle::build_proof(&leaves, i).unwrap();
        assert!(
            merkle::verify_proof(&leaves[i], &proof, &root),
            "proof failed for index {} in 7-leaf tree",
            i
        );
    }
}
