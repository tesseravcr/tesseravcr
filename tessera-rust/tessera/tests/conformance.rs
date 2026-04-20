//! VCR Protocol Conformance Tests
//!
//! Reads spec/TEST-VECTORS.json and verifies that this Rust implementation
//! produces identical canonical bytes and receipt_id values as the Python
//! reference implementation.

use base64::Engine;
use serde_json::Value;
use std::fs;

use tessera::receipt::{Extension, ParentRef, Receipt, RoyaltyTerms};
use tessera::transfer::{RoyaltyPayment, TransferRecord};

fn load_vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/TEST-VECTORS.json");
    let data = fs::read_to_string(path).expect("Failed to read TEST-VECTORS.json");
    serde_json::from_str(&data).expect("Failed to parse TEST-VECTORS.json")
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    hex::decode(s).expect("invalid hex")
}

fn b64_to_bytes(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("invalid base64")
}

fn build_receipt(inputs: &Value) -> Receipt {
    let parent_receipts: Vec<ParentRef> = inputs["parent_receipts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| ParentRef {
            receipt_id: hex_to_bytes(p["receipt_id"].as_str().unwrap()),
            receipt_hash: hex_to_bytes(p["receipt_hash"].as_str().unwrap()),
            relationship: p["relationship"].as_str().unwrap().to_string(),
        })
        .collect();

    Receipt {
        schema_version: inputs["schema_version"].as_u64().unwrap() as u16,
        model_id: hex_to_bytes(inputs["model_id"].as_str().unwrap()),
        verification_key_id: hex_to_bytes(inputs["verification_key_id"].as_str().unwrap()),
        input_hash: hex_to_bytes(inputs["input_hash"].as_str().unwrap()),
        output_hash: hex_to_bytes(inputs["output_hash"].as_str().unwrap()),
        proof: b64_to_bytes(inputs["proof"].as_str().unwrap()),
        public_inputs: b64_to_bytes(inputs["public_inputs"].as_str().unwrap()),
        proving_backend: inputs["proving_backend"].as_str().unwrap().to_string(),
        timestamp: inputs["timestamp"].as_u64().unwrap(),
        parent_receipts,
        provenance_depth: inputs["provenance_depth"].as_u64().unwrap() as u16,
        provider: hex_to_bytes(inputs["provider"].as_str().unwrap()),
        original_price: inputs["original_price"].as_u64().unwrap(),
        currency: inputs["currency"].as_str().unwrap().to_string(),
        royalty_terms: RoyaltyTerms {
            provider_royalty: inputs["royalty_terms"]["provider_royalty"].as_u64().unwrap() as u16,
            parent_royalty: inputs["royalty_terms"]["parent_royalty"].as_u64().unwrap() as u16,
            cascade: inputs["royalty_terms"]["cascade"].as_bool().unwrap(),
        },
        transfer_count: 0,
        signature: Vec::new(),
        signature_scheme: inputs["signature_scheme"].as_str().unwrap().to_string(),
        extensions: inputs["extensions"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|e| Extension {
                        ext_type: e["type"].as_str().unwrap().to_string(),
                        data: b64_to_bytes(e["data"].as_str().unwrap()),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

// ── Test 1: Minimal receipt canonical bytes and receipt_id ──────

#[test]
fn minimal_receipt_canonical_bytes() {
    let vectors = load_vectors();
    let v = &vectors["vectors"]["minimal_receipt"];
    let receipt = build_receipt(&v["inputs"]);

    let canonical = receipt.canonical_bytes();
    let expected_hex = v["expected"]["canonical_bytes_hex"].as_str().unwrap();
    let expected_bytes = hex_to_bytes(expected_hex);

    assert_eq!(
        canonical.len(),
        expected_bytes.len(),
        "canonical bytes length mismatch: got {}, expected {}",
        canonical.len(),
        expected_bytes.len(),
    );

    // Find first divergence for debugging
    if canonical != expected_bytes {
        for (i, (a, b)) in canonical.iter().zip(expected_bytes.iter()).enumerate() {
            if a != b {
                panic!(
                    "canonical bytes diverge at byte {}: got 0x{:02x}, expected 0x{:02x}",
                    i, a, b
                );
            }
        }
    }

    assert_eq!(canonical, expected_bytes, "canonical bytes mismatch");
}

#[test]
fn minimal_receipt_id() {
    let vectors = load_vectors();
    let v = &vectors["vectors"]["minimal_receipt"];
    let receipt = build_receipt(&v["inputs"]);

    let receipt_id = hex::encode(receipt.receipt_id());
    let expected_id = v["expected"]["receipt_id"].as_str().unwrap();

    assert_eq!(receipt_id, expected_id, "receipt_id mismatch");
}

#[test]
fn minimal_receipt_id_equals_hash() {
    let vectors = load_vectors();
    let v = &vectors["vectors"]["minimal_receipt"];
    let receipt = build_receipt(&v["inputs"]);

    assert_eq!(receipt.receipt_id(), receipt.receipt_hash());
}

// ── Test 2: Receipt with parent references ─────────────────────

#[test]
fn receipt_with_parent_canonical_bytes() {
    let vectors = load_vectors();
    let v = &vectors["vectors"]["receipt_with_parent"];
    let receipt = build_receipt(&v["inputs"]);

    let canonical = receipt.canonical_bytes();
    let expected_hex = v["expected"]["canonical_bytes_hex"].as_str().unwrap();
    let expected_bytes = hex_to_bytes(expected_hex);

    assert_eq!(
        canonical.len(),
        expected_bytes.len(),
        "canonical bytes length mismatch: got {}, expected {}",
        canonical.len(),
        expected_bytes.len(),
    );

    if canonical != expected_bytes {
        for (i, (a, b)) in canonical.iter().zip(expected_bytes.iter()).enumerate() {
            if a != b {
                panic!(
                    "canonical bytes diverge at byte {}: got 0x{:02x}, expected 0x{:02x}",
                    i, a, b
                );
            }
        }
    }

    assert_eq!(canonical, expected_bytes);
}

#[test]
fn receipt_with_parent_id() {
    let vectors = load_vectors();
    let v = &vectors["vectors"]["receipt_with_parent"];
    let receipt = build_receipt(&v["inputs"]);

    let receipt_id = hex::encode(receipt.receipt_id());
    let expected_id = v["expected"]["receipt_id"].as_str().unwrap();

    assert_eq!(receipt_id, expected_id);
}

#[test]
fn parent_ref_canonical_bytes() {
    let vectors = load_vectors();
    let v = &vectors["vectors"]["receipt_with_parent"];
    let parent = &v["inputs"]["parent_receipts"][0];

    let parent_ref = ParentRef {
        receipt_id: hex_to_bytes(parent["receipt_id"].as_str().unwrap()),
        receipt_hash: hex_to_bytes(parent["receipt_hash"].as_str().unwrap()),
        relationship: parent["relationship"].as_str().unwrap().to_string(),
    };

    let canonical = parent_ref.canonical_bytes();
    let expected = hex_to_bytes(v["expected"]["parent_ref_canonical_hex"].as_str().unwrap());

    assert_eq!(canonical, expected, "parent_ref canonical bytes mismatch");
}

// ── Test 3: Field-by-field breakdown ───────────────────────────

#[test]
fn canonical_serialisation_field_breakdown() {
    let vectors = load_vectors();
    let v = &vectors["vectors"]["canonical_serialisation_breakdown"];
    let fields = v["fields"].as_array().unwrap();

    // Build the receipt from the minimal_receipt inputs
    let receipt = build_receipt(&vectors["vectors"]["minimal_receipt"]["inputs"]);
    let canonical = receipt.canonical_bytes();
    let concatenated_hex = v["concatenated_hex"].as_str().unwrap();

    assert_eq!(
        hex::encode(&canonical),
        concatenated_hex,
        "concatenated canonical bytes don't match field breakdown"
    );

    // Verify the SHA-256 of concatenated bytes matches
    let sha = hex::encode(receipt.receipt_id());
    let expected_sha = v["sha256_of_concatenated"].as_str().unwrap();
    assert_eq!(sha, expected_sha);

    // Verify each field's encoded hex contributes correctly
    let mut offset = 0;
    for field in fields {
        let field_hex = field["encoded_hex"].as_str().unwrap();
        let field_bytes = hex_to_bytes(field_hex);
        let field_name = field["field"].as_str().unwrap();

        let slice = &canonical[offset..offset + field_bytes.len()];
        assert_eq!(
            slice,
            field_bytes.as_slice(),
            "field '{}' mismatch at offset {}",
            field_name,
            offset,
        );
        offset += field_bytes.len();
    }
    assert_eq!(offset, canonical.len(), "fields don't cover all canonical bytes");
}

// ── Test 4: Transfer record ────────────────────────────────────

#[test]
fn transfer_record_canonical_bytes() {
    let vectors = load_vectors();
    let v = &vectors["vectors"]["transfer_record"];
    let inputs = &v["inputs"];

    let royalties: Vec<RoyaltyPayment> = inputs["royalties_paid"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rp| RoyaltyPayment {
            recipient: hex_to_bytes(rp["recipient"].as_str().unwrap()),
            amount: rp["amount"].as_u64().unwrap(),
            receipt_id: hex_to_bytes(rp["receipt_id"].as_str().unwrap()),
        })
        .collect();

    let xfer = TransferRecord {
        receipt_id: hex_to_bytes(inputs["receipt_id"].as_str().unwrap()),
        from_key: hex_to_bytes(inputs["from_key"].as_str().unwrap()),
        to_key: hex_to_bytes(inputs["to_key"].as_str().unwrap()),
        price: inputs["price"].as_u64().unwrap(),
        currency: inputs["currency"].as_str().unwrap().to_string(),
        timestamp: inputs["timestamp"].as_u64().unwrap(),
        royalties_paid: royalties,
        seller_signature: Vec::new(),
        parent_receipts: vec![],
    };

    let expected_hex = v["expected"]["canonical_bytes_hex"].as_str().unwrap();
    let expected = hex_to_bytes(expected_hex);

    assert_eq!(xfer.canonical_bytes(), expected, "transfer canonical bytes mismatch");

    let expected_hash = v["expected"]["transfer_hash"].as_str().unwrap();
    assert_eq!(hex::encode(xfer.transfer_hash()), expected_hash, "transfer hash mismatch");
}

// ── Test 5: Deterministic key derivation ──────────────────────

fn test_key(label: &str) -> ed25519_dalek::SigningKey {
    use sha2::{Digest, Sha256};
    let seed = Sha256::digest(label.as_bytes());
    ed25519_dalek::SigningKey::from_bytes(&seed.into())
}

#[test]
fn deterministic_key_derivation() {
    let vectors = load_vectors();

    // Verify Rust derives the same public keys as Python
    let key_a = test_key("tessera-test-key-a");
    let key_b = test_key("tessera-test-key-b");

    let expected_a = vectors["vectors"]["minimal_receipt"]["inputs"]["provider"]
        .as_str()
        .unwrap();
    let expected_b = vectors["vectors"]["receipt_with_parent"]["inputs"]["provider"]
        .as_str()
        .unwrap();

    assert_eq!(
        hex::encode(key_a.verifying_key().to_bytes()),
        expected_a,
        "key_a public key mismatch"
    );
    assert_eq!(
        hex::encode(key_b.verifying_key().to_bytes()),
        expected_b,
        "key_b public key mismatch"
    );
}

// ── Test 6: Signature verification from test vectors ──────────

#[test]
fn minimal_receipt_signature_verification() {
    let vectors = load_vectors();
    let v = &vectors["vectors"]["minimal_receipt"];
    let mut receipt = build_receipt(&v["inputs"]);

    // Load the signature from the test vector
    let sig_b64 = v["expected"]["signature"].as_str().unwrap();
    receipt.signature = b64_to_bytes(sig_b64);

    assert!(
        receipt.verify_signature(),
        "signature from test vector should verify"
    );

    // Tamper and verify it breaks
    receipt.original_price = 9999;
    assert!(
        !receipt.verify_signature(),
        "signature should fail after tampering"
    );
}

#[test]
fn receipt_with_parent_signature_verification() {
    let vectors = load_vectors();
    let v = &vectors["vectors"]["receipt_with_parent"];
    let mut receipt = build_receipt(&v["inputs"]);

    let sig_b64 = v["expected"]["signature"].as_str().unwrap();
    receipt.signature = b64_to_bytes(sig_b64);

    assert!(
        receipt.verify_signature(),
        "parent receipt signature should verify"
    );
}

#[test]
fn rust_sign_matches_python() {
    // Derive the same key as Python, sign the same receipt, verify signatures match
    let vectors = load_vectors();
    let v = &vectors["vectors"]["minimal_receipt"];
    let mut receipt = build_receipt(&v["inputs"]);

    let key_a = test_key("tessera-test-key-a");
    receipt.sign(&key_a);

    let expected_sig = v["expected"]["signature"].as_str().unwrap();
    let expected_sig_bytes = b64_to_bytes(expected_sig);

    assert_eq!(
        receipt.signature, expected_sig_bytes,
        "Rust signature should be identical to Python signature"
    );
}

// ── Test 7: Signing and verification roundtrip ─────────────────

#[test]
fn sign_and_verify_roundtrip() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);

    let mut receipt = Receipt {
        schema_version: 1,
        model_id: vec![0u8; 32],
        verification_key_id: vec![0u8; 32],
        input_hash: vec![0u8; 32],
        output_hash: vec![0u8; 32],
        proof: Vec::new(),
        public_inputs: Vec::new(),
        proving_backend: "ezkl-halo2".to_string(),
        timestamp: 1714500000,
        parent_receipts: Vec::new(),
        provenance_depth: 0,
        provider: Vec::new(),
        original_price: 1000,
        currency: "USD-cents".to_string(),
        royalty_terms: RoyaltyTerms {
            provider_royalty: 500,
            parent_royalty: 300,
            cascade: true,
        },
        transfer_count: 0,
        signature: Vec::new(),
        signature_scheme: "ed25519".to_string(),
        extensions: Vec::new(),
    };

    receipt.sign(&signing_key);
    assert!(receipt.verify_signature(), "signature should verify after signing");

    // Tamper with a field — signature should break
    receipt.original_price = 9999;
    assert!(!receipt.verify_signature(), "signature should fail after tampering");
}

// ── Test 8: Receipt with extensions ───────────────────────────

#[test]
fn receipt_with_extensions_canonical_bytes() {
    let vectors = load_vectors();
    let v = &vectors["vectors"]["receipt_with_extensions"];
    let receipt = build_receipt(&v["inputs"]);

    let canonical = receipt.canonical_bytes();
    let expected_hex = v["expected"]["canonical_bytes_hex"].as_str().unwrap();
    let expected_bytes = hex_to_bytes(expected_hex);

    assert_eq!(
        canonical.len(),
        expected_bytes.len(),
        "canonical bytes length mismatch: got {}, expected {}",
        canonical.len(),
        expected_bytes.len(),
    );

    if canonical != expected_bytes {
        for (i, (a, b)) in canonical.iter().zip(expected_bytes.iter()).enumerate() {
            if a != b {
                panic!(
                    "canonical bytes diverge at byte {}: got 0x{:02x}, expected 0x{:02x}",
                    i, a, b
                );
            }
        }
    }

    assert_eq!(canonical, expected_bytes);
}

#[test]
fn receipt_with_extensions_id() {
    let vectors = load_vectors();
    let v = &vectors["vectors"]["receipt_with_extensions"];
    let receipt = build_receipt(&v["inputs"]);

    let receipt_id = hex::encode(receipt.receipt_id());
    let expected_id = v["expected"]["receipt_id"].as_str().unwrap();

    assert_eq!(receipt_id, expected_id, "receipt_id mismatch for extensions vector");
}

#[test]
fn receipt_with_extensions_signature_verification() {
    let vectors = load_vectors();
    let v = &vectors["vectors"]["receipt_with_extensions"];
    let mut receipt = build_receipt(&v["inputs"]);

    let sig_b64 = v["expected"]["signature"].as_str().unwrap();
    receipt.signature = b64_to_bytes(sig_b64);

    assert!(
        receipt.verify_signature(),
        "extensions receipt signature should verify"
    );

    // Tamper and verify it breaks
    receipt.original_price = 9999;
    assert!(
        !receipt.verify_signature(),
        "signature should fail after tampering"
    );
}
