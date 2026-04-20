//! VCR receipt schema and canonical serialisation.
//!
//! Implements Section 2–5 of VCR-SPEC.md.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

// ── Supporting structures (Section 3) ──────────────────────────

#[derive(Clone, Debug)]
pub struct ParentRef {
    pub receipt_id: Vec<u8>,   // bytes32
    pub receipt_hash: Vec<u8>, // bytes32
    pub relationship: String,  // "input", "reference", "aggregation"
}

impl ParentRef {
    /// Canonical bytes: 3 LEN-prefixed sub-fields (Section 4.3).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_field(&mut out, &self.receipt_id);
        encode_field(&mut out, &self.receipt_hash);
        encode_field(&mut out, self.relationship.as_bytes());
        out
    }
}

#[derive(Clone, Debug)]
pub struct RoyaltyTerms {
    pub provider_royalty: u16, // basis points 0–10000
    pub parent_royalty: u16,
    pub cascade: bool,
}

impl RoyaltyTerms {
    /// Canonical bytes: 3 LEN-prefixed sub-fields, no outer wrapper (Section 4.3).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_field(&mut out, &self.provider_royalty.to_be_bytes());
        encode_field(&mut out, &self.parent_royalty.to_be_bytes());
        encode_field(&mut out, &[if self.cascade { 0x01 } else { 0x00 }]);
        out
    }
}

#[derive(Clone, Debug)]
pub struct Extension {
    pub ext_type: String,
    pub data: Vec<u8>,
}

impl Extension {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_field(&mut out, self.ext_type.as_bytes());
        encode_field(&mut out, &self.data);
        out
    }
}

// ── Receipt (Section 2) ────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct Receipt {
    // Identity
    pub schema_version: u16,

    // Computation
    pub model_id: Vec<u8>,
    pub verification_key_id: Vec<u8>,
    pub input_hash: Vec<u8>,
    pub output_hash: Vec<u8>,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<u8>,
    pub proving_backend: String,
    pub timestamp: u64,

    // Provenance
    pub parent_receipts: Vec<ParentRef>,
    pub provenance_depth: u16,

    // Economics
    pub provider: Vec<u8>,
    pub original_price: u64,
    pub currency: String,
    pub royalty_terms: RoyaltyTerms,
    pub transfer_count: u16, // excluded from canonical serialisation

    // Integrity
    pub signature: Vec<u8>,  // excluded from canonical serialisation
    pub signature_scheme: String,
    pub extensions: Vec<Extension>,
}

impl Receipt {
    /// Canonical binary serialisation (Section 4.4).
    ///
    /// 17 fields in exact normative order. transfer_count and signature excluded.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();

        //  1. schema_version
        encode_field(&mut out, &self.schema_version.to_be_bytes());
        //  2. model_id
        encode_field(&mut out, &self.model_id);
        //  3. verification_key_id
        encode_field(&mut out, &self.verification_key_id);
        //  4. input_hash
        encode_field(&mut out, &self.input_hash);
        //  5. output_hash
        encode_field(&mut out, &self.output_hash);
        //  6. proof
        encode_field(&mut out, &self.proof);
        //  7. public_inputs
        encode_field(&mut out, &self.public_inputs);
        //  8. proving_backend
        encode_field(&mut out, self.proving_backend.as_bytes());
        //  9. timestamp
        encode_field(&mut out, &self.timestamp.to_be_bytes());
        // 10. parent_receipts (LIST)
        encode_list(&mut out, &self.parent_receipts);
        // 11. provenance_depth
        encode_field(&mut out, &self.provenance_depth.to_be_bytes());
        // 12. provider
        encode_field(&mut out, &self.provider);
        // 13. original_price
        encode_field(&mut out, &self.original_price.to_be_bytes());
        // 14. currency
        encode_field(&mut out, self.currency.as_bytes());
        // 15. royalty_terms (nested, no outer wrapper)
        out.extend_from_slice(&self.royalty_terms.canonical_bytes());
        // 16. signature_scheme
        encode_field(&mut out, self.signature_scheme.as_bytes());
        // 17. extensions (LIST)
        encode_ext_list(&mut out, &self.extensions);

        out
    }

    /// receipt_id = SHA-256(canonical_bytes) (Section 5.1).
    pub fn receipt_id(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&self.canonical_bytes());
        hasher.finalize().to_vec()
    }

    /// receipt_hash is an alias for receipt_id (Section 5.1).
    pub fn receipt_hash(&self) -> Vec<u8> {
        self.receipt_id()
    }

    /// Sign the receipt with an Ed25519 private key (Section 5.3).
    ///
    /// Sets provider to the corresponding public key and computes signature.
    pub fn sign(&mut self, signing_key: &SigningKey) {
        self.provider = signing_key.verifying_key().to_bytes().to_vec();
        let hash = self.receipt_hash();
        self.signature = signing_key.sign(&hash).to_bytes().to_vec();
    }

    /// Verify the signature against the provider public key (Section 6.2).
    pub fn verify_signature(&self) -> bool {
        if self.signature.len() != 64 || self.provider.len() != 32 {
            return false;
        }
        let Ok(vk_bytes): Result<[u8; 32], _> = self.provider.clone().try_into() else {
            return false;
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(&vk_bytes) else {
            return false;
        };
        let Ok(sig_bytes): Result<[u8; 64], _> = self.signature.clone().try_into() else {
            return false;
        };
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let hash = self.receipt_hash();
        verifying_key.verify(&hash, &signature).is_ok()
    }
}

// ── Encoding helpers (Section 4.1–4.2) ─────────────────────────

/// LEN(x) = BE32(len(x)) || x
fn encode_field(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

/// LIST = BE32(count) || item_0.canonical_bytes() || ...
fn encode_list(out: &mut Vec<u8>, items: &[ParentRef]) {
    out.extend_from_slice(&(items.len() as u32).to_be_bytes());
    for item in items {
        out.extend_from_slice(&item.canonical_bytes());
    }
}

fn encode_ext_list(out: &mut Vec<u8>, items: &[Extension]) {
    out.extend_from_slice(&(items.len() as u32).to_be_bytes());
    for item in items {
        out.extend_from_slice(&item.canonical_bytes());
    }
}
