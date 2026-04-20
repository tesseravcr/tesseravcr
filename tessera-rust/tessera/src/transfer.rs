//! Transfer records and ownership tracking.
//!
//! Implements Section 10 of VCR-SPEC.md.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct RoyaltyPayment {
    pub recipient: Vec<u8>,  // bytes32
    pub amount: u64,
    pub receipt_id: Vec<u8>, // bytes32
}

impl RoyaltyPayment {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_field(&mut out, &self.recipient);
        encode_field(&mut out, &self.amount.to_be_bytes());
        encode_field(&mut out, &self.receipt_id);
        out
    }
}

#[derive(Clone, Debug)]
pub struct ParentRef {
    pub parent_receipt_id: Vec<u8>, // bytes32
    pub relationship: String,
}

#[derive(Clone, Debug)]
pub struct TransferRecord {
    pub receipt_id: Vec<u8>,
    pub from_key: Vec<u8>,
    pub to_key: Vec<u8>,
    pub price: u64,
    pub currency: String,
    pub timestamp: u64,
    pub royalties_paid: Vec<RoyaltyPayment>,
    pub seller_signature: Vec<u8>,
    #[allow(dead_code)]
    pub parent_receipts: Vec<ParentRef>,
}

impl TransferRecord {
    /// Canonical serialisation (Section 10.3).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_field(&mut out, &self.receipt_id);
        encode_field(&mut out, &self.from_key);
        encode_field(&mut out, &self.to_key);
        encode_field(&mut out, &self.price.to_be_bytes());
        encode_field(&mut out, self.currency.as_bytes());
        encode_field(&mut out, &self.timestamp.to_be_bytes());
        // royalties list
        out.extend_from_slice(&(self.royalties_paid.len() as u32).to_be_bytes());
        for rp in &self.royalties_paid {
            out.extend_from_slice(&rp.canonical_bytes());
        }
        out
    }

    /// transfer_hash = SHA-256(canonical_bytes)
    pub fn transfer_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&self.canonical_bytes());
        hasher.finalize().to_vec()
    }

    pub fn sign(&mut self, signing_key: &SigningKey) {
        self.from_key = signing_key.verifying_key().to_bytes().to_vec();
        let hash = self.transfer_hash();
        self.seller_signature = signing_key.sign(&hash).to_bytes().to_vec();
    }

    pub fn verify_signature(&self) -> bool {
        if self.seller_signature.len() != 64 || self.from_key.len() != 32 {
            return false;
        }
        let Ok(vk_bytes): Result<[u8; 32], _> = self.from_key.clone().try_into() else {
            return false;
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(&vk_bytes) else {
            return false;
        };
        let Ok(sig_bytes): Result<[u8; 64], _> = self.seller_signature.clone().try_into() else {
            return false;
        };
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let hash = self.transfer_hash();
        verifying_key.verify(&hash, &signature).is_ok()
    }
}

fn encode_field(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}
