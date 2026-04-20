use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::store::SignedCheckpoint;

#[derive(Debug, Clone)]
pub struct WitnessSignature {
    pub witness_key: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Debug)]
pub struct WitnessState {
    /// Last witnessed log_size per operator_key (for rollback detection)
    last_witnessed: HashMap<String, u64>,
}

impl WitnessState {
    pub fn new() -> Self {
        WitnessState {
            last_witnessed: HashMap::new(),
        }
    }

    /// Check if this checkpoint represents a rollback for the given operator
    pub fn is_rollback(&self, operator_key: &str, log_size: u64) -> bool {
        if let Some(&last_size) = self.last_witnessed.get(operator_key) {
            log_size < last_size
        } else {
            false
        }
    }

    /// Record that we witnessed this checkpoint
    pub fn record_witness(&mut self, operator_key: String, log_size: u64) {
        self.last_witnessed.insert(operator_key, log_size);
    }
}

/// Request to witness a checkpoint
#[derive(Debug, Serialize, Deserialize)]
pub struct WitnessRequest {
    pub checkpoint: CheckpointData,
    pub operator_key: String,
    pub operator_signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckpointData {
    pub root: String,
    pub log_size: u64,
    pub timestamp: u64,
}

/// Response from witnessing
#[derive(Debug, Serialize, Deserialize)]
pub struct WitnessResponse {
    pub witness_key: String,
    pub witness_signature: String,
}

/// Error during witness verification
#[derive(Debug)]
pub enum WitnessError {
    InvalidSignature,
    Rollback { operator: String, expected: u64, got: u64 },
    InvalidKey,
}

impl std::fmt::Display for WitnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WitnessError::InvalidSignature => write!(f, "invalid operator signature"),
            WitnessError::Rollback { operator, expected, got } => {
                write!(f, "rollback detected for {}: log_size {} < {}", operator, got, expected)
            }
            WitnessError::InvalidKey => write!(f, "invalid operator key"),
        }
    }
}

/// Verify a witness request and produce a countersignature
pub fn witness_checkpoint(
    req: &WitnessRequest,
    witness_state: &mut WitnessState,
    our_key: &SigningKey,
) -> Result<WitnessResponse, WitnessError> {
    // 1. Decode operator key
    let op_key_bytes = hex::decode(&req.operator_key)
        .map_err(|_| WitnessError::InvalidKey)?;
    if op_key_bytes.len() != 32 {
        return Err(WitnessError::InvalidKey);
    }
    let mut op_key_arr = [0u8; 32];
    op_key_arr.copy_from_slice(&op_key_bytes);
    let op_vk = VerifyingKey::from_bytes(&op_key_arr)
        .map_err(|_| WitnessError::InvalidKey)?;

    // 2. Reconstruct checkpoint bytes (spec format: 69 bytes)
    let cp_bytes = checkpoint_bytes(
        req.checkpoint.log_size,
        &hex::decode(&req.checkpoint.root).map_err(|_| WitnessError::InvalidKey)?,
        req.checkpoint.timestamp,
    );

    // 3. Verify operator signature
    let op_sig_bytes = hex::decode(&req.operator_signature)
        .map_err(|_| WitnessError::InvalidSignature)?;
    if op_sig_bytes.len() != 64 {
        return Err(WitnessError::InvalidSignature);
    }
    let mut op_sig_arr = [0u8; 64];
    op_sig_arr.copy_from_slice(&op_sig_bytes);
    let op_sig = Signature::from_bytes(&op_sig_arr);

    op_vk.verify(&cp_bytes, &op_sig)
        .map_err(|_| WitnessError::InvalidSignature)?;

    // 4. Rollback detection
    if witness_state.is_rollback(&req.operator_key, req.checkpoint.log_size) {
        let expected = witness_state.last_witnessed[&req.operator_key];
        return Err(WitnessError::Rollback {
            operator: req.operator_key.clone(),
            expected,
            got: req.checkpoint.log_size,
        });
    }

    // 5. Record this witness
    witness_state.record_witness(req.operator_key.clone(), req.checkpoint.log_size);

    // 6. Countersign the same checkpoint bytes
    let witness_sig = our_key.sign(&cp_bytes);

    Ok(WitnessResponse {
        witness_key: hex::encode(our_key.verifying_key().to_bytes()),
        witness_signature: hex::encode(witness_sig.to_bytes()),
    })
}

/// Reconstruct checkpoint bytes for signing (same as store.rs)
fn checkpoint_bytes(log_size: u64, root: &[u8], timestamp: u64) -> [u8; 69] {
    let mut buf = [0u8; 69];
    buf[..21].copy_from_slice(b"tessera-checkpoint-v1");
    buf[21..29].copy_from_slice(&log_size.to_be_bytes());
    buf[29..61].copy_from_slice(&root[..32]);
    buf[61..69].copy_from_slice(&timestamp.to_be_bytes());
    buf
}

/// Client for requesting witnesses from peers
pub struct WitnessClient {
    client: reqwest::Client,
    peers: Vec<String>,
    threshold: usize,
}

impl WitnessClient {
    pub fn new(peers: Vec<String>, threshold: usize) -> Self {
        WitnessClient {
            client: reqwest::Client::new(),
            peers,
            threshold,
        }
    }

    /// Request witnesses for a checkpoint from all peers
    pub async fn request_witnesses(
        &self,
        checkpoint: &SignedCheckpoint,
        operator_key: &str,
    ) -> Vec<WitnessSignature> {
        let req = WitnessRequest {
            checkpoint: CheckpointData {
                root: hex::encode(checkpoint.root),
                log_size: checkpoint.log_size,
                timestamp: checkpoint.timestamp,
            },
            operator_key: operator_key.to_string(),
            operator_signature: hex::encode(checkpoint.operator_signature),
        };

        let mut witnesses = Vec::new();

        for peer_url in &self.peers {
            let url = format!("{}/v1/internal/witness", peer_url);

            match self.client.post(&url).json(&req).send().await {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(witness_resp) = resp.json::<WitnessResponse>().await {
                        if let (Ok(key_bytes), Ok(sig_bytes)) = (
                            hex::decode(&witness_resp.witness_key),
                            hex::decode(&witness_resp.witness_signature),
                        ) {
                            if key_bytes.len() == 32 && sig_bytes.len() == 64 {
                                let mut key = [0u8; 32];
                                let mut sig = [0u8; 64];
                                key.copy_from_slice(&key_bytes);
                                sig.copy_from_slice(&sig_bytes);
                                witnesses.push(WitnessSignature {
                                    witness_key: key,
                                    signature: sig,
                                });

                                // Stop if we have enough witnesses
                                if witnesses.len() >= self.threshold {
                                    break;
                                }
                            }
                        }
                    }
                }
                Ok(resp) => {
                    tracing::warn!(peer = %peer_url, status = resp.status().as_u16(), "witness request failed");
                }
                Err(e) => {
                    tracing::warn!(peer = %peer_url, error = %e, "witness request error");
                }
            }
        }

        witnesses
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn witness_valid_checkpoint() {
        let operator_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let witness_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut witness_state = WitnessState::new();

        let root = [0u8; 32];
        let log_size = 5;
        let timestamp = 1714500000;
        let cp_bytes = checkpoint_bytes(log_size, &root, timestamp);
        let op_sig = operator_key.sign(&cp_bytes);

        let req = WitnessRequest {
            checkpoint: CheckpointData {
                root: hex::encode(root),
                log_size,
                timestamp,
            },
            operator_key: hex::encode(operator_key.verifying_key().to_bytes()),
            operator_signature: hex::encode(op_sig.to_bytes()),
        };

        let result = witness_checkpoint(&req, &mut witness_state, &witness_key);
        assert!(result.is_ok());

        let resp = result.unwrap();
        assert_eq!(resp.witness_key, hex::encode(witness_key.verifying_key().to_bytes()));

        // Verify witness signature
        let wit_sig_bytes = hex::decode(&resp.witness_signature).unwrap();
        let mut wit_sig_arr = [0u8; 64];
        wit_sig_arr.copy_from_slice(&wit_sig_bytes);
        let wit_sig = Signature::from_bytes(&wit_sig_arr);
        assert!(witness_key.verifying_key().verify(&cp_bytes, &wit_sig).is_ok());
    }

    #[test]
    fn reject_rollback() {
        let operator_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let witness_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut witness_state = WitnessState::new();
        let op_key_hex = hex::encode(operator_key.verifying_key().to_bytes());

        // Witness checkpoint at log_size = 10
        witness_state.record_witness(op_key_hex.clone(), 10);

        // Try to witness checkpoint at log_size = 5 (rollback)
        let root = [0u8; 32];
        let cp_bytes = checkpoint_bytes(5, &root, 1714500000);
        let op_sig = operator_key.sign(&cp_bytes);

        let req = WitnessRequest {
            checkpoint: CheckpointData {
                root: hex::encode(root),
                log_size: 5,
                timestamp: 1714500000,
            },
            operator_key: op_key_hex,
            operator_signature: hex::encode(op_sig.to_bytes()),
        };

        let result = witness_checkpoint(&req, &mut witness_state, &witness_key);
        assert!(matches!(result, Err(WitnessError::Rollback { .. })));
    }

    #[test]
    fn reject_invalid_signature() {
        let operator_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let witness_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut witness_state = WitnessState::new();

        let req = WitnessRequest {
            checkpoint: CheckpointData {
                root: hex::encode([0u8; 32]),
                log_size: 5,
                timestamp: 1714500000,
            },
            operator_key: hex::encode(operator_key.verifying_key().to_bytes()),
            operator_signature: hex::encode([0u8; 64]), // Invalid signature
        };

        let result = witness_checkpoint(&req, &mut witness_state, &witness_key);
        assert!(matches!(result, Err(WitnessError::InvalidSignature)));
    }
}
