use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::{Path, State};
use axum::Json;
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::AppError;
use crate::store::{Store, StoreError};
use crate::witness::{WitnessClient, WitnessError, WitnessRequest, WitnessResponse, WitnessState};
use tessera::merkle;
use tessera::transfer::{RoyaltyPayment, TransferRecord};

pub struct AppState {
    pub store: Mutex<Store>,
    pub operator_key_hex: String,
    pub start_time: Instant,
    pub witness_state: Mutex<WitnessState>,
    pub signing_key: SigningKey,
    pub witness_client: Option<WitnessClient>,
}

fn hex32(s: &str) -> Result<Vec<u8>, AppError> {
    let bytes = hex::decode(s).map_err(|_| AppError::BadRequest(format!("invalid hex: {}", s)))?;
    if bytes.len() != 32 {
        return Err(AppError::BadRequest(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn hex64_sig(s: &str) -> Result<Vec<u8>, AppError> {
    let bytes = hex::decode(s).map_err(|_| AppError::BadRequest(format!("invalid hex: {}", s)))?;
    if bytes.len() != 64 {
        return Err(AppError::BadRequest(format!(
            "expected 64-byte signature, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn hex_bytes(s: &str) -> Result<Vec<u8>, AppError> {
    hex::decode(s).map_err(|_| AppError::BadRequest(format!("invalid hex: {}", s)))
}

fn store_err(e: StoreError) -> AppError {
    match e {
        StoreError::BadSignature => AppError::BadRequest(e.to_string()),
        StoreError::CanonicalMismatch => AppError::BadRequest(e.to_string()),
        StoreError::DoubleSpend { .. } => AppError::Conflict(e.to_string()),
        StoreError::DuplicateLeaf => AppError::Conflict(e.to_string()),
        StoreError::Db(_) | StoreError::Internal(_) => AppError::Internal(e.to_string()),
    }
}

fn proof_json(proof: &merkle::InclusionProof) -> Value {
    let path: Vec<Value> = proof
        .path
        .iter()
        .map(|step| {
            json!({
                "sibling": hex::encode(step.sibling),
                "direction": match step.direction {
                    merkle::Direction::Left => "left",
                    merkle::Direction::Right => "right",
                },
            })
        })
        .collect();
    json!({
        "index": proof.index,
        "leaf_hash": hex::encode(proof.leaf_hash),
        "root": hex::encode(proof.root),
        "log_size": proof.log_size,
        "path": path,
    })
}

// POST /v1/submit

#[derive(Deserialize)]
pub struct SubmitRequest {
    pub receipt_id: String,
    pub from_key: String,
    pub to_key: String,
    pub price: u64,
    pub currency: String,
    pub timestamp: u64,
    #[serde(default)]
    pub royalties_paid: Vec<RoyaltyPaymentReq>,
    pub seller_signature: String,
    pub canonical_bytes: String,
}

#[derive(Deserialize)]
pub struct RoyaltyPaymentReq {
    pub recipient: String,
    pub amount: u64,
    pub receipt_id: String,
}

pub async fn submit(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubmitRequest>,
) -> Result<Json<Value>, AppError> {
    let receipt_id = hex32(&req.receipt_id)?;
    let from_key = hex32(&req.from_key)?;
    let to_key = hex32(&req.to_key)?;
    let seller_signature = hex64_sig(&req.seller_signature)?;
    let canonical = hex_bytes(&req.canonical_bytes)?;

    let mut royalties = Vec::with_capacity(req.royalties_paid.len());
    for rp in &req.royalties_paid {
        royalties.push(RoyaltyPayment {
            recipient: hex32(&rp.recipient)?,
            amount: rp.amount,
            receipt_id: hex32(&rp.receipt_id)?,
        });
    }

    let transfer = TransferRecord {
        receipt_id,
        from_key,
        to_key,
        price: req.price,
        currency: req.currency.clone(),
        timestamp: req.timestamp,
        royalties_paid: royalties,
        seller_signature,
    };

    let mut result = {
        let mut store = state.store.lock().unwrap();
        store.append_transfer(&transfer, &canonical).map_err(store_err)?
    };

    // Request witnesses from peers if configured
    if let Some(ref witness_client) = state.witness_client {
        let witnesses = witness_client
            .request_witnesses(&result.checkpoint, &state.operator_key_hex)
            .await;
        result.checkpoint.witnesses = witnesses;
    }

    let witness_sigs: Vec<Value> = result
        .checkpoint
        .witnesses
        .iter()
        .map(|w| {
            json!({
                "witness_key": hex::encode(w.witness_key),
                "signature": hex::encode(w.signature),
            })
        })
        .collect();

    Ok(Json(json!({
        "index": result.index,
        "leaf_hash": hex::encode(result.leaf_hash),
        "root": hex::encode(result.root),
        "log_size": result.log_size,
        "log_timestamp": result.log_timestamp,
        "checkpoint": {
            "root": hex::encode(result.checkpoint.root),
            "log_size": result.checkpoint.log_size,
            "timestamp": result.checkpoint.timestamp,
            "operator_signature": hex::encode(result.checkpoint.operator_signature),
            "witnesses": witness_sigs,
        },
    })))
}

// GET /v1/proof/:index

pub async fn proof(
    State(state): State<Arc<AppState>>,
    Path(index): Path<u64>,
) -> Result<Json<Value>, AppError> {
    let store = state.store.lock().unwrap();
    let proof = store
        .get_proof(index as usize)
        .ok_or_else(|| AppError::NotFound(format!("no entry at index {}", index)))?;
    Ok(Json(proof_json(&proof)))
}

// GET /v1/entry/:index

pub async fn entry(
    State(state): State<Arc<AppState>>,
    Path(index): Path<u64>,
) -> Result<Json<Value>, AppError> {
    let store = state.store.lock().unwrap();
    let row = store
        .get_entry(index)
        .map_err(store_err)?
        .ok_or_else(|| AppError::NotFound(format!("no entry at index {}", index)))?;
    Ok(Json(json!({
        "index": row.idx,
        "receipt_id": row.receipt_id,
        "from_key": row.from_key,
        "to_key": row.to_key,
        "price": row.price,
        "currency": row.currency,
        "transfer_timestamp": row.transfer_ts,
        "log_timestamp": row.log_ts,
        "leaf_hash": hex::encode(row.leaf_hash),
        "seller_signature": hex::encode(row.seller_sig),
    })))
}

// GET /v1/receipt/:receipt_id

pub async fn receipt(
    State(state): State<Arc<AppState>>,
    Path(receipt_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    hex32(&receipt_id)?;

    let store = state.store.lock().unwrap();
    let (owner, last_idx) = store
        .get_receipt_owner(&receipt_id)
        .map_err(store_err)?
        .ok_or_else(|| AppError::NotFound(format!("receipt {} not found", receipt_id)))?;

    let entries = store
        .get_entries_for_receipt(&receipt_id)
        .map_err(store_err)?;

    let latest_proof = store.get_proof(last_idx as usize).map(|p| proof_json(&p));

    let transfers: Vec<Value> = entries
        .iter()
        .map(|e| {
            json!({
                "index": e.idx,
                "from_key": e.from_key,
                "to_key": e.to_key,
                "price": e.price,
                "currency": e.currency,
                "transfer_timestamp": e.transfer_ts,
                "log_timestamp": e.log_ts,
            })
        })
        .collect();

    Ok(Json(json!({
        "receipt_id": receipt_id,
        "owner": owner,
        "transfer_count": transfers.len(),
        "transfers": transfers,
        "latest_proof": latest_proof,
    })))
}

// GET /v1/checkpoint

pub async fn checkpoint(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let store = state.store.lock().unwrap();
    let cp = store
        .latest_checkpoint()
        .map_err(store_err)?
        .ok_or_else(|| AppError::NotFound("no checkpoints yet".to_string()))?;

    Ok(Json(json!({
        "root": hex::encode(cp.root),
        "log_size": cp.log_size,
        "timestamp": cp.timestamp,
        "operator_signature": hex::encode(cp.operator_signature),
    })))
}

// GET /v1/health

pub async fn health(State(state): State<Arc<AppState>>) -> Json<Value> {
    let store = state.store.lock().unwrap();
    let log_size = store.log_size();
    let root = hex::encode(store.root());
    drop(store);

    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "operator_key": state.operator_key_hex,
        "log_size": log_size,
        "root": root,
        "uptime_seconds": state.start_time.elapsed().as_secs(),
    }))
}

// POST /v1/internal/witness

pub async fn witness(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WitnessRequest>,
) -> Result<Json<WitnessResponse>, AppError> {
    let mut witness_state = state.witness_state.lock().unwrap();

    let resp = crate::witness::witness_checkpoint(&req, &mut witness_state, &state.signing_key)
        .map_err(|e| match e {
            WitnessError::InvalidSignature => AppError::BadRequest(e.to_string()),
            WitnessError::Rollback { .. } => AppError::Conflict(e.to_string()),
            WitnessError::InvalidKey => AppError::BadRequest(e.to_string()),
        })?;

    Ok(Json(resp))
}
