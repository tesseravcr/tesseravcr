use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey, Verifier};
use rusqlite::{params, Connection};
use serde_json;

use crate::witness::WitnessSignature;
use tessera::merkle;
use tessera::transfer::TransferRecord;

#[derive(Debug)]
pub struct SubmitResult {
    pub index: u64,
    pub leaf_hash: [u8; 32],
    pub root: [u8; 32],
    pub log_size: u64,
    pub log_timestamp: u64,
    pub checkpoint: SignedCheckpoint,
}

#[derive(Debug, Clone)]
pub struct SignedCheckpoint {
    pub root: [u8; 32],
    pub log_size: u64,
    pub timestamp: u64,
    pub operator_signature: [u8; 64],
    pub witnesses: Vec<WitnessSignature>,
}

#[derive(Debug)]
pub struct ParentRefRow {
    pub parent_receipt_id: String,
    pub relationship: String,
}

#[derive(Debug)]
pub struct EntryRow {
    pub idx: u64,
    pub receipt_id: String,
    pub from_key: String,
    pub to_key: String,
    pub price: u64,
    pub currency: String,
    pub transfer_ts: u64,
    pub log_ts: u64,
    pub leaf_hash: [u8; 32],
    pub raw_entry: Vec<u8>,
    pub seller_sig: Vec<u8>,
    pub parent_receipts: Vec<ParentRefRow>,
}

#[derive(Debug, Clone)]
pub struct ProviderRow {
    pub pubkey: String,
    pub endpoint: String,
    pub models: Vec<String>,
    pub price_per_1k_tokens: u64,
    pub currency: String,
    pub last_seen: u64,
}

#[derive(Debug)]
pub enum StoreError {
    BadSignature,
    CanonicalMismatch,
    DoubleSpend { receipt_id: String, expected_from: String },
    DuplicateLeaf,
    Db(rusqlite::Error),
    Internal(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::BadSignature => write!(f, "invalid seller signature"),
            StoreError::CanonicalMismatch => write!(f, "canonical bytes mismatch"),
            StoreError::DoubleSpend { receipt_id, expected_from } => {
                write!(f, "double-spend: receipt {} expected from_key {}", receipt_id, expected_from)
            }
            StoreError::DuplicateLeaf => write!(f, "duplicate leaf hash"),
            StoreError::Db(e) => write!(f, "database error: {}", e),
            StoreError::Internal(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Db(e)
    }
}

pub struct Store {
    conn: Connection,
    leaves: Vec<[u8; 32]>,
    cached_root: [u8; 32],
    operator_key: SigningKey,
}

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS entries (
    idx          INTEGER PRIMARY KEY,
    receipt_id   TEXT NOT NULL,
    from_key     TEXT NOT NULL,
    to_key       TEXT NOT NULL,
    price        INTEGER NOT NULL,
    currency     TEXT NOT NULL,
    transfer_ts  INTEGER NOT NULL,
    log_ts       INTEGER NOT NULL,
    leaf_hash    BLOB NOT NULL UNIQUE,
    raw_entry    BLOB NOT NULL,
    seller_sig   BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS ownership (
    receipt_id    TEXT PRIMARY KEY,
    owner_key     TEXT NOT NULL,
    last_entry_idx INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoints (
    log_size      INTEGER PRIMARY KEY,
    root          BLOB NOT NULL,
    timestamp     INTEGER NOT NULL,
    operator_sig  BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_entries_receipt ON entries(receipt_id);

CREATE TABLE IF NOT EXISTS parent_receipts (
    receipt_id        TEXT NOT NULL,
    parent_receipt_id TEXT NOT NULL,
    relationship      TEXT NOT NULL,
    PRIMARY KEY (receipt_id, parent_receipt_id)
);

CREATE INDEX IF NOT EXISTS idx_parent_by_receipt ON parent_receipts(receipt_id);
CREATE INDEX IF NOT EXISTS idx_parent_by_parent ON parent_receipts(parent_receipt_id);

CREATE TABLE IF NOT EXISTS providers (
    pubkey TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    models TEXT NOT NULL,
    price_per_1k_tokens INTEGER NOT NULL DEFAULT 1,
    currency TEXT NOT NULL DEFAULT 'USD-cents',
    last_seen INTEGER NOT NULL,
    signature TEXT NOT NULL
);
"#;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs()
}

fn checkpoint_bytes(log_size: u64, root: &[u8; 32], timestamp: u64) -> [u8; 69] {
    let mut buf = [0u8; 69];
    buf[..21].copy_from_slice(b"tessera-checkpoint-v1");
    buf[21..29].copy_from_slice(&log_size.to_be_bytes());
    buf[29..61].copy_from_slice(root);
    buf[61..69].copy_from_slice(&timestamp.to_be_bytes());
    buf
}

impl Store {
    pub fn open(path: &Path, operator_key: SigningKey) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;

        let mut leaves: Vec<[u8; 32]> = Vec::new();
        {
            let mut stmt = conn.prepare("SELECT leaf_hash FROM entries ORDER BY idx")?;
            let rows = stmt.query_map([], |row| {
                let blob: Vec<u8> = row.get(0)?;
                let mut h = [0u8; 32];
                h.copy_from_slice(&blob);
                Ok(h)
            })?;
            for row in rows {
                leaves.push(row?);
            }
        }

        let cached_root = merkle::compute_root(&leaves);

        Ok(Store { conn, leaves, cached_root, operator_key })
    }

    pub fn log_size(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn root(&self) -> [u8; 32] {
        self.cached_root
    }

    pub fn append_transfer(
        &mut self,
        transfer: &TransferRecord,
        submitted_canonical: &[u8],
    ) -> Result<SubmitResult, StoreError> {
        // 1. canonical reconstruction
        let reconstructed = transfer.canonical_bytes();
        if reconstructed != submitted_canonical {
            return Err(StoreError::CanonicalMismatch);
        }

        // 2. signature verification
        if !verify_transfer_sig(transfer) {
            return Err(StoreError::BadSignature);
        }

        let receipt_id_hex = hex::encode(&transfer.receipt_id);
        let from_key_hex = hex::encode(&transfer.from_key);
        let to_key_hex = hex::encode(&transfer.to_key);

        // 3. double-spend check
        let existing_owner: Option<String> = self.conn.query_row(
            "SELECT owner_key FROM ownership WHERE receipt_id = ?1",
            params![receipt_id_hex],
            |row| row.get(0),
        ).optional()?;

        if let Some(owner) = existing_owner {
            if owner != from_key_hex {
                return Err(StoreError::DoubleSpend {
                    receipt_id: receipt_id_hex,
                    expected_from: owner,
                });
            }
        }

        // 4. compute leaf, reject duplicate
        let log_ts = now_unix();
        let entry = merkle::entry_bytes(submitted_canonical, log_ts);
        let leaf_hash = merkle::hash_leaf(&entry);

        let dup: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM entries WHERE leaf_hash = ?1)",
            params![leaf_hash.as_slice()],
            |row| row.get(0),
        )?;
        if dup {
            return Err(StoreError::DuplicateLeaf);
        }

        // 5. append
        let idx = self.leaves.len() as u64;
        self.conn.execute(
            "INSERT INTO entries (idx, receipt_id, from_key, to_key, price, currency, transfer_ts, log_ts, leaf_hash, raw_entry, seller_sig)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                idx as i64,
                receipt_id_hex,
                from_key_hex,
                to_key_hex,
                transfer.price as i64,
                transfer.currency,
                transfer.timestamp as i64,
                log_ts as i64,
                leaf_hash.as_slice(),
                entry.as_slice(),
                transfer.seller_signature.as_slice(),
            ],
        )?;

        self.conn.execute(
            "INSERT INTO ownership (receipt_id, owner_key, last_entry_idx) VALUES (?1, ?2, ?3)
             ON CONFLICT(receipt_id) DO UPDATE SET owner_key = ?2, last_entry_idx = ?3",
            params![receipt_id_hex, to_key_hex, idx as i64],
        )?;

        for pr in &transfer.parent_receipts {
            self.conn.execute(
                "INSERT OR IGNORE INTO parent_receipts (receipt_id, parent_receipt_id, relationship) VALUES (?1, ?2, ?3)",
                params![receipt_id_hex, hex::encode(&pr.parent_receipt_id), &pr.relationship],
            )?;
        }

        // 6. update in-memory state
        self.leaves.push(leaf_hash);
        self.cached_root = merkle::compute_root(&self.leaves);

        // 7. sign checkpoint
        let log_size = self.leaves.len() as u64;
        let cp_bytes = checkpoint_bytes(log_size, &self.cached_root, log_ts);
        let sig = self.operator_key.sign(&cp_bytes);

        self.conn.execute(
            "INSERT INTO checkpoints (log_size, root, timestamp, operator_sig) VALUES (?1, ?2, ?3, ?4)",
            params![
                log_size as i64,
                self.cached_root.as_slice(),
                log_ts as i64,
                sig.to_bytes().as_slice(),
            ],
        )?;

        let checkpoint = SignedCheckpoint {
            root: self.cached_root,
            log_size,
            timestamp: log_ts,
            operator_signature: sig.to_bytes(),
            witnesses: Vec::new(),
        };

        Ok(SubmitResult {
            index: idx,
            leaf_hash,
            root: self.cached_root,
            log_size,
            log_timestamp: log_ts,
            checkpoint,
        })
    }

    pub fn get_proof(&self, index: usize) -> Option<merkle::InclusionProof> {
        if index >= self.leaves.len() {
            return None;
        }
        let path = merkle::build_proof(&self.leaves, index)?;
        Some(merkle::InclusionProof {
            index: index as u64,
            leaf_hash: self.leaves[index],
            path,
            root: self.cached_root,
            log_size: self.leaves.len() as u64,
        })
    }

    pub fn get_entry(&self, index: u64) -> Result<Option<EntryRow>, StoreError> {
        let result = self.conn.query_row(
            "SELECT idx, receipt_id, from_key, to_key, price, currency, transfer_ts, log_ts, leaf_hash, raw_entry, seller_sig
             FROM entries WHERE idx = ?1",
            params![index as i64],
            |row| {
                let leaf_blob: Vec<u8> = row.get(8)?;
                let mut leaf_hash = [0u8; 32];
                leaf_hash.copy_from_slice(&leaf_blob);
                Ok(EntryRow {
                    idx: row.get::<_, i64>(0)? as u64,
                    receipt_id: row.get(1)?,
                    from_key: row.get(2)?,
                    to_key: row.get(3)?,
                    price: row.get::<_, i64>(4)? as u64,
                    currency: row.get(5)?,
                    transfer_ts: row.get::<_, i64>(6)? as u64,
                    log_ts: row.get::<_, i64>(7)? as u64,
                    leaf_hash,
                    raw_entry: row.get(9)?,
                    seller_sig: row.get(10)?,
                    parent_receipts: Vec::new(),
                })
            },
        ).optional()?;

        if let Some(mut entry) = result {
            entry.parent_receipts = self.load_parents(&entry.receipt_id)?;
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    pub fn get_receipt_owner(&self, receipt_id: &str) -> Result<Option<(String, u64)>, StoreError> {
        let result = self.conn.query_row(
            "SELECT owner_key, last_entry_idx FROM ownership WHERE receipt_id = ?1",
            params![receipt_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64)),
        ).optional()?;
        Ok(result)
    }

    pub fn get_entries_for_receipt(&self, receipt_id: &str) -> Result<Vec<EntryRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT idx, receipt_id, from_key, to_key, price, currency, transfer_ts, log_ts, leaf_hash, raw_entry, seller_sig
             FROM entries WHERE receipt_id = ?1 ORDER BY idx",
        )?;
        let rows = stmt.query_map(params![receipt_id], |row| {
            let leaf_blob: Vec<u8> = row.get(8)?;
            let mut leaf_hash = [0u8; 32];
            leaf_hash.copy_from_slice(&leaf_blob);
            Ok(EntryRow {
                idx: row.get::<_, i64>(0)? as u64,
                receipt_id: row.get(1)?,
                from_key: row.get(2)?,
                to_key: row.get(3)?,
                price: row.get::<_, i64>(4)? as u64,
                currency: row.get(5)?,
                transfer_ts: row.get::<_, i64>(6)? as u64,
                log_ts: row.get::<_, i64>(7)? as u64,
                leaf_hash,
                raw_entry: row.get(9)?,
                seller_sig: row.get(10)?,
                parent_receipts: Vec::new(),
            })
        })?;
        let mut entries = Vec::new();
        for row in rows {
            let mut entry = row?;
            entry.parent_receipts = self.load_parents(&entry.receipt_id)?;
            entries.push(entry);
        }
        Ok(entries)
    }

    fn load_parents(&self, receipt_id: &str) -> Result<Vec<ParentRefRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT parent_receipt_id, relationship FROM parent_receipts WHERE receipt_id = ?1",
        )?;
        let rows = stmt.query_map(params![receipt_id], |row| {
            Ok(ParentRefRow {
                parent_receipt_id: row.get(0)?,
                relationship: row.get(1)?,
            })
        })?;
        let mut parents = Vec::new();
        for row in rows {
            parents.push(row?);
        }
        Ok(parents)
    }

    pub fn latest_checkpoint(&self) -> Result<Option<SignedCheckpoint>, StoreError> {
        let result = self.conn.query_row(
            "SELECT log_size, root, timestamp, operator_sig FROM checkpoints ORDER BY log_size DESC LIMIT 1",
            [],
            |row| {
                let root_blob: Vec<u8> = row.get(1)?;
                let mut root = [0u8; 32];
                root.copy_from_slice(&root_blob);
                let sig_blob: Vec<u8> = row.get(3)?;
                let mut sig = [0u8; 64];
                sig.copy_from_slice(&sig_blob);
                Ok(SignedCheckpoint {
                    log_size: row.get::<_, i64>(0)? as u64,
                    root,
                    timestamp: row.get::<_, i64>(2)? as u64,
                    operator_signature: sig,
                    witnesses: Vec::new(), // Witnesses not persisted in DB, collected on-demand
                })
            },
        ).optional()?;
        Ok(result)
    }

    pub fn store_provider(
        &self,
        pubkey: &str,
        endpoint: &str,
        models: &str,
        price: u64,
        currency: &str,
        timestamp: u64,
        signature: &str,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO providers (pubkey, endpoint, models, price_per_1k_tokens, currency, last_seen, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(pubkey) DO UPDATE SET endpoint = ?2, models = ?3, price_per_1k_tokens = ?4, currency = ?5, last_seen = ?6, signature = ?7",
            params![
                pubkey,
                endpoint,
                models,
                price as i64,
                currency,
                timestamp as i64,
                signature,
            ],
        )?;
        Ok(())
    }

    pub fn get_providers(&self, model_filter: Option<&str>) -> Result<Vec<ProviderRow>, StoreError> {
        let cutoff = now_unix().saturating_sub(3600);
        let mut providers = Vec::new();

        if let Some(model) = model_filter {
            let pattern = format!("%{}%", model);
            let mut stmt = self.conn.prepare(
                "SELECT pubkey, endpoint, models, price_per_1k_tokens, currency, last_seen
                 FROM providers WHERE last_seen >= ?1 AND models LIKE ?2",
            )?;
            let rows = stmt.query_map(params![cutoff as i64, pattern], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)? as u64,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)? as u64,
                ))
            })?;
            for row in rows {
                let (pubkey, endpoint, models_json, price, currency, last_seen) = row?;
                let models: Vec<String> = serde_json::from_str(&models_json).unwrap_or_default();
                providers.push(ProviderRow { pubkey, endpoint, models, price_per_1k_tokens: price, currency, last_seen });
            }
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT pubkey, endpoint, models, price_per_1k_tokens, currency, last_seen
                 FROM providers WHERE last_seen >= ?1",
            )?;
            let rows = stmt.query_map(params![cutoff as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)? as u64,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)? as u64,
                ))
            })?;
            for row in rows {
                let (pubkey, endpoint, models_json, price, currency, last_seen) = row?;
                let models: Vec<String> = serde_json::from_str(&models_json).unwrap_or_default();
                providers.push(ProviderRow { pubkey, endpoint, models, price_per_1k_tokens: price, currency, last_seen });
            }
        }

        Ok(providers)
    }
}

fn verify_transfer_sig(transfer: &TransferRecord) -> bool {
    if transfer.seller_signature.len() != 64 || transfer.from_key.len() != 32 {
        return false;
    }
    let Ok(vk_bytes): Result<[u8; 32], _> = transfer.from_key.clone().try_into() else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&vk_bytes) else {
        return false;
    };
    let Ok(sig_bytes): Result<[u8; 64], _> = transfer.seller_signature.clone().try_into() else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let hash = transfer.transfer_hash();
    vk.verify(&hash, &sig).is_ok()
}

trait OptionalExt<T> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error>;
}

impl<T> OptionalExt<T> for Result<T, rusqlite::Error> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};
    use tessera::transfer::TransferRecord;
    use tempfile::TempDir;

    fn test_store() -> (Store, TempDir) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("test.db");
        let operator_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let store = Store::open(&db_path, operator_key).unwrap();
        (store, dir)
    }

    fn make_signed_transfer(seller: &SigningKey, buyer_pub: &[u8; 32], receipt_id: &[u8; 32]) -> TransferRecord {
        let mut transfer = TransferRecord {
            receipt_id: receipt_id.to_vec(),
            from_key: seller.verifying_key().to_bytes().to_vec(),
            to_key: buyer_pub.to_vec(),
            price: 2000,
            currency: "USD-cents".to_string(),
            timestamp: 1714500000,
            royalties_paid: vec![],
            seller_signature: vec![],
            parent_receipts: vec![],
        };
        transfer.sign(seller);
        transfer
    }

    #[test]
    fn append_and_query() {
        let (mut store, _dir) = test_store();
        let seller = SigningKey::generate(&mut rand::rngs::OsRng);
        let buyer = SigningKey::generate(&mut rand::rngs::OsRng);
        let receipt_id = Sha256::digest(b"test-receipt-001").into();

        let transfer = make_signed_transfer(&seller, &buyer.verifying_key().to_bytes(), &receipt_id);
        let canonical = transfer.canonical_bytes();

        let result = store.append_transfer(&transfer, &canonical).unwrap();
        assert_eq!(result.index, 0);
        assert_eq!(result.log_size, 1);

        let entry = store.get_entry(0).unwrap().unwrap();
        assert_eq!(entry.receipt_id, hex::encode(receipt_id));

        let (owner, _) = store.get_receipt_owner(&hex::encode(receipt_id)).unwrap().unwrap();
        assert_eq!(owner, hex::encode(buyer.verifying_key().to_bytes()));
    }

    #[test]
    fn reject_bad_signature() {
        let (mut store, _dir) = test_store();
        let seller = SigningKey::generate(&mut rand::rngs::OsRng);
        let buyer = SigningKey::generate(&mut rand::rngs::OsRng);
        let receipt_id = Sha256::digest(b"test-receipt-002").into();

        let mut transfer = make_signed_transfer(&seller, &buyer.verifying_key().to_bytes(), &receipt_id);
        transfer.seller_signature[0] ^= 0xff; // corrupt sig
        let canonical = transfer.canonical_bytes();

        let err = store.append_transfer(&transfer, &canonical).unwrap_err();
        assert!(matches!(err, StoreError::BadSignature));
    }

    #[test]
    fn reject_canonical_mismatch() {
        let (mut store, _dir) = test_store();
        let seller = SigningKey::generate(&mut rand::rngs::OsRng);
        let buyer = SigningKey::generate(&mut rand::rngs::OsRng);
        let receipt_id = Sha256::digest(b"test-receipt-003").into();

        let transfer = make_signed_transfer(&seller, &buyer.verifying_key().to_bytes(), &receipt_id);
        let mut bad_canonical = transfer.canonical_bytes();
        bad_canonical.push(0xff);

        let err = store.append_transfer(&transfer, &bad_canonical).unwrap_err();
        assert!(matches!(err, StoreError::CanonicalMismatch));
    }

    #[test]
    fn reject_double_spend() {
        let (mut store, _dir) = test_store();
        let seller = SigningKey::generate(&mut rand::rngs::OsRng);
        let buyer_a = SigningKey::generate(&mut rand::rngs::OsRng);
        let buyer_b = SigningKey::generate(&mut rand::rngs::OsRng);
        let attacker = SigningKey::generate(&mut rand::rngs::OsRng);
        let receipt_id: [u8; 32] = Sha256::digest(b"test-receipt-004").into();

        // first transfer: seller → buyer_a
        let t1 = make_signed_transfer(&seller, &buyer_a.verifying_key().to_bytes(), &receipt_id);
        store.append_transfer(&t1, &t1.canonical_bytes()).unwrap();

        // attacker tries to transfer the same receipt (not the current owner)
        let t2 = make_signed_transfer(&attacker, &buyer_b.verifying_key().to_bytes(), &receipt_id);
        let err = store.append_transfer(&t2, &t2.canonical_bytes()).unwrap_err();
        assert!(matches!(err, StoreError::DoubleSpend { .. }));
    }

    #[test]
    fn valid_resale() {
        let (mut store, _dir) = test_store();
        let seller = SigningKey::generate(&mut rand::rngs::OsRng);
        let buyer_a = SigningKey::generate(&mut rand::rngs::OsRng);
        let buyer_b = SigningKey::generate(&mut rand::rngs::OsRng);
        let receipt_id: [u8; 32] = Sha256::digest(b"test-receipt-005").into();

        // seller → buyer_a
        let t1 = make_signed_transfer(&seller, &buyer_a.verifying_key().to_bytes(), &receipt_id);
        store.append_transfer(&t1, &t1.canonical_bytes()).unwrap();

        // buyer_a → buyer_b (valid resale: from_key matches current owner)
        let t2 = make_signed_transfer(&buyer_a, &buyer_b.verifying_key().to_bytes(), &receipt_id);
        let result = store.append_transfer(&t2, &t2.canonical_bytes()).unwrap();
        assert_eq!(result.index, 1);
        assert_eq!(result.log_size, 2);

        let (owner, _) = store.get_receipt_owner(&hex::encode(receipt_id)).unwrap().unwrap();
        assert_eq!(owner, hex::encode(buyer_b.verifying_key().to_bytes()));
    }

    #[test]
    fn reject_duplicate_leaf() {
        let (mut store, _dir) = test_store();
        let seller = SigningKey::generate(&mut rand::rngs::OsRng);
        let buyer = SigningKey::generate(&mut rand::rngs::OsRng);
        let receipt_id: [u8; 32] = Sha256::digest(b"test-receipt-006").into();

        let transfer = make_signed_transfer(&seller, &buyer.verifying_key().to_bytes(), &receipt_id);
        let canonical = transfer.canonical_bytes();
        store.append_transfer(&transfer, &canonical).unwrap();

        // same transfer again — same canonical bytes will produce same log_ts (within same second)
        // but we force it by testing the leaf_hash uniqueness constraint directly
        // In practice, duplicate leaf is extremely unlikely (requires same canonical + same log_ts)
        // so we test the DB constraint by inserting a raw duplicate
        let leaf_hash = store.leaves[0];
        let result = store.conn.execute(
            "INSERT INTO entries (idx, receipt_id, from_key, to_key, price, currency, transfer_ts, log_ts, leaf_hash, raw_entry, seller_sig)
             VALUES (99, 'dup', 'dup', 'dup', 0, 'X', 0, 0, ?1, X'00', X'00')",
            params![leaf_hash.as_slice()],
        );
        assert!(result.is_err());
    }

    #[test]
    fn proof_roundtrip() {
        let (mut store, _dir) = test_store();
        let seller = SigningKey::generate(&mut rand::rngs::OsRng);
        let buyer = SigningKey::generate(&mut rand::rngs::OsRng);

        for i in 0..5u8 {
            let receipt_id: [u8; 32] = Sha256::digest(&[i]).into();
            let t = make_signed_transfer(&seller, &buyer.verifying_key().to_bytes(), &receipt_id);
            store.append_transfer(&t, &t.canonical_bytes()).unwrap();
        }

        for i in 0..5 {
            let proof = store.get_proof(i).unwrap();
            assert!(merkle::verify_proof(&proof.leaf_hash, &proof.path, &proof.root));
            assert_eq!(proof.log_size, 5);
        }

        assert!(store.get_proof(5).is_none());
    }

    #[test]
    fn checkpoint_signed_correctly() {
        let (mut store, _dir) = test_store();
        let seller = SigningKey::generate(&mut rand::rngs::OsRng);
        let buyer = SigningKey::generate(&mut rand::rngs::OsRng);
        let receipt_id: [u8; 32] = Sha256::digest(b"test-receipt-cp").into();

        let t = make_signed_transfer(&seller, &buyer.verifying_key().to_bytes(), &receipt_id);
        let result = store.append_transfer(&t, &t.canonical_bytes()).unwrap();

        let cp = &result.checkpoint;
        let cp_bytes = checkpoint_bytes(cp.log_size, &cp.root, cp.timestamp);
        let sig = ed25519_dalek::Signature::from_bytes(&cp.operator_signature);
        let vk = store.operator_key.verifying_key();
        assert!(vk.verify(&cp_bytes, &sig).is_ok());
    }

    #[test]
    fn reload_from_disk() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("persist.db");
        let operator_key = SigningKey::generate(&mut rand::rngs::OsRng);

        let seller = SigningKey::generate(&mut rand::rngs::OsRng);
        let buyer = SigningKey::generate(&mut rand::rngs::OsRng);
        let receipt_id: [u8; 32] = Sha256::digest(b"persist-test").into();

        let root_after_append;
        {
            let mut store = Store::open(&db_path, operator_key.clone()).unwrap();
            let t = make_signed_transfer(&seller, &buyer.verifying_key().to_bytes(), &receipt_id);
            store.append_transfer(&t, &t.canonical_bytes()).unwrap();
            root_after_append = store.root();
        }

        // reopen — should reload leaves and recompute same root
        let store2 = Store::open(&db_path, operator_key).unwrap();
        assert_eq!(store2.log_size(), 1);
        assert_eq!(store2.root(), root_after_append);
    }

    #[test]
    fn transfer_history() {
        let (mut store, _dir) = test_store();
        let seller = SigningKey::generate(&mut rand::rngs::OsRng);
        let buyer_a = SigningKey::generate(&mut rand::rngs::OsRng);
        let buyer_b = SigningKey::generate(&mut rand::rngs::OsRng);
        let receipt_id: [u8; 32] = Sha256::digest(b"history-test").into();

        let t1 = make_signed_transfer(&seller, &buyer_a.verifying_key().to_bytes(), &receipt_id);
        store.append_transfer(&t1, &t1.canonical_bytes()).unwrap();

        let t2 = make_signed_transfer(&buyer_a, &buyer_b.verifying_key().to_bytes(), &receipt_id);
        store.append_transfer(&t2, &t2.canonical_bytes()).unwrap();

        let entries = store.get_entries_for_receipt(&hex::encode(receipt_id)).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].from_key, hex::encode(seller.verifying_key().to_bytes()));
        assert_eq!(entries[1].from_key, hex::encode(buyer_a.verifying_key().to_bytes()));
    }
}
