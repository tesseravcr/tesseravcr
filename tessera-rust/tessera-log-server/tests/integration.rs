use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::routing::{get, post};
use axum::Router;
use ed25519_dalek::SigningKey;
use reqwest::Client;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tessera::transfer::TransferRecord;
use tessera_log_server::api;
use tessera_log_server::store::Store;
use tessera_log_server::witness::WitnessState;

struct TestServer {
    url: String,
    client: Client,
    _dir: TempDir,
}

async fn start_server() -> TestServer {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let operator_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let operator_key_hex = hex::encode(operator_key.verifying_key().to_bytes());
    let store = Store::open(&db_path, operator_key.clone()).unwrap();

    let state = Arc::new(api::AppState {
        store: Mutex::new(store),
        operator_key_hex,
        start_time: Instant::now(),
        witness_state: Mutex::new(WitnessState::new()),
        signing_key: operator_key,
        witness_client: None, // No witnessing in unit tests
    });

    let app = Router::new()
        .route("/v1/health", get(api::health))
        .route("/v1/submit", post(api::submit))
        .route("/v1/proof/:index", get(api::proof))
        .route("/v1/entry/:index", get(api::entry))
        .route("/v1/receipt/:receipt_id", get(api::receipt))
        .route("/v1/checkpoint", get(api::checkpoint))
        .route("/v1/internal/witness", post(api::witness))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let url = format!("http://{}", addr);
    let client = Client::new();

    // Wait for server to be ready
    for _ in 0..50 {
        if client.get(&format!("{}/v1/health", url)).send().await.is_ok() {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }

    TestServer {
        url,
        client,
        _dir: dir,
    }
}

fn make_signed_transfer(
    seller: &SigningKey,
    buyer_pub: &[u8; 32],
    receipt_id: &[u8; 32],
) -> TransferRecord {
    let mut t = TransferRecord {
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
    t.sign(seller);
    t
}

fn submit_body(t: &TransferRecord) -> Value {
    json!({
        "receipt_id": hex::encode(&t.receipt_id),
        "from_key": hex::encode(&t.from_key),
        "to_key": hex::encode(&t.to_key),
        "price": t.price,
        "currency": t.currency,
        "timestamp": t.timestamp,
        "royalties_paid": [],
        "seller_signature": hex::encode(&t.seller_signature),
        "canonical_bytes": hex::encode(t.canonical_bytes()),
    })
}

impl TestServer {
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.url, path)
    }

    async fn get_json(&self, path: &str) -> (u16, Value) {
        let resp = self.client.get(self.url(path)).send().await.unwrap();
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap();
        let val: Value = serde_json::from_str(&text)
            .unwrap_or_else(|_| panic!("GET {} returned {}: {:?}", path, status, text));
        (status, val)
    }

    async fn post_json(&self, path: &str, body: &Value) -> (u16, Value) {
        let resp = self.client.post(self.url(path)).json(body).send().await.unwrap();
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap();
        let val: Value = serde_json::from_str(&text)
            .unwrap_or_else(|_| panic!("POST {} returned {}: {:?}", path, status, text));
        (status, val)
    }
}

#[tokio::test]
async fn health_endpoint() {
    let srv = start_server().await;
    let (status, body) = srv.get_json("/v1/health").await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["log_size"], 0);
}

#[tokio::test]
async fn submit_and_query_all_endpoints() {
    let srv = start_server().await;
    let seller = SigningKey::generate(&mut rand::rngs::OsRng);
    let buyer = SigningKey::generate(&mut rand::rngs::OsRng);
    let rid: [u8; 32] = Sha256::digest(b"integ-001").into();

    let transfer = make_signed_transfer(&seller, &buyer.verifying_key().to_bytes(), &rid);

    let (status, data) = srv.post_json("/v1/submit", &submit_body(&transfer)).await;
    assert_eq!(status, 200);
    assert_eq!(data["index"], 0);
    assert_eq!(data["log_size"], 1);
    assert!(data["checkpoint"]["operator_signature"].as_str().unwrap().len() == 128);

    let (status, proof) = srv.get_json("/v1/proof/0").await;
    assert_eq!(status, 200);
    assert_eq!(proof["index"], 0);
    assert_eq!(proof["log_size"], 1);

    let (status, entry) = srv.get_json("/v1/entry/0").await;
    assert_eq!(status, 200);
    assert_eq!(entry["receipt_id"], hex::encode(rid));
    assert_eq!(entry["price"], 2000);

    let (status, receipt) = srv.get_json(&format!("/v1/receipt/{}", hex::encode(rid))).await;
    assert_eq!(status, 200);
    assert_eq!(receipt["owner"], hex::encode(buyer.verifying_key().to_bytes()));
    assert_eq!(receipt["transfer_count"], 1);

    let (status, cp) = srv.get_json("/v1/checkpoint").await;
    assert_eq!(status, 200);
    assert_eq!(cp["log_size"], 1);

    let (status, h) = srv.get_json("/v1/health").await;
    assert_eq!(status, 200);
    assert_eq!(h["log_size"], 1);
}

#[tokio::test]
async fn double_spend_returns_409() {
    let srv = start_server().await;
    let seller = SigningKey::generate(&mut rand::rngs::OsRng);
    let buyer_a = SigningKey::generate(&mut rand::rngs::OsRng);
    let buyer_b = SigningKey::generate(&mut rand::rngs::OsRng);
    let attacker = SigningKey::generate(&mut rand::rngs::OsRng);
    let rid: [u8; 32] = Sha256::digest(b"integ-ds").into();

    let t1 = make_signed_transfer(&seller, &buyer_a.verifying_key().to_bytes(), &rid);
    let (status, _) = srv.post_json("/v1/submit", &submit_body(&t1)).await;
    assert_eq!(status, 200);

    let t2 = make_signed_transfer(&attacker, &buyer_b.verifying_key().to_bytes(), &rid);
    let (status, err) = srv.post_json("/v1/submit", &submit_body(&t2)).await;
    assert_eq!(status, 409);
    assert!(err["error"].as_str().unwrap().contains("double-spend"));
}

#[tokio::test]
async fn bad_signature_returns_400() {
    let srv = start_server().await;
    let seller = SigningKey::generate(&mut rand::rngs::OsRng);
    let buyer = SigningKey::generate(&mut rand::rngs::OsRng);
    let rid: [u8; 32] = Sha256::digest(b"integ-badsig").into();

    let mut transfer = make_signed_transfer(&seller, &buyer.verifying_key().to_bytes(), &rid);
    transfer.seller_signature[0] ^= 0xff;

    let (status, _) = srv.post_json("/v1/submit", &submit_body(&transfer)).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn canonical_mismatch_returns_400() {
    let srv = start_server().await;
    let seller = SigningKey::generate(&mut rand::rngs::OsRng);
    let buyer = SigningKey::generate(&mut rand::rngs::OsRng);
    let rid: [u8; 32] = Sha256::digest(b"integ-canon").into();

    let transfer = make_signed_transfer(&seller, &buyer.verifying_key().to_bytes(), &rid);
    let mut body = submit_body(&transfer);
    body["canonical_bytes"] = json!("deadbeef");

    let (status, _) = srv.post_json("/v1/submit", &body).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn valid_resale_chain() {
    let srv = start_server().await;
    let seller = SigningKey::generate(&mut rand::rngs::OsRng);
    let buyer_a = SigningKey::generate(&mut rand::rngs::OsRng);
    let buyer_b = SigningKey::generate(&mut rand::rngs::OsRng);
    let rid: [u8; 32] = Sha256::digest(b"integ-resale").into();

    let t1 = make_signed_transfer(&seller, &buyer_a.verifying_key().to_bytes(), &rid);
    let (status, _) = srv.post_json("/v1/submit", &submit_body(&t1)).await;
    assert_eq!(status, 200);

    let t2 = make_signed_transfer(&buyer_a, &buyer_b.verifying_key().to_bytes(), &rid);
    let (status, data) = srv.post_json("/v1/submit", &submit_body(&t2)).await;
    assert_eq!(status, 200);
    assert_eq!(data["index"], 1);
    assert_eq!(data["log_size"], 2);

    let (status, receipt) = srv.get_json(&format!("/v1/receipt/{}", hex::encode(rid))).await;
    assert_eq!(status, 200);
    assert_eq!(receipt["owner"], hex::encode(buyer_b.verifying_key().to_bytes()));
    assert_eq!(receipt["transfer_count"], 2);
}

#[tokio::test]
async fn not_found_returns_404() {
    let srv = start_server().await;

    let (status, _) = srv.get_json("/v1/proof/0").await;
    assert_eq!(status, 404);

    let (status, _) = srv.get_json("/v1/entry/0").await;
    assert_eq!(status, 404);

    let (status, _) = srv.get_json("/v1/checkpoint").await;
    assert_eq!(status, 404);

    let fake = "a".repeat(64);
    let (status, _) = srv.get_json(&format!("/v1/receipt/{}", fake)).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn multiple_receipts_with_proofs() {
    let srv = start_server().await;
    let seller = SigningKey::generate(&mut rand::rngs::OsRng);
    let buyer = SigningKey::generate(&mut rand::rngs::OsRng);

    for i in 0..3u8 {
        let rid: [u8; 32] = Sha256::digest(&[i]).into();
        let t = make_signed_transfer(&seller, &buyer.verifying_key().to_bytes(), &rid);
        let (status, data) = srv.post_json("/v1/submit", &submit_body(&t)).await;
        assert_eq!(status, 200);
        assert_eq!(data["index"], i as u64);
    }

    for i in 0..3 {
        let (status, proof) = srv.get_json(&format!("/v1/proof/{}", i)).await;
        assert_eq!(status, 200);
        assert_eq!(proof["log_size"], 3);
    }

    let (status, h) = srv.get_json("/v1/health").await;
    assert_eq!(status, 200);
    assert_eq!(h["log_size"], 3);
}

#[tokio::test]
async fn witness_endpoint() {
    let srv = start_server().await;
    let seller = SigningKey::generate(&mut rand::rngs::OsRng);
    let buyer = SigningKey::generate(&mut rand::rngs::OsRng);
    let rid: [u8; 32] = Sha256::digest(b"integ-witness").into();

    // Submit a transfer to get a checkpoint
    let transfer = make_signed_transfer(&seller, &buyer.verifying_key().to_bytes(), &rid);
    let (status, data) = srv.post_json("/v1/submit", &submit_body(&transfer)).await;
    assert_eq!(status, 200);

    // Extract checkpoint data
    let cp_root = data["checkpoint"]["root"].as_str().unwrap();
    let cp_log_size = data["checkpoint"]["log_size"].as_u64().unwrap();
    let cp_timestamp = data["checkpoint"]["timestamp"].as_u64().unwrap();
    let cp_op_sig = data["checkpoint"]["operator_signature"].as_str().unwrap();

    // Request witness from another node (simulated by same server)
    let witness_req = json!({
        "checkpoint": {
            "root": cp_root,
            "log_size": cp_log_size,
            "timestamp": cp_timestamp,
        },
        "operator_key": data["checkpoint"]["root"].as_str().unwrap(), // Placeholder
        "operator_signature": cp_op_sig,
    });

    // This will fail because operator_key doesn't match signature, but tests endpoint exists
    let (status, _) = srv.post_json("/v1/internal/witness", &witness_req).await;
    assert!(status == 400 || status == 409); // BadRequest or Conflict
}

#[tokio::test]
async fn witnessed_checkpoints() {
    // Start server 1 (will be witnessed)
    let srv1 = start_server().await;
    
    // Start server 2 (witness)
    let srv2 = start_server().await;
    
    // Create a server 3 with witnessing enabled pointing to srv2
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let operator_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let operator_key_hex = hex::encode(operator_key.verifying_key().to_bytes());
    let store = Store::open(&db_path, operator_key.clone()).unwrap();

    // Configure witness client pointing to srv2
    let witness_client = tessera_log_server::witness::WitnessClient::new(
        vec![srv2.url.clone()],
        1, // threshold = 1
    );

    let state = Arc::new(api::AppState {
        store: Mutex::new(store),
        operator_key_hex,
        start_time: Instant::now(),
        witness_state: Mutex::new(WitnessState::new()),
        signing_key: operator_key,
        witness_client: Some(witness_client),
    });

    let app = Router::new()
        .route("/v1/health", get(api::health))
        .route("/v1/submit", post(api::submit))
        .route("/v1/checkpoint", get(api::checkpoint))
        .route("/v1/internal/witness", post(api::witness))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let url = format!("http://{}", addr);
    let client = Client::new();

    // Wait for server to be ready
    for _ in 0..50 {
        if client.get(&format!("{}/v1/health", url)).send().await.is_ok() {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }

    // Submit a transfer to srv3 (which will request witness from srv2)
    let seller = SigningKey::generate(&mut rand::rngs::OsRng);
    let buyer = SigningKey::generate(&mut rand::rngs::OsRng);
    let rid: [u8; 32] = Sha256::digest(b"witnessed-test").into();
    let transfer = make_signed_transfer(&seller, &buyer.verifying_key().to_bytes(), &rid);

    let resp = client
        .post(&format!("{}/v1/submit", url))
        .json(&submit_body(&transfer))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    let data: Value = resp.json().await.unwrap();

    // Verify checkpoint has witnesses
    let witnesses = data["checkpoint"]["witnesses"].as_array().unwrap();
    assert_eq!(witnesses.len(), 1, "should have 1 witness signature");
    assert!(witnesses[0]["witness_key"].as_str().unwrap().len() == 64);
    assert!(witnesses[0]["signature"].as_str().unwrap().len() == 128);
}
