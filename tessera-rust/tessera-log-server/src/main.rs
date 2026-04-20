mod config;

use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use ed25519_dalek::SigningKey;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use config::Config;
use tessera_log_server::api;
use tessera_log_server::store::Store;
use tessera_log_server::witness::{WitnessClient, WitnessState};

fn load_or_generate_key(path: &str) -> SigningKey {
    if let Ok(bytes) = fs::read(path) {
        if bytes.len() == 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            tracing::info!(path, "loaded operator key");
            return SigningKey::from_bytes(&seed);
        }
        tracing::warn!(path, len = bytes.len(), "key file wrong size, regenerating");
    }

    let mut rng = rand::rngs::OsRng;
    let key = SigningKey::generate(&mut rng);
    fs::write(path, key.to_bytes()).expect("failed to write key file");

    let pub_path = format!("{}.pub", path.trim_end_matches(".key"));
    let pub_hex = hex::encode(key.verifying_key().to_bytes());
    fs::write(&pub_path, &pub_hex).expect("failed to write public key file");

    tracing::info!(path, pub_path, "generated new operator key");
    key
}

#[tokio::main]
async fn main() {
    let config = Config::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_new(&config.log_level).unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let signing_key = load_or_generate_key(&config.key_file);
    let operator_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

    tracing::info!(
        bind = %config.bind,
        operator_key = %operator_key_hex,
        "starting tessera-log-server"
    );

    let store = Store::open(Path::new(&config.db), signing_key.clone()).expect("failed to open database");
    tracing::info!(log_size = store.log_size(), "loaded log state");

    // Create witness client if peers configured
    let witness_client = if !config.peers.is_empty() && config.witness_threshold > 0 {
        tracing::info!(
            peers = config.peers.len(),
            threshold = config.witness_threshold,
            "witness client enabled"
        );
        Some(WitnessClient::new(config.peers.clone(), config.witness_threshold))
    } else {
        tracing::info!("witness client disabled (no peers configured)");
        None
    };

    let state = Arc::new(api::AppState {
        store: Mutex::new(store),
        operator_key_hex,
        start_time: Instant::now(),
        witness_state: Mutex::new(WitnessState::new()),
        signing_key,
        witness_client,
    });

    let app = Router::new()
        .route("/v1/health", get(api::health))
        .route("/v1/submit", post(api::submit))
        .route("/v1/proof/:index", get(api::proof))
        .route("/v1/entry/:index", get(api::entry))
        .route("/v1/receipt/:receipt_id", get(api::receipt))
        .route("/v1/checkpoint", get(api::checkpoint))
        .route("/v1/internal/witness", post(api::witness))
        .with_state(state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = config.bind.parse().expect("invalid bind address");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");
    tracing::info!(%addr, "listening");

    axum::serve(listener, app).await.expect("server error");
}
