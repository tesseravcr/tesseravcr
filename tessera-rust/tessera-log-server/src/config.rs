use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "tessera-log-server", about = "Tessera VCR transparency log server")]
pub struct Config {
    /// SQLite database path
    #[arg(long, env = "TESSERA_DB", default_value = "tessera-log.db")]
    pub db: String,

    /// Listen address
    #[arg(long, env = "TESSERA_BIND", default_value = "0.0.0.0:7800")]
    pub bind: String,

    /// Ed25519 key file (32 raw bytes)
    #[arg(long, env = "TESSERA_KEY_FILE", default_value = "operator.key")]
    pub key_file: String,

    /// Peer log URLs (comma-separated)
    #[arg(long, env = "TESSERA_PEERS", value_delimiter = ',')]
    pub peers: Vec<String>,

    /// Required witness signatures
    #[arg(long, env = "TESSERA_WITNESS_THRESHOLD", default_value = "0")]
    pub witness_threshold: usize,

    /// Tracing log level
    #[arg(long, env = "TESSERA_LOG_LEVEL", default_value = "info")]
    pub log_level: String,
}
