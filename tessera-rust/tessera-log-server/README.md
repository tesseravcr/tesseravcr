# Tessera Log Server

Transparency log server for Verified Compute Receipts (VCR).

## Quick Start

### Docker Compose (3-node local cluster)

```bash
docker-compose up -d
```

This starts 3 independent log nodes:
- **log1**: http://localhost:7801
- **log2**: http://localhost:7802
- **log3**: http://localhost:7803

Check health:
```bash
curl http://localhost:7801/v1/health
curl http://localhost:7802/v1/health
curl http://localhost:7803/v1/health
```

Stop cluster:
```bash
docker-compose down -v
```

### Docker (single node)

```bash
docker build -t tessera-log-server .
docker run -d -p 7800:7800 -v tessera-data:/data tessera-log-server
```

### From Source

```bash
cargo run --release
```

## Configuration

Environment variables:
- `TESSERA_DB` - Database path (default: `/data/tessera-log.db`)
- `TESSERA_KEY_FILE` - Operator key path (default: `/data/operator.key`)
- `TESSERA_BIND` - Listen address (default: `0.0.0.0:7800`)
- `TESSERA_LOG_LEVEL` - Log level (default: `info`)

Command-line flags:
```bash
tessera-log-server --help
```

## API Endpoints

- `GET /v1/health` - Server health and status
- `POST /v1/submit` - Submit signed transfer record
- `GET /v1/proof/:index` - Get inclusion proof for entry
- `GET /v1/entry/:index` - Get transfer entry details
- `GET /v1/receipt/:receipt_id` - Get receipt ownership and history
- `GET /v1/checkpoint` - Get latest signed checkpoint

## Image Size

**24.6 MB** (Alpine-based multi-stage build)

## Performance

- **Startup time**: ~18s for 3-node cluster
- **Storage**: SQLite with WAL mode
- **Concurrency**: Tokio async runtime

## License

MIT
