# Production Deployment

Deploy tessera-log-server with automatic TLS and cross-log witnessing.

## Quick Start

On a fresh VM (Ubuntu 22.04+):

```bash
curl -fsSL https://raw.githubusercontent.com/tesseravcr/tessera-rust/main/tessera-log-server/deploy/setup.sh | sudo bash
```

## Manual Setup

### 1. Install Docker

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-plugin
sudo systemctl enable docker
sudo systemctl start docker
```

### 2. Clone and Configure

```bash
git clone https://github.com/tesseravcr/tessera-rust.git
cd tessera-rust/tessera-log-server/deploy
```

Edit `.env` with your peer URLs:

```bash
TESSERA_PEERS=https://log1.example.com,https://log2.example.com,https://log3.example.com
TESSERA_WITNESS_THRESHOLD=2
```

### 3. Configure Caddy

Edit `Caddyfile` to set your domain:

```
your-domain.com {
    reverse_proxy localhost:7800
    ...
}
```

### 4. Deploy

```bash
sudo docker compose -f docker-compose.prod.yml up -d
```

### 5. Get Operator Key

```bash
sudo docker exec tessera-log cat /data/operator.pub
```

Share this key with peer operators.

## Architecture

```
Internet → Caddy (TLS) → Tessera Log Server
           :443           :7800
```

- **Caddy**: Automatic HTTPS via Let's Encrypt
- **Tessera**: Internal port 7800, not exposed
- **Data**: Persistent in `/var/lib/tessera`

## Multi-Node Setup

For 3-node production cluster:

### Node 1 (US-East)
```bash
# .env
TESSERA_PEERS=https://log2.example.com,https://log3.example.com
TESSERA_WITNESS_THRESHOLD=2
```

### Node 2 (EU)
```bash
# .env
TESSERA_PEERS=https://log1.example.com,https://log3.example.com
TESSERA_WITNESS_THRESHOLD=2
```

### Node 3 (US-West)
```bash
# .env
TESSERA_PEERS=https://log1.example.com,https://log2.example.com
TESSERA_WITNESS_THRESHOLD=2
```

After deployment:
1. Get each node's operator public key
2. Share keys with all operators (for manual verification)
3. Submit test transfer to node 1
4. Verify checkpoint has 2 witness signatures

## Management

### Check Status
```bash
docker compose -f docker-compose.prod.yml ps
```

### View Logs
```bash
docker compose -f docker-compose.prod.yml logs -f tessera-log
docker compose -f docker-compose.prod.yml logs -f caddy
```

### Stop Services
```bash
docker compose -f docker-compose.prod.yml down
```

### Update
```bash
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

### Backup
```bash
sudo tar -czf tessera-backup-$(date +%Y%m%d).tar.gz /var/lib/tessera
```

## Testing Production Deployment

### Health Check
```bash
curl https://your-domain.com/v1/health
```

### Submit Transfer
```bash
# See main README for transfer signing examples
curl -X POST https://your-domain.com/v1/submit \
  -H "Content-Type: application/json" \
  -d @transfer.json
```

### Verify Witnessing
```bash
# Check that checkpoint includes witness signatures
curl https://your-domain.com/v1/checkpoint | jq '.witnesses'
```

### Cross-Log Verification
```bash
# Submit to node 1
RECEIPT_ID=$(curl -X POST https://log1.example.com/v1/submit -d @transfer.json | jq -r '.checkpoint.root')

# Query on node 2 (should see same receipt after gossip)
curl https://log2.example.com/v1/receipt/$RECEIPT_ID
```

## Cost Estimate

Per node (DigitalOcean/Hetzner):
- **VM**: $6-12/month (1 CPU, 1GB RAM, 25GB SSD)
- **Bandwidth**: Included (1TB+)
- **Domain**: $12/year

**3-node cluster**: ~$20-40/month total

## Security

- All external traffic over TLS (automatic via Let's Encrypt)
- Operator keys stored in `/var/lib/tessera` (root-only)
- No exposed database ports
- Docker restart policy prevents downtime
- Healthchecks ensure Caddy only proxies when backend is ready

## Troubleshooting

### Caddy can't get certificate
- Check DNS points to server IP
- Ensure ports 80/443 are open in firewall
- Check logs: `docker compose logs caddy`

### Witness requests failing
- Verify peer URLs are correct in `.env`
- Check firewall allows outbound HTTPS
- Confirm peer nodes are running: `curl https://peer/v1/health`

### Database locked
- SQLite with WAL mode handles concurrent reads
- If issues persist, check disk space and inode usage

## Monitoring

Add to your monitoring stack:

```bash
# Health endpoint returns JSON
curl https://your-domain.com/v1/health
# Fields: status, log_size, root, uptime_seconds, operator_key
```

Alerts:
- HTTP 200 on `/v1/health`
- `log_size` increasing (append activity)
- `uptime_seconds` < 60 (recent restart)
