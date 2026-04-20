# Deployment Plan for Seed Nodes

**Goal:** 3 log nodes live by tomorrow, Hacker News post-ready.

## Prerequisites

- [ ] GitHub repo public at `github.com/yourusername/tesseravcr`
- [ ] Domain: `tesseravcr.org` with DNS access
- [ ] Hetzner account (or DigitalOcean)
- [ ] Your email for Let's Encrypt certs

## Step 1: Publish Docker Image (30 mins)

Create `.github/workflows/docker-publish.yml`:

```yaml
name: Docker Build & Push

on:
  push:
    branches: [ main ]
    paths:
      - 'tessera-rust/**'
  workflow_dispatch:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3
      
      - name: Login to GitHub Container Registry
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          context: ./tessera-rust
          file: ./tessera-rust/tessera-log-server/Dockerfile
          push: true
          tags: |
            ghcr.io/${{ github.repository_owner }}/tessera-log-server:latest
            ghcr.io/${{ github.repository_owner }}/tessera-log-server:${{ github.sha }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

Push to GitHub, wait for Action to complete.

## Step 2: Provision VMs (10 mins)

### Hetzner (recommended: cheap + reliable)

```bash
# Via web UI:
# 1. Go to https://console.hetzner.cloud
# 2. Create project "tesseravcr"
# 3. Create 3 servers:
#    - log1: CPX11, Ubuntu 22.04, Nuremberg datacenter
#    - log2: CPX11, Ubuntu 22.04, Helsinki datacenter
#    - log3: CPX11, Ubuntu 22.04, Falkenstein datacenter (or use Oracle free tier)
# 4. Note down IPs:
#    LOG1_IP=<ip>
#    LOG2_IP=<ip>
#    LOG3_IP=<ip>
```

Cost: €8.30/month (~$9)

## Step 3: Configure DNS (5 mins)

In your domain registrar (Cloudflare, Namecheap, etc):

```
A    log1.tesseravcr.org    <LOG1_IP>    (proxy off if Cloudflare)
A    log2.tesseravcr.org    <LOG2_IP>    (proxy off)
A    log3.tesseravcr.org    <LOG3_IP>    (proxy off)
```

Wait 2-5 minutes for DNS propagation. Test:
```bash
dig log1.tesseravcr.org +short
```

## Step 4: Fix Deployment Files (10 mins)

### Update `deploy/Caddyfile`

```caddyfile
{
    email your-email@example.com
}

{$DOMAIN:localhost} {
    reverse_proxy localhost:7800
    encode gzip
    
    log {
        output file /var/log/caddy/access.log
        format json
    }
}
```

### Update `deploy/.env.example`

```bash
# Copy this to .env and edit with your actual values

# This node's public domain
DOMAIN=log1.tesseravcr.org

# Peer log URLs (comma-separated, exclude yourself)
TESSERA_PEERS=https://log2.tesseravcr.org,https://log3.tesseravcr.org

# Witness threshold (min signatures required)
TESSERA_WITNESS_THRESHOLD=2
```

### Update `deploy/docker-compose.prod.yml`

Add DOMAIN env var:

```yaml
services:
  tessera-log:
    image: ghcr.io/yourusername/tessera-log-server:latest
    # ... rest same ...
    
  caddy:
    image: caddy:2-alpine
    # ... rest same ...
    environment:
      - DOMAIN=${DOMAIN}
```

### Update `deploy/setup.sh`

Change:
```bash
git clone https://github.com/tesseravcr/tessera-rust.git
```

To:
```bash
git clone https://github.com/yourusername/tesseravcr.git
```

## Step 5: Deploy Node 1 (5 mins)

```bash
# SSH into log1
ssh root@<LOG1_IP>

# Run setup
curl -fsSL https://raw.githubusercontent.com/yourusername/tesseravcr/main/tessera-rust/tessera-log-server/deploy/setup.sh | bash

# Configure environment
cd /opt/tesseravcr/tessera-rust/tessera-log-server/deploy
cat > .env <<EOF
DOMAIN=log1.tesseravcr.org
TESSERA_PEERS=https://log2.tesseravcr.org,https://log3.tesseravcr.org
TESSERA_WITNESS_THRESHOLD=2
EOF

# Restart with new config
docker compose -f docker-compose.prod.yml down
docker compose -f docker-compose.prod.yml up -d

# Get operator public key
docker exec tessera-log cat /data/operator.pub
# Save this! You'll need it for verification
```

## Step 6: Deploy Nodes 2 & 3 (10 mins)

Repeat Step 5 on log2 and log3, changing:
- `DOMAIN=log2.tesseravcr.org` (or log3)
- `TESSERA_PEERS=` (exclude the current node)

## Step 7: Verify (5 mins)

```bash
# Test health endpoints
curl https://log1.tesseravcr.org/v1/health
curl https://log2.tesseravcr.org/v1/health
curl https://log3.tesseravcr.org/v1/health

# Each should return:
# {"status":"ok","log_size":0,"uptime_seconds":...}
```

## Step 8: Test Cross-Log Transfer (10 mins)

```bash
# Generate test transfer (on your local machine)
cd tesseravcr/tessera-py
python3 <<EOF
from tessera.transfer import TransferRecord
from cryptography.hazmat.primitives.asymmetric import ed25519
import json

# Generate keypair
seller_key = ed25519.Ed25519PrivateKey.generate()
buyer_key = ed25519.Ed25519PrivateKey.generate()

# Create transfer
transfer = TransferRecord(
    receipt_id=b'\x00' * 32,  # dummy receipt
    from_key=seller_key.public_key().public_bytes_raw(),
    to_key=buyer_key.public_key().public_bytes_raw(),
    price=1000,
    currency="USD-cents",
    timestamp=1714500000,
    royalties_paid=[],
    seller_signature=b''
)

# Sign it
transfer.sign(seller_key)

# Output as JSON
print(json.dumps({
    "receipt_id": transfer.receipt_id.hex(),
    "from_key": transfer.from_key.hex(),
    "to_key": transfer.to_key.hex(),
    "price": transfer.price,
    "currency": transfer.currency,
    "timestamp": transfer.timestamp,
    "royalties_paid": [],
    "seller_signature": transfer.seller_signature.hex(),
    "canonical_bytes": transfer.canonical_bytes().hex()
}, indent=2))
EOF
```

Save output to `transfer.json`, then:

```bash
# Submit to log1
curl -X POST https://log1.tesseravcr.org/v1/submit \
  -H "Content-Type: application/json" \
  -d @transfer.json

# Should return:
# {"index":0,"log_size":1,"checkpoint":{...,"witnesses":[...]}}

# Verify witnesses array has 2 signatures (from log2 and log3)
```

## Step 9: Update README for HN (30 mins)

Add to main README:

```markdown
## Try It Now

Three seed log servers are live:
- https://log1.tesseravcr.org
- https://log2.tesseravcr.org
- https://log3.tesseravcr.org

### Run Your Own Node

```bash
# On Ubuntu 22.04 VM:
curl -fsSL https://raw.githubusercontent.com/yourusername/tesseravcr/main/tessera-rust/tessera-log-server/deploy/setup.sh | sudo bash

# Configure:
cd /opt/tesseravcr/tessera-rust/tessera-log-server/deploy
cp .env.example .env
nano .env  # Edit DOMAIN and TESSERA_PEERS

# Start:
docker compose -f docker-compose.prod.yml up -d
```

Your node will automatically witness checkpoints from configured peers.

### Cost to Run

- **$4-6/month** for a VPS (Hetzner CPX11 or DigitalOcean Basic)
- **$0** using Oracle Cloud Free Tier
```

## Total Time: ~2 hours

## Total Cost: $9-15/month

## What Others See

1. Working demo with 3 live nodes
2. One-command deployment
3. Clear costs (cheap!)
4. Automatic TLS
5. Cross-node witnessing proven

## Blockers

- [ ] Docker image published (GitHub Actions)
- [ ] DNS configured
- [ ] VMs provisioned
- [ ] Deployment files updated with real URLs

## For Tomorrow's HN Post

Title: **Show HN: Tessera – Transparency logs for verified AI agent computation**

Body:
```
I built a protocol for verified compute receipts between AI agents.

When an agent performs a computation, it produces a cryptographically signed 
receipt proving what model ran, what inputs/outputs, and when. Any other 
agent can verify this independently, with no blockchain or central authority.

Receipts chain into provenance DAGs and track ownership transfers with 
automatic royalty cascades.

3 seed transparency log servers are live. You can run your own node for 
$4-6/month or free on Oracle Cloud.

Live demo: https://log1.tesseravcr.org/v1/health
Spec: https://github.com/yourusername/tesseravcr/blob/main/spec/VCR-SPEC.md
Docker one-liner in README.

Built this because autonomous agents need verifiable work history, and 
blockchain feels like the wrong abstraction.

Curious what HN thinks—too early? Missing something obvious?
```
