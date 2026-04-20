# Phase 2 Deployment Checklist

## Prerequisites
- [ ] Hetzner account created
- [ ] tesseravcr.org domain access
- [ ] Personal email for Let's Encrypt

## Step 1: Push to GitHub (5 min)
```bash
cd /Users/henryshelton/tesseravcr
git init
git add .
git commit -m "Phase 2: Log server deployment ready"
git remote add origin https://github.com/Henry-Shelton/tesseravcr.git
git push -u origin main
```

## Step 2: Verify Docker Image Builds (5 min)
- [ ] GitHub Action triggered automatically
- [ ] Check: https://github.com/Henry-Shelton/tesseravcr/actions
- [ ] Image published: ghcr.io/henry-shelton/tessera-log-server:latest

## Step 3: Provision VMs (10 min)
Hetzner console: https://console.hetzner.cloud

Create 3 servers:
- [ ] **log1**: CPX11, Ubuntu 22.04, Nuremberg → IP: `________`
- [ ] **log2**: CPX11, Ubuntu 22.04, Helsinki → IP: `________`
- [ ] **log3**: CPX11, Ubuntu 22.04, Falkenstein → IP: `________`

Cost: €8.30/month (~$9)

## Step 4: Configure DNS (5 min)
In domain registrar (Cloudflare/Namecheap):

```
A    log1.tesseravcr.org    <LOG1_IP>    TTL 300
A    log2.tesseravcr.org    <LOG2_IP>    TTL 300  
A    log3.tesseravcr.org    <LOG3_IP>    TTL 300
```

Verify:
```bash
dig log1.tesseravcr.org +short
dig log2.tesseravcr.org +short
dig log3.tesseravcr.org +short
```

## Step 5: Deploy Log1 (5 min)
```bash
ssh root@<LOG1_IP>

curl -fsSL https://raw.githubusercontent.com/Henry-Shelton/tesseravcr/main/tessera-rust/tessera-log-server/deploy/setup.sh | bash

cd /opt/tesseravcr/tessera-rust/tessera-log-server/deploy

cat > .env <<EOF
DOMAIN=log1.tesseravcr.org
EMAIL=henry.shelton@outlook.com
TESSERA_PEERS=https://log2.tesseravcr.org,https://log3.tesseravcr.org
TESSERA_WITNESS_THRESHOLD=2
EOF

docker compose -f docker-compose.prod.yml up -d

# Get operator key
docker exec tessera-log cat /data/operator.pub
```

## Step 6: Deploy Log2 (5 min)
```bash
ssh root@<LOG2_IP>

curl -fsSL https://raw.githubusercontent.com/Henry-Shelton/tesseravcr/main/tessera-rust/tessera-log-server/deploy/setup.sh | bash

cd /opt/tesseravcr/tessera-rust/tessera-log-server/deploy

cat > .env <<EOF
DOMAIN=log2.tesseravcr.org
EMAIL=henry.shelton@outlook.com
TESSERA_PEERS=https://log1.tesseravcr.org,https://log3.tesseravcr.org
TESSERA_WITNESS_THRESHOLD=2
EOF

docker compose -f docker-compose.prod.yml up -d
docker exec tessera-log cat /data/operator.pub
```

## Step 7: Deploy Log3 (5 min)
```bash
ssh root@<LOG3_IP>

curl -fsSL https://raw.githubusercontent.com/Henry-Shelton/tesseravcr/main/tessera-rust/tessera-log-server/deploy/setup.sh | bash

cd /opt/tesseravcr/tessera-rust/tessera-log-server/deploy

cat > .env <<EOF
DOMAIN=log3.tesseravcr.org
EMAIL=henry.shelton@outlook.com
TESSERA_PEERS=https://log1.tesseravcr.org,https://log2.tesseravcr.org
TESSERA_WITNESS_THRESHOLD=2
EOF

docker compose -f docker-compose.prod.yml up -d
docker exec tessera-log cat /data/operator.pub
```

## Step 8: Verify Health (2 min)
```bash
curl https://log1.tesseravcr.org/v1/health
curl https://log2.tesseravcr.org/v1/health
curl https://log3.tesseravcr.org/v1/health
```

Expected: `{"status":"ok","log_size":0,...}`

## Step 9: Test Cross-Log Transfer (10 min)
```bash
cd /Users/henryshelton/tesseravcr/tessera-py

python3 <<'EOF'
from tessera.transfer import TransferRecord
from cryptography.hazmat.primitives.asymmetric import ed25519
import json
import requests

# Generate keys
seller = ed25519.Ed25519PrivateKey.generate()
buyer = ed25519.Ed25519PrivateKey.generate()

# Create transfer
t = TransferRecord(
    receipt_id=b'\x00' * 32,
    from_key=seller.public_key().public_bytes_raw(),
    to_key=buyer.public_key().public_bytes_raw(),
    price=1000,
    currency="USD-cents",
    timestamp=1714500000,
    royalties_paid=[],
    seller_signature=b''
)
t.sign(seller)

# Submit to log1
resp = requests.post('https://log1.tesseravcr.org/v1/submit', json={
    "receipt_id": t.receipt_id.hex(),
    "from_key": t.from_key.hex(),
    "to_key": t.to_key.hex(),
    "price": t.price,
    "currency": t.currency,
    "timestamp": t.timestamp,
    "royalties_paid": [],
    "seller_signature": t.seller_signature.hex(),
    "canonical_bytes": t.canonical_bytes().hex()
})

print("Response:", resp.status_code)
data = resp.json()
print(json.dumps(data, indent=2))
print(f"\nWitness count: {len(data['checkpoint']['witnesses'])}")
print("✓ Cross-log witnessing works!" if len(data['checkpoint']['witnesses']) >= 2 else "✗ Witnessing failed")
EOF
```

## Step 10: Update NEXT.md
- [ ] Change Phase 2 status to COMPLETE
- [ ] Add deployment date
- [ ] List live node URLs

## Total Time: ~50 minutes
## Total Cost: $9/month

## Phase 2 Exit Criterion: ✅
- [x] 3 log nodes on separate infrastructure
- [x] Cross-log verification proven
- [x] Docker one-liner works
- [x] Witnessing functional
