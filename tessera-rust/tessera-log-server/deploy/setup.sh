#!/bin/bash
set -euo pipefail

# Production deployment setup for tessera-log-server
# Run on fresh Ubuntu/Debian VM with sudo

echo "==> Installing dependencies"
apt-get update
apt-get install -y docker.io docker-compose-plugin git curl

echo "==> Starting Docker"
systemctl enable docker
systemctl start docker

echo "==> Creating data directory"
mkdir -p /var/lib/tessera
mkdir -p /var/log/caddy

echo "==> Cloning deployment config"
cd /opt
git clone https://github.com/Henry-Shelton/tesseravcr.git
cd tesseravcr/tessera-rust/tessera-log-server/deploy

echo "==> Setting up environment"
if [ ! -f .env ]; then
    cp .env.example .env
    echo "Created .env from template - YOU MUST EDIT IT:"
    echo "  nano /opt/tesseravcr/tessera-rust/tessera-log-server/deploy/.env"
    echo ""
    echo "Set DOMAIN, EMAIL, and TESSERA_PEERS for your node"
    exit 1
fi

echo "==> Pulling images"
docker compose -f docker-compose.prod.yml pull

echo "==> Starting services"
docker compose -f docker-compose.prod.yml up -d

echo "==> Waiting for health"
for i in {1..30}; do
    if curl -sf http://localhost:7800/v1/health > /dev/null; then
        echo "✓ Server is healthy"
        break
    fi
    echo "Waiting for server... ($i/30)"
    sleep 2
done

echo ""
echo "==> Deployment complete"
echo ""
echo "Check status:"
echo "  docker compose -f docker-compose.prod.yml ps"
echo ""
echo "View logs:"
echo "  docker compose -f docker-compose.prod.yml logs -f"
echo ""
echo "Get operator public key:"
echo "  docker exec tessera-log cat /data/operator.pub"
echo ""
