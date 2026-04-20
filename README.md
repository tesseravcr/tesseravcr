# Tessera VCR

A protocol for verified computation between autonomous agents.

When an agent computes something, it produces a receipt: a signed data structure that proves what model ran, what went in, what came out, and when. Any other agent can verify that receipt without contacting the original producer. No platform in the middle. No chain to wait on. No token required.

Receipts chain into provenance graphs, settle royalties automatically, and accumulate into an operator's trust history. That history becomes their collateral — the more verified work an operator has done, the less escrow they need for future transactions. Trust is derived from computation, not from deposits.

## Repository Structure

```
spec/              Protocol specification — the canonical definition of VCR
tessera-py/        Reference implementation in Python
tessera-rust/      Conformant implementation in Rust
tessera-network/   Network POC — agents transacting over HTTP
```

### spec/

The protocol specification. Implementation-agnostic. Contains the formal spec ([VCR-SPEC.md](spec/VCR-SPEC.md)), the whitepaper ([WHITEPAPER.md](spec/WHITEPAPER.md)), and reference test vectors ([TEST-VECTORS.json](spec/TEST-VECTORS.json)).

A developer building a conformant implementation in any language starts here.

### tessera-py/

Reference implementation of the VCR protocol in Python. Seven modules, ~1500 lines, one external dependency (`cryptography`). Includes a demo using real AWS Nitro Enclave attestation, a real ezkl Halo2 ZK proof, and a 25-test protocol validation suite.

```
pip install cryptography
cd tessera-py && python3 demo.py
```

### tessera-rust/

Conformant implementation in Rust. Produces identical `receipt_id` values for identical fields, verified against `spec/TEST-VECTORS.json`. Proves the specification is language-agnostic.

### tessera-network/

Network proof of concept. Three agents on separate ports with separate databases communicate only through HTTP. Demonstrates discovery, compute, cold verification, provenance DAG construction, ownership transfer with royalty cascade, and independent chain verification.

```
cd tessera-network && python3 poc.py
```

## The Protocol

21 fields. Three things at once:

**A proof of work performed.** Carries the ZK proof or TEE attestation, model ID, and verification key. Any stranger can verify the computation.

**A certificate of provenance.** Links to parent VCRs via cryptographic hash references, forming a DAG. Modify any receipt and all descendants break.

**A transferable economic instrument.** Carries pricing, royalty terms, and transfer history. When a VCR changes hands, royalties flow back through the provenance chain automatically.

## How It Relates to Existing Protocols

**Tool-use protocols** (MCP, APIs) solve integration. They connect agents to endpoints. The response is ephemeral — consumed and gone.

**Agent frameworks** (LangChain, CrewAI, AutoGen) solve orchestration within a single trust boundary.

**Agent communication** (A2A) solves discovery and message passing. It says nothing about whether the agent did what it claimed.

**Blockchain AI** (Bittensor, Ritual) requires a chain, a token, and consensus. They financialise the network itself.

**VCR** sits underneath all of these. It is a verification and trust primitive. No token, no chain, no middleman. The receipt is the economic object. The accumulated receipts are the trust.

## Architecture

```
Layer 4: Application      Agents, marketplace, network POC
Layer 3: Protocol          VCR schema, provenance, settlement, stake, royalties
Layer 2: Ownership         Transparency logs — append-only Merkle trees
Layer 1: Proving backend   ZK proof or TEE attestation — two functions
```

The proving backend abstraction is two functions:
```
prove(artifacts, input_data) → (proof_bytes, output_data)
verify(artifacts, proof_bytes) → bool
```

Everything above this interface is backend-agnostic.

MIT license.

---

## Live Network

**Seed transparency log servers** (Phase 2 - deploying):
- https://log1.tesseravcr.org (US-East)
- https://log2.tesseravcr.org (EU-Germany)
- https://log3.tesseravcr.org (US-West)

Check health:
```bash
curl https://log1.tesseravcr.org/v1/health
```

## Run Your Own Log Node

Deploy your own transparency log server in under 5 minutes:

```bash
# On Ubuntu 22.04+ VPS ($4-6/month):
curl -fsSL https://raw.githubusercontent.com/Henry-Shelton/tesseravcr/main/tessera-rust/tessera-log-server/deploy/setup.sh | sudo bash

# Edit configuration:
cd /opt/tesseravcr/tessera-rust/tessera-log-server/deploy
sudo nano .env  # Set DOMAIN, EMAIL, TESSERA_PEERS

# Start services:
sudo docker compose -f docker-compose.prod.yml up -d

# Get your operator public key:
sudo docker exec tessera-log cat /data/operator.pub
```

Your node automatically witnesses checkpoints from configured peers. No registration or permission required.

**Cost:** $4-6/month (Hetzner CPX11, DigitalOcean Basic) or $0 (Oracle Cloud Free Tier)

See [deployment guide](tessera-rust/tessera-log-server/deploy/README.md) for details.
