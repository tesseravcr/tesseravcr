# tessera-network

**Proof-of-concept: Algorithmic trust from cryptographic work history.**

This repo proves VCR's core primitive: agents build verifiable reputation through signed receipts, hash-linked provenance, and transparency logs. Trust is computed algorithmically from public data. No platforms. No human judgment. Just cryptographic math.

## What this proves

1. **Receipts work** — Ed25519 signatures + SHA-256 content binding
2. **Provenance DAG works** — Hash-linked parent receipts form tamper-evident graph  
3. **Trust computation works** — Stake = direct value + vouched capital
4. **Vouching works** — Established agents stake for newcomers (cold start solution)
5. **Transparency logs work** — Append-only Merkle tree (RFC 6962) with inclusion proofs
6. **Everything is cryptographically verifiable** — Zero-trust audit from raw database

## Files

```
merkle.py              Standard Merkle tree (RFC 6962)
log_store.py           SQLite persistence (receipts, DAG, vouches)
transparency.py        Transparency log (indexing + proofs)
log_server.py          HTTP API (15 endpoints)
node.py                Agent node (compute + trust computation)
test_network.py        Full demo (4 agents, receipts → trust)
generate_visuals.py    Visual proof generator (PNG graphs + HTML)
verify_artifacts.py    Cryptographic verification (signatures, hashes, proofs)
```

**Total: ~2,500 lines**

## Quick start

Run the full demo:
```bash
python3 test_network.py
```

This starts 4 agents (Alpha, Beta, Gamma, Delta), a transparency log, and demonstrates:
- Receipt creation and signing
- Provenance DAG construction
- Trust score computation
- Vouching mechanism
- Transfer of ownership

Generate visual proof:
```bash
python3 generate_visuals.py
```

Creates `visualizations/index.html` with:
- Provenance DAG (who builds on whose work)
- Trust scores (stake vs transaction value)
- Agent network (interaction graph)
- Timeline (all events chronologically)

Verify cryptographic properties:
```bash
python3 verify_artifacts.py
```

Proves from raw database:
- Ed25519 signatures valid
- Output hashes match
- DAG links correct
- Merkle inclusion proofs valid
- Trust scores computed correctly
- Vouch signatures valid

## Dependencies

```bash
pip install flask cryptography requests matplotlib networkx
```

## How it works

**Identity**: Ed25519 keypairs. Each agent signs their receipts.

**Content binding**: SHA-256 hashes commit to input/output data.

**Provenance**: Receipts reference parent receipt IDs, forming a DAG.

**Trust**: `effective_stake = direct_value + vouched_stake`. Trust quotient = stake / transaction_value.

**Settlement recommendations**:
- Quotient ≥ 50: instant settlement
- Quotient 5-50: escrow
- Quotient < 5: collateral required

**Vouching**: Agent A stakes $X for Agent B. If B defaults, A loses stake. Solves cold start.

**Transparency log**: All receipts indexed in append-only Merkle tree. Anyone can verify inclusion.

## The primitive

**Algorithmic trust from work history.**

- Not verification (LLMs aren't deterministic)
- Not reputation (no human judgment)  
- Not credit scores (no off-chain data)

Pure math: `trust = f(public_receipts, vouches)`. No platform required.

## Value proposition

For **AI agents**: Build portable reputation. Work history follows you across contexts.

For **clients**: Decide settlement method algorithmically. No trusted intermediaries.

For **networks**: Bootstrap trust without platforms. Vouching solves cold start.

## Visual proof

After running `generate_visuals.py`, open `visualizations/index.html` in a browser to see the live network state with all cryptographic artifacts rendered as graphs.
