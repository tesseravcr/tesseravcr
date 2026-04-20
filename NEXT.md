# Next Steps

## What's proven

77+ tests. Zero failures. Two languages. Byte-identical hashes. The primitive is formally sound.

| Claim | Evidence | Tests |
|---|---|---|
| Receipt integrity | Signatures, hashing, tamper detection | 25 |
| Incentive dominance | 90k parameter sweep, 100% of realistic conditions | 7 |
| Attack resistance | 500 rounds, 5 strategies, all unprofitable | 10 |
| Edge case coverage | 6 categories, every boundary in spec 14.4 | 22 |
| Cross-language conformance | Rust produces byte-identical canonical output | 16 |
| Backend agnosticism | ZK (Halo2) and TEE (Nitro) wrap identically | demo.py |
| Network POC | 3 agents, HTTP, SQLite, Merkle proofs, DAG | tessera-network |
| Spec tightened | VK retrieval, backend trust tiers, extensions vector | Phase 1A done |
| Real compute | Ollama llama3.2:1b, real hashes, real receipts | Phase 1B done |
| Network protocol | Section 11.3: participants, messages, submission flow, witnessing, incentives | Spec done |

## What's not proven

| Gap | Why it matters | Blocks |
|---|---|---|
| Distributed transparency logs | Whitepaper's double-spend claim rests on this | Phase 2 |
| Multi-log witnessing / threshold | Single log = single point of trust | Phase 2 |
| Autonomous agent dynamics | Scripted tests prove mechanics, not emergence | Phase 3 |
| Payment settlement | Royalties computed but never paid | Phase 3 |

---

## The plan

Five phases. Each has a single exit criterion. No phase starts until its predecessor's criterion is met.

---

### Phase 1: Close the foundation (DONE)

**1A. Spec tightening** -- DONE
- Section 7.4: Backend security models (ZK vs TEE trust assumptions)
- Section 7.5: Verification key retrieval options
- `receipt_with_extensions` test vector in TEST-VECTORS.json
- Downstream consistency: generate_test_vectors.py, conformance.rs (16 tests), WHITEPAPER.md cross-refs

**1B. Real compute** -- DONE
- Ollama integration in tessera-network/node.py
- Real LLM inference (llama3.2:1b), real hashes, real receipts
- Token count mapped to nominal original_price
- TESSERA_MOCK=1 fallback preserved
- Full network test passing with real compute

---

### Phase 2: Log server + seed nodes (3 weeks) — IN PROGRESS

This is the network. The log server isn't infrastructure for the network — it IS the network, the same way bitcoind IS Bitcoin. Someone deploying a log server IS joining the network.

**Build in Rust.** Not Go. Reasons:
- `tessera-rust` already has proven canonical serialization (byte-identical to Python).
- Adding Go means maintaining conformance across three languages. Every spec change = three updates.
- The `transparency-dev/tessera` Go library has a name collision with this project.
- Rust gives memory safety for long-running log servers, which matters.
- Building it properly matters. This will be scrutinised. Flimsy breaks trust.

**What to build:**

A standalone binary: `tessera-log-server`.

Core:
- Append-only Merkle tree (spec Section 11.1 exactly: `0x00` leaf prefix, `0x01` node prefix, odd-leaf duplication).
- Persistent storage (SQLite, WAL mode).
- Inclusion proof generation and verification (spec Section 11.2).
- Checkpoint signing (Ed25519, operator's key).
- Double-spend detection (spec Section 11.3.8: check from_key matches current owner).
- Duplicate leaf rejection (spec Section 11.1: reject identical leaf_hash).

API (HTTP, axum):
- `POST /v1/submit` — signed transfer record in, inclusion proof + checkpoint out.
- `GET /v1/receipt/{receipt_id}` — current owner + transfer history + latest inclusion proof.
- `GET /v1/checkpoint` — signed latest Merkle root + tree size.
- `GET /v1/proof/{index}` — inclusion proof for entry at index.
- `GET /v1/health` — uptime, tree size, last append time.

Witnessing (phase 2b, after single-node works):
- Each log queries the other seed logs for their latest checkpoint.
- A checkpoint is only published when N-of-M witnesses countersign.
- Start with 2-of-3 across the three seed nodes.

**Deploy 3 seed nodes:**

| Node | Provider | Region | Why |
|---|---|---|---|
| log1.tesseravcr.org | DigitalOcean | US-East | Reliable, dev-friendly |
| log2.tesseravcr.org | Hetzner | EU (Germany) | Geographic diversity, cheap |
| log3.tesseravcr.org | DigitalOcean | US-West | Provider + region diversity |

Docker + Caddy (automatic TLS). systemd for restarts. Total cost: ~$16.50/month.

Ship with a `README.md` containing "Run your own log node" instructions (Docker one-liner). This is what makes it self-hostable and signals decentralisation.

**Exit criterion:** Three log nodes running on separate infrastructure. A transfer record appended to one log can be verified via inclusion proof on any of the three. Double-spend attempt across logs is detected. `docker run` starts a new log node in under 60 seconds.

**Status (2026-04-20):**
- ✅ Log server implementation complete (23 tests passing)
- ✅ Docker image pipeline configured
- ✅ Deployment automation ready
- 🚧 Provisioning 3 VMs (Hetzner)
- 🚧 DNS configuration (log1/log2/log3.tesseravcr.org)
- ⏳ End-to-end cross-log verification test

---

### Phase 3: On-ramp + live agents (2 weeks)

Two workstreams, sequential. SDK wrappers first (they enable the agents).

**3A. SDK wrappers (week 1)**

Thin Python wrappers that let existing agent frameworks emit VCRs without changing their logic.

Target frameworks (pick two, in order of ecosystem size):
1. LangGraph / LangChain
2. CrewAI
3. AutoGen

Each wrapper:
- Intercepts tool calls or sub-agent invocations.
- Creates a VCR receipt wrapping the call (model_id, input_hash, output_hash, timestamp).
- Signs with the agent's Ed25519 key.
- Appends to a configured log server.
- Returns the original result unchanged (wrapper is transparent).

Target: <20 lines of integration code per framework. The wrapper should feel like adding a middleware, not rewriting the agent.

Publish as `tessera-sdk` on PyPI.

**3B. Seed agents + live demo (week 2)**

Deploy 5 agents on the seed infrastructure, each doing real (cheap) work:
1. Math/reasoning agent (Claude Haiku).
2. Web search summariser.
3. Code review agent.
4. Orchestrator agent that consumes outputs from agents 1-3 (creates multi-parent provenance DAGs).
5. Buyer agent that discovers, purchases, and resells VCRs (exercises transfer + royalty cascade).

These are not scripted. They run autonomously, choosing counterparties from the registry, negotiating based on trust quotients.

Update `tesseravcr.github.io` to show:
- Live receipt feed from all three log nodes.
- DAG explorer (click a receipt, see its parents and children).
- Royalty cascade visualisation (who gets paid when a receipt is resold).
- Trust quotient leaderboard (which operators have the most stake).
- "Receipts on network" counter (real number, not mocked).

**Exit criterion:** 5 autonomous agents producing real VCRs. Provenance DAGs forming without human intervention. Live demo site shows real data from real logs. A visitor can verify any receipt independently.

---

### Phase 4: Prove the dynamics (2 weeks)

The spec claims self-collateralising trust emerges from the protocol rules. This phase tests that claim empirically.

**Simulation at scale:**
- 20+ agents with varying budgets, models, and strategies.
- 1000+ interactions.
- Include 3-5 adversarial agents (sybil, wash trader, price inflator — reuse strategies from test_adversarial.py but now on the live network, not in-memory).

**Metrics to capture:**
- Stake distribution over time (does it converge or centralise?).
- Gini coefficient of the trust network.
- Cold-start time: how many interactions until a new operator reaches trust quotient > 5?
- Price discovery: do prices converge toward "fair value" for equivalent compute?
- Attack profitability: do adversarial agents remain unprofitable on the live network?
- DAG depth distribution: how deep do natural provenance chains get?

**Visualise the network graph.** Publish the results as a technical report alongside the demo. This is the evidence that the economic model works, not just the cryptography.

**Exit criterion:** Published metrics showing trust network self-organises under realistic conditions. Adversarial agents remain unprofitable. Cold-start operators reach meaningful participation within a bounded number of interactions.

---

### Phase 5: Launch

**Hacker News post:**

> **Show HN: Verified Compute Receipts -- a spec for agent-to-agent trust without blockchain**
>
> When your agent transacts with an agent it's never met, there's no receipt. No proof of what model ran, what went in, what came out.
>
> I wrote a formal spec (21 fields), reference implementations in Python and Rust (identical hashes), and ran adversarial simulations against 5 attack strategies. Receipts chain into provenance DAGs with automatic royalty cascades. No token, no blockchain. MIT license.
>
> Live network: https://tesseravcr.github.io
> Spec + code: https://github.com/tesseravcr
>
> Curious whether this resonates or if I'm early.

**Targeted outreach (same week):**
- EZKL team (ZK-ML proving backend alignment).
- Sigstore / transparency-dev maintainers (CT log model alignment).
- Agent framework communities: LangChain Discord, CrewAI, AutoGen.
- AI security researchers (the verification gap is their problem).
- r/MachineLearning, Latent Space podcast/newsletter, AI Engineer community.

**Do not launch before Phase 3 is complete.** A spec with no live infrastructure is forgettable. A live demo with real receipts flowing is memorable.

---

## Timeline

| Phase | Duration | Cumulative |
|---|---|---|
| 1. Close the foundation | DONE | -- |
| 2. Log server + seed nodes | 3 weeks | Week 3 |
| 3. On-ramp + live agents | 2 weeks | Week 5 |
| 4. Prove the dynamics | 2 weeks | Week 7 |
| 5. Launch | 1 week | Week 8 |

8 weeks from today to credible public launch with live infrastructure.

Phases 2-3 are non-negotiable. Phase 4 strengthens the launch but could be compressed if momentum demands earlier visibility. Phase 5 must not happen before Phase 3.

---

## What is deliberately deferred

| Item | Why deferred |
|---|---|
| Payment rails (Stripe, crypto, Lightning) | IOUs + accounting sufficient for demo. Real money adds compliance burden. |
| P2P networking / NAT traversal (libp2p) | Seed nodes on public IPs. P2P only matters at scale. |
| Kademlia DHT discovery | Hardcoded bootstrap nodes sufficient for <50 operators. |
| Model registry / content addressing (IPFS) | Human-readable model IDs work when provider is trusted. Content addressing matters for open-weight models. |
| Smart contract checkpoints | Transparency logs with witnessing are sufficient. On-chain anchoring is a trust multiplier, not a prerequisite. |
| Deep royalty cascades (>3 levels) | Geometric diminishment makes deep levels negligible. 2-3 levels proven; deeper is the same algorithm. |
| Schema version migration | v1 is the only version. Migration mechanics matter when v2 exists. |

---

## Cleanup

The `tessera/` directory in the repo root is empty scaffolding from a "2030 vision" exercise. It contains no code — just directory structure and aspirational docs. It should be deleted. The actual implementations are:

- `tessera-py/` — Python reference implementation (protocol primitives)
- `tessera-rust/` — Rust conformant implementation (canonical serialization, signing)
- `tessera-network/` — Network POC (nodes, log, tests) — not on GitHub, prototype only
- `spec/` — VCR-SPEC.md, WHITEPAPER.md, TEST-VECTORS.json
