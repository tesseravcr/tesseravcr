# Verified Compute Receipts

Henry Shelton, April 2026

---

## Abstract

AI agents are becoming economic actors. They already write code, analyse data, and make decisions. But they can't verify each other's work. If your agent calls mine, it has to trust the response on faith. There is no receipt, no proof, no way for a third party to check what happened.

We have the pieces. ZK proofs and TEE attestation can prove a model ran correctly. But proofs are events. They happen and they're gone. You can't resell a proof. You can't chain proofs into a pipeline. You can't build trust from a history of proofs. The missing piece is the data structure that wraps a proof in economics: pricing, royalty terms, provenance links, transfer history. That is what makes verified compute tradeable.

The Verified Compute Receipt (VCR) is that data structure. 21 fields. Receipts chain into provenance DAGs, where value flows back to every contributor automatically when derived work is sold. Trust is self-collateralising: your accumulated receipts are your collateral, with no external deposits required. Ownership is tracked through append-only transparency logs, not blockchain consensus.

1504 lines of Python. Every claim in this paper runs.

---

## The problem

Every trust mechanism in commerce assumes three things about the actors: they persist, they have identities, and they face consequences. Agents break all three. An agent spins up, does work, and vanishes. It has no reputation to protect, no identity to stake, no consequence to fear.

So agent-to-agent commerce today is either walled garden (same developer, same org, same trust boundary) or blind faith. When your agent needs a specialist's output, it either trusts the response or doesn't use it. There is no middle ground. No way to verify the claimed model actually ran. No way to track who produced what. No way to resell a verified result to someone who wasn't there for the original computation.

MCP and APIs don't solve this. They solve integration. Your developer configures which endpoints your agent can call. The agent trusts the endpoint because the developer trusts the endpoint. The response is ephemeral, consumed and gone. A third party can't verify it, you can't resell it, you can't compose it into a provenance chain. The moment agents start autonomously discovering and transacting with strangers, with no developer pre-approving anything, tool-use protocols have nothing to offer. They assume a human in the loop. We are building for a world where the human is gone.

Verification technology (EZKL, Halo2, TEE attestation) can prove a model produced a specific output. But a proof is an event, not an artifact. No persistent object carries the proof alongside the economic context and provenance. You can't resell a proof. You can't chain proofs into derivative work.

Compute financialisation (Ornn, GAIB, Bittensor, Ritual) prices inputs: GPU hours, model weights, network validation. None of them create a tradeable representation of the output itself. Consider that a GPU hour of pharmaceutical screening might produce a result worth $100k while the same hour classifying cat photos produces fractions of a cent. Same inputs, six orders of magnitude apart in output value. You can't capture that with input pricing. Output pricing can, but only if the output is verifiable.

---

## The solution

The VCR is a 21-field data structure that wraps a cryptographic proof in an economic envelope. It is three things at once.

A proof of work performed. It carries the ZK proof or TEE attestation, model ID, and verification key. Any stranger can verify the computation without contacting the original producer.

A certificate of provenance. It links to parent VCRs via cryptographic hash references, forming a DAG. Modify any receipt and all descendants break.

A transferable economic instrument. It carries pricing, royalty terms, and transfer history. When a VCR changes hands, royalties flow back through the provenance chain automatically.

No token. No blockchain. Just a data structure with enough fields to make verified AI outputs tradeable.

---

## Protocol design

### Design principles

The protocol is backend-agnostic. The VCR wraps a proof but does not care how it was generated. ZK proof, TEE attestation, it does not matter. The schema is indifferent. The implementation demonstrates both.

Each VCR is self-contained. It carries everything a stranger needs to verify the computation and assess its value, with no external lookups beyond the model's verification key (see Spec Section 7.5 for retrieval options).

VCRs are hash-linked. They reference parents by hash, forming a DAG. Modify any receipt and all descendants break.

The schema is minimal. Every field exists because it is necessary for verification, provenance, or economics. 21 fields. 1504 lines for the entire protocol layer.

There is no native token. Prices are denominated in whatever currency the parties agree on. The protocol is infrastructure, like HTTP, and HTTP doesn't have a token.

### Receipt schema

21 fields across five sections:

Identity, which uniquely identifies the receipt.
| Field | Type | Description |
|---|---|---|
| receipt_id | bytes32 | SHA-256 of canonical serialisation of all other fields (excluding signature). Derived, not assigned. Serves as both identifier and integrity check. |
| schema_version | uint16 | Protocol version. Currently 1. |

Computation, covering what was computed and the proof it was done correctly.
| Field | Type | Description |
|---|---|---|
| model_id | bytes32 | Hash of model specification (ONNX file, weights, circuit definition). |
| verification_key_id | bytes32 | Hash of the verification key. VK published separately. |
| input_hash | bytes32 | SHA-256 of computation input. Input not included (privacy-preserving). |
| output_hash | bytes32 | SHA-256 of computation output. Output travels alongside receipt but isn't part of canonical form. |
| proof | bytes | Proof blob. Opaque to protocol. Backend determines format. |
| public_inputs | bytes | Public inputs to the proof circuit. Backend-specific. |
| proving_backend | string | Identifier for proving system (e.g. "ezkl-halo2", "tee-nitro-v1"). |
| timestamp | uint64 | Unix timestamp of computation. |

Provenance, linking to parent computations.
| Field | Type | Description |
|---|---|---|
| parent_receipts | ParentRef[] | Ordered list of parent VCRs. Empty for root computations. |
| provenance_depth | uint16 | Longest path from this receipt to a root (0 = root). |

Economics, covering pricing, royalties, and transfer history.
| Field | Type | Description |
|---|---|---|
| provider | bytes32 | Public key of the entity that performed the computation. |
| original_price | uint64 | Price paid for original computation, in base currency units. |
| currency | string | Denomination (e.g. "USD-cents", "ETH-wei"). |
| royalty_terms | RoyaltyTerms | Revenue split on resale. |
| transfer_count | uint16 | Times this receipt has been transferred. Starts at 0. Excluded from canonical hash because it is mutable state tracked by the transfer ledger, not part of the immutable receipt. |

Integrity, which binds everything together.
| Field | Type | Description |
|---|---|---|
| signature | bytes | Provider's Ed25519 signature over the receipt's canonical hash. |
| signature_scheme | string | "ed25519" or "ecdsa-secp256k1". |
| extensions | Extension[] | Optional protocol extensions. |

### Supporting structures

ParentRef links a VCR to a parent in the provenance DAG.
| Field | Type | Description |
|---|---|---|
| receipt_id | bytes32 | Parent's receipt identifier. |
| receipt_hash | bytes32 | SHA-256 of parent's complete canonical serialisation. Allows integrity verification without having the parent on hand. |
| relationship | string | "input" (computational dependency), "reference" (informational), or "aggregation" (combining multiple parents). |

RoyaltyTerms defines how revenue is distributed on resale.
| Field | Type | Description |
|---|---|---|
| provider_royalty | uint16 | Basis points (0-10000) owed to original provider on resale. |
| parent_royalty | uint16 | Basis points owed to parent receipt holders, split equally among all parents. |
| cascade | bool | If true, royalties propagate up the entire provenance chain recursively. |

### Canonical serialisation

For hashing and signing, the receipt must serialise deterministically. Fields in schema-defined order, each prefixed with a 4-byte big-endian length, followed by raw bytes. UTF-8 strings. Big-endian integers. Lists prefixed with a 4-byte count.

Two fields excluded from canonical form: signature (obviously) and transfer_count (mutable state, tracked externally). Everything else is immutable after signing.

Why not JSON or Protobuf? JSON key ordering varies across implementations. Protobuf has edge cases with default values. Binary canonical serialisation gives you identical hashes in every language. JSON is used only for transport.

### Identity and integrity as one field

receipt_id is derived, not assigned. It's the SHA-256 of all canonical fields except the signature. This single hash is both the identifier (for lookup) and the integrity check (for tamper detection). The same value gets signed, and the same value gets embedded in downstream ParentRef entries. One computation, two roles.

---

## Verification

You get a VCR. Five checks:

1. **Integrity.** Recompute the hash from the fields. Compare against receipt_id. Mismatch = tampered.
2. **Signature.** Verify the Ed25519 signature using the provider's public key. Fails = not from the claimed provider.
3. **Proof.** Call verify(proof, verification_key, public_inputs) using the proving_backend. Fails = computation wasn't performed correctly.
4. **Output binding.** SHA-256 the received output, compare against output_hash. Mismatch = different output than what was proved.
5. **Provenance** (optional). For each parent receipt, verify recursively. If parents aren't available, you can check the hash is well-formed but can't verify validity. You choose your own trust threshold.

All five pass? The output was computed correctly by the claimed provider using the claimed model. Doesn't matter if you've never met them. The trust is in the maths.

---

## Provenance

VCRs form a DAG through parent_receipts:

```
[A: satellite intel]         depth 0  (proprietary data)
        \
[B: clinical analysis]      depth 0  (domain expertise)
         }-->  [D: synthesis]   depth 1  (orchestration)
[C: compliance audit]       depth 0  (regulatory certification)
        /
```

Each edge is a ParentRef containing the parent's receipt_id and receipt_hash. The hash covers the parent's complete canonical serialisation, so modifying the parent breaks the child's provenance link. Transfer (ownership change) is separate from derivation (computational dependency).

The DAG is append-only, independently verifiable, tamper-evident, and supports multi-parent references. It's a general graph, not a linear chain.

This is the part that doesn't exist anywhere else for AI outputs. An agent buys verified specialist outputs, runs them through its own model, and produces a new VCR with cryptographic links to everything it built on. The derivative carries its own proof plus a verifiable reference to its entire supply chain. Royalties track automatically through the chain.

---

## Settlement

### Direct computation

```
Client                              Provider
  |-- REQUEST(task_spec) ------------->|
  |-- ESCROW(payment, task_spec_hash)->|  (funds locked)
  |<-- RECEIPT(vcr, output) ----------|  (provider delivers)
  |-- VERIFY(vcr) --------------------|  (client checks locally)
  |-- RELEASE or REFUND -------------->|  (valid: release. invalid: refund.)
```

Payment releases if and only if the receipt verifies. The escrow mechanism is pluggable: in-memory for the POC, a payment processor or smart contract for production.

### Resale and royalty cascade

When a VCR holder resells:

1. Compute provider_royalty bps of sale price and credit to the provider.
2. Compute parent_royalty bps of sale price and split equally among parent_receipts entries.
3. If cascade is true and the parent receipt is available, apply the parent's own royalty_terms to the parent's share recursively (return to step 1 with the parent receipt and the parent's share as the amount).
4. If cascade is false, credit the parent's provider directly.
5. The seller gets the remainder.

Royalties diminish geometrically with depth. A 3% parent royalty cascading through a chain where each level takes 3% produces 3%, 0.09%, 0.0027%, and so on. This is by design: meaningful for direct parents, negligible for deep ancestors.

### Transfer records

VCRs are immutable after signing. Ownership is tracked in a separate transfer ledger:

| Field | Type | Description |
|---|---|---|
| receipt_id | bytes32 | Which VCR was transferred |
| from | bytes32 | Seller's public key |
| to | bytes32 | Buyer's public key |
| price | uint64 | Sale price |
| currency | string | Denomination |
| timestamp | uint64 | When |
| royalties_paid | RoyaltyPayment[] | Breakdown of all royalty distributions |
| transfer_hash | bytes32 | SHA-256 of canonical serialisation |
| seller_signature | bytes | Ed25519 over transfer_hash |

Single ownership is enforced: a VCR can only be sold by its current owner. In the POC this is an in-memory data structure. In production, ownership is tracked through transparency logs.

---

## Ownership layer

Verification is bilateral. Two agents check each other's receipts directly. But ownership tracking needs a global view. If Alice sells the same receipt to both Bob and Carol through separate channels, neither can detect the conflict without shared state.

The standard answer is a blockchain. We don't need one. What we actually need is append-only history, public auditability, and double-spend detection. These are exactly the properties that Certificate Transparency already provides for TLS certificates, running in production today, securing billions of HTTPS connections without mining, tokens, or consensus protocols.

A VCR transparency log is an append-only Merkle tree of transfer records. Multiple independent operators run logs. A transfer goes to a threshold of logs (say, 3 of 5). Before accepting a transfer, a buyer checks whether this receipt has already been transferred. Merkle inclusion proofs make verification O(log n).

There is a double-spend window between submission and threshold confirmation. High-value transactions wait for multiple logs, like Bitcoin confirmations but measured in seconds rather than minutes because appending is O(1). Low-value transactions use single-log confirmation because the risk is bounded by the transaction value. The buyer chooses their own threshold.

---

## Self-collateralising trust

Every existing answer to the trust question externalises the collateral. Bitcoin externalises trust onto energy expenditure. Ethereum staking externalises it onto locked tokens. Traditional finance externalises it onto cash deposits. In every case, the collateral and the product are separate things. You lock up value over here to prove you'll behave over there.

The VCR inverts this. An operator's accumulated receipts, their royalty streams, and the downstream chains that depend on their work are simultaneously their product and their bond. The collateral is endogenous, generated by honest participation rather than deposited from outside. Cheating doesn't cost a deposit. It destroys everything you've built.

### Effective stake

For any operator, three quantities are deterministically computable from public VCR data:

**Direct value.** Sum of original_price across all their receipts, weighted by whether each has been settled through escrow. An unsold receipt is a claim. A sold receipt is market-validated evidence.

**Royalty streams.** NPV of future royalty income, estimated from royalty terms, transfer velocity, and a discount rate. This income dies the moment the operator's receipts become untrusted.

**Dependency depth.** How many downstream VCRs reference this operator's receipts as parents. This is the blast radius: how much of the broader economy breaks if this operator's work becomes suspect.

```
effective_stake = w_direct × direct_value
               + w_royalty × royalty_NPV
               + w_depth  × dependency_count × unit_value
```

The protocol defines the mechanisms (the formula, the settled/unsettled distinction) and leaves the parameters (weights, thresholds, multipliers) to the market. Fixed mechanisms, floating parameters. Same pattern as every successful protocol — Bitcoin bakes in the 21M cap but lets difficulty float.

### Trust quotient

```
trust_quotient = effective_stake / transaction_value
```

A quotient of 73 means the operator has 73x more to lose than they could gain by cheating on this transaction. A quotient of 0 means they have nothing to lose at all.

| Quotient | Recommendation |
|---|---|
| >= 50 | Instant settlement, stake dwarfs the transaction |
| 5 - 50 | Standard escrow |
| < 5 | Collateral required |

These are recommendations, not enforcement. The protocol provides the number. Participants make the call.

Unlike credit scores (central authority, opaque model), the trust quotient is computed by anyone from public data using a deterministic function. Unlike blockchain staking (lock capital you already have), the trust quotient generates its own capital through work. You can't buy your way to a high quotient. You have to earn it.

### Sybil resistance

Effective stake is gameable. Create fake identities, trade receipts between them, inflate your stake without doing real work. This is a well-studied problem. Douceur (2002) proved it can't be fully prevented without a trust anchor. Every distributed trust system since has worked within this constraint.

The protocol naturally produces an interaction graph. Every receipt with parents creates a bilateral interaction, and every transfer creates a bilateral interaction. This graph is the input to the reputation layer.

The reputation layer modulates effective stake based on the graph. The reference implementation applies EigenTrust (Kamvar et al., 2003), which is mathematically identical to PageRank applied to the interaction graph. Isolated sybil clusters converge to zero. Well-connected legitimate operators converge to positive values.

```
effective_stake = raw_stake × max(diversity, floor) + vouched_stake
```

These aren't novel algorithms. They're established frameworks applied to a new data structure. The novelty is in the data the protocol produces, not in the reputation algorithms that consume it. The protocol doesn't claim to prevent sybil attacks. It makes them expensive in proportion to their payoff. Same guarantee as Bitcoin.

### Cold start

A new operator with zero history has an effective stake of zero. The answer is the same as traditional credit: start small, build up. Accept smaller transaction limits. Get vouched by an established operator who puts a fraction of their own stake on the line as a public record. The quotient rises with every honest transaction. This is how credit markets actually developed, not by solving trust cryptographically, but by making trust an emergent property of accumulated economic activity.

---

## Architecture

Four layers, strictly separated:

```
Layer 4: Application      HTTP agents, marketplace UI, demo scripts
Layer 3: Protocol          VCR schema, provenance, settlement, stake, royalties. 1504 lines.
Layer 2: Ownership         Transparency logs — append-only Merkle trees
Layer 1: Proving backend   ZK proof or TEE attestation. Two functions.
```

Layer 3 never references EZKL, Halo2, or any specific proving tech. The entire proving backend abstraction is two functions:

```
prove(artifacts, input_data) -> (proof_bytes, output_data)
verify(artifacts, proof_bytes) -> bool
```

Swapping the proving backend means implementing those two functions. Nothing else changes. ZK proofs give mathematical certainty but are limited to small deterministic models today. TEE attestation gives hardware-backed verification that works with any model, including LLMs. The implementation demonstrates both, producing interchangeable VCRs through the same protocol. Note that these backends carry different trust assumptions — ZK proofs are mathematically unforgeable while TEE attestations depend on hardware vendor PKI (see Spec Section 7.4).

---

## Security

### What holds

**Proof unforgeability.** Can't create a valid proof for a computation you didn't perform. Follows from proving system soundness.

**Signature unforgeability.** Can't attribute a receipt to a provider who didn't create it. Any modification changes the hash, signature breaks.

**Tamper detection.** Change any field, the hash changes, the signature breaks, all descendants break.

**Output binding.** Can't swap in a different output. SHA-256 mismatch caught at verification step 4.

**Double-sell prevention.** Transfer ledger enforces single ownership. Transparency logs provide global detection.

### What doesn't hold

**Price inflation.** original_price is self-reported. An operator could claim $100 for trivial computation. Mitigation: effective stake weights settled receipts higher than unsold. The market is the price oracle.

**Provenance claims are self-reported.** A producer can reference parent receipts they didn't actually use. This is fundamental to digital goods: once data has been seen, copying cannot be prevented. The mitigation is that honest provenance is profitable through royalty participation and depth as a credibility signal, while dishonest provenance is detectable through a missing transfer record.

**Timestamps are self-reported.** Production deployments use transparency log append order as authoritative timestamp.

**Royalty enforcement is voluntary.** A hostile buyer can skip payments. The transparency log makes it visible and their trust quotient drops. Enforcement is market-emergent, the same as supplier relationships. Skip paying your suppliers and word gets around.

**Metadata leakage.** model_id identifies the model. input_hash identifies the input. For small input spaces, an attacker can brute-force the hash. This is Arrow's information paradox: the more accurately you describe what's for sale, the closer you get to giving it away.

**ZK limits.** Fixed-point arithmetic limits model complexity. Backend limitation, not protocol limitation.

The threat model: the adversary cannot break SHA-256, Ed25519, or the proving system's soundness. Everything else is economic.

---

## Conclusion

The VCR is a missing primitive: a standardised, self-verifying representation of AI compute output that lets strangers trust, price, and trade cognitive work without trusting the producer.

Agents don't persist, don't have identities, and don't face consequences. Every existing trust mechanism assumes all three. The VCR replaces those assumptions with maths. Proofs for correctness, signatures for attribution, hash linking for provenance, basis-point royalties for automatic economic flow, and self-collateralising trust that grows from work rather than deposits.

1504 lines of protocol code. One external dependency. Running on a laptop.

---

## Appendix A: incentive analysis

The protocol's provenance attribution relies on economic incentives rather than cryptographic enforcement. This appendix shows the conditions under which honest attribution is the dominant strategy.

Operator P produces VCR_A. Operator Q produces derivative VCR_B using VCR_A's output as input. Q has two strategies: honest (reference VCR_A as parent, pay royalties, gain provenance depth) or dishonest (omit the reference, avoid royalties, lose the verified chain).

| Symbol | Meaning |
|---|---|
| S | Sale price of VCR_B |
| r_p | Provider royalty rate (basis points / 10000) |
| r_a | Parent royalty rate (basis points / 10000) |
| k | Expected downstream resales |
| d | Price premium for verified provenance (d > 1) |
| p | Detection probability |
| L | Loss on detection: forfeited revenue from accumulated VCR history |

```
E[honest]    = d × S × (1 + k × r_p - r_a)
E[dishonest] = S × (1 + k × r_p) - p × L
```

Worked example: S = $100, r_p = 5%, r_a = 3%, k = 3 resales, d = 1.2, p = 0.4, L = $5000.

Honest: $134.40. Dishonest: -$1885. Honest dominates by $2019.

The result is driven by the detection loss term. Even with p = 0.1, dishonesty is unprofitable. For agents, buyer agents cross-reference hashes against every known VCR instantly — detection probability approaches 1 for publicly listed work.

## Appendix B: known attack classes

| Attack | Description | Defence | Source |
|---|---|---|---|
| Sybil receipts | Fake operators, fabricated receipts | Diversity scoring penalises insular clusters | EigenTrust (2003) |
| Wash trading | Transfer receipts between own keys | Diversity-weighted settled multiplier | Anti-wash-trade economics |
| Provenance stuffing | Deep fake parent chains | Dependency depth weighted by diversity | Graph-based trust metrics |
| Sybil vouching | Inflate sybil stakes, vouch for real identity | Voucher's stake is diversity-weighted | Transitive trust (EigenTrust) |
| Whitewashing | Abandon identity, create new one | New operators start at zero | Feldman et al. (2004) |
| Long con | Build trust, then defraud | Cost scales with target value | Fundamental limit |
| Eclipse | Hide conflicting transfers | Transparency log threshold | Certificate Transparency |

The cost of a successful attack scales with the target. To pass a trust quotient of 50 for a $10,000 transaction, the attacker needs $500,000 in effective stake built from real settled transactions with diverse counterparties. The protocol makes fraud expensive, not impossible. This is the best any decentralised reputation system can achieve (Douceur, 2002).

## Appendix C: glossary

| Term | Definition |
|---|---|
| VCR | Verified Compute Receipt. The core data structure. |
| Provenance DAG | Directed acyclic graph formed by VCRs referencing parents. |
| Proving backend | System generating and verifying proofs (EZKL/Halo2, TEE attestation, etc). |
| Receipt hash | SHA-256 of canonical serialisation. Both identifier and integrity check. |
| Verification key | Public key specific to a model circuit. Published openly. |
| Royalty cascade | Propagation of royalty payments up the provenance DAG on resale. |
| Transfer ledger | Record of VCR ownership transfers. |
| Transparency log | Append-only Merkle tree of transfer records. Double-spend detection without blockchain. |
| Basis points | Unit for royalties. 10000 bps = 100%. 500 bps = 5%. |
| Canonical serialisation | Deterministic binary encoding ensuring identical hashes across all implementations. |
| Effective stake | Weighted sum of an operator's direct value, royalty NPV, and dependency depth. |
| Trust quotient | Effective stake divided by transaction value. The core signal for settlement terms. |

## Appendix D: measurements

All measurements from commodity hardware (laptop, no GPU). The protocol layer adds less than 10ms per operation.

| Metric | Value |
|---|---|
| ZK backend, single computation | ~800ms - 2.0s |
| ZK backend, proof size | 18 KB |
| TEE backend, single LLM call (Nitro) | ~3-5s |
| TEE backend, attestation doc size | ~4.5 KB (COSE Sign1) |
| Protocol overhead (serialise + sign + verify) | <10ms |
| Signature scheme | Ed25519 |
| Hash function | SHA-256 |
| Receipt fields | 21 |
| Protocol code | 1504 lines Python (7 modules) |
| Proving backend abstraction | 2 functions |
| Backends demonstrated | 2 (ZK, TEE) |
