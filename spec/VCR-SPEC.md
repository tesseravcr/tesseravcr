# VCR Protocol Specification

Version 1.0, April 2026

---

## 1. Overview

The Verified Compute Receipt (VCR) is a data structure that wraps a cryptographic proof of AI computation in an economic envelope. A VCR is simultaneously a proof of work performed, a certificate of provenance, and a transferable economic instrument.

This document defines the VCR schema, serialisation rules, verification procedure, settlement protocol, transfer mechanism, transparency log structure, and trust computation. It is implementation-agnostic. Any implementation producing conformant VCRs is a valid participant in the protocol.

### 1.1 Scope

This specification defines:
- The VCR receipt schema and all supporting structures
- Canonical binary serialisation for deterministic hashing
- The verification procedure (5 checks)
- The proving backend interface (2 functions)
- The provenance DAG and parent reference semantics
- The settlement protocol with royalty cascade
- Transfer records and ownership tracking
- Transparency log structure (append-only Merkle trees)
- Effective stake computation and trust quotient

This specification does not define:
- Which proving system to use (ZK, TEE, or future systems)
- Transport protocol (HTTP, gRPC, or other)
- Key management or identity systems
- Dispute resolution
- Specific currency or payment infrastructure

### 1.2 Notation

- `bytes32` — Exactly 32 bytes.
- `bytes` — Variable-length byte sequence.
- `uint16` — Unsigned 16-bit integer.
- `uint32` — Unsigned 32-bit integer.
- `uint64` — Unsigned 64-bit integer.
- `string` — UTF-8 encoded text.
- `bool` — Single byte: `0x01` = true, `0x00` = false.
- `H(x)` — SHA-256 hash of `x`.
- `||` — Byte concatenation.
- `BE16(n)` — Big-endian encoding of `n` as 2 bytes.
- `BE32(n)` — Big-endian encoding of `n` as 4 bytes.
- `BE64(n)` — Big-endian encoding of `n` as 8 bytes.
- `LEN(x)` — `BE32(len(x)) || x` — 4-byte big-endian length prefix followed by raw bytes.
- `bps` — Basis points. 10000 bps = 100%. 500 bps = 5%.

---

## 2. Receipt Schema

A VCR contains 21 fields across five sections. Two fields (`receipt_id` and `receipt_hash`) are derived from the others and are never stored — they are computed on demand.

### 2.1 Identity

| Field | Type | Description |
|---|---|---|
| `receipt_id` | bytes32 | `H(canonical_bytes)`. Derived, never assigned. Both identifier and integrity check. |
| `schema_version` | uint16 | Protocol version. This specification defines version `1`. |

### 2.2 Computation

| Field | Type | Description |
|---|---|---|
| `model_id` | bytes32 | Hash of model specification (ONNX file, weights, circuit definition). |
| `verification_key_id` | bytes32 | Hash of the verification key. The VK is published separately. |
| `input_hash` | bytes32 | `H(input_data)`. The input itself is not included (privacy-preserving). |
| `output_hash` | bytes32 | `H(output_data)`. The output travels alongside the receipt but is not part of the canonical form. |
| `proof` | bytes | Proof blob. Opaque to the protocol. Format determined by `proving_backend`. |
| `public_inputs` | bytes | Public inputs to the proof circuit. Backend-specific. |
| `proving_backend` | string | Identifier for the proving system. Examples: `"ezkl-halo2"`, `"tee-nitro-v1"`, `"tee-sgx-v2"`. |
| `timestamp` | uint64 | Unix timestamp (seconds) of computation. Self-reported by provider. |

### 2.3 Provenance

| Field | Type | Description |
|---|---|---|
| `parent_receipts` | ParentRef[] | Ordered list of parent VCRs. Empty for root computations. See Section 3.1. |
| `provenance_depth` | uint16 | Longest path from this receipt to a root receipt. `0` for root computations. |

### 2.4 Economics

| Field | Type | Description |
|---|---|---|
| `provider` | bytes32 | Public key of the entity that performed the computation. |
| `original_price` | uint64 | Price paid for the computation, in base currency units. |
| `currency` | string | Denomination. Examples: `"USD-cents"`, `"ETH-wei"`. |
| `royalty_terms` | RoyaltyTerms | Revenue split on resale. See Section 3.2. |
| `transfer_count` | uint16 | Number of times this receipt has been transferred. Starts at `0`. **Excluded from canonical serialisation** — mutable state tracked by the transfer ledger. |

### 2.5 Integrity

| Field | Type | Description |
|---|---|---|
| `signature` | bytes | Provider's signature over `receipt_hash`. **Excluded from canonical serialisation.** |
| `signature_scheme` | string | `"ed25519"` or `"ecdsa-secp256k1"`. |
| `extensions` | Extension[] | Optional protocol extensions. See Section 3.3. |

### 2.6 Derived Fields

`receipt_id` and `receipt_hash` are the same value: `H(canonical_bytes)`. Two names for clarity — `receipt_id` for lookup, `receipt_hash` for integrity and provenance linking.

---

## 3. Supporting Structures

### 3.1 ParentRef

Links a VCR to a parent in the provenance DAG.

| Field | Type | Description |
|---|---|---|
| `receipt_id` | bytes32 | Parent's receipt identifier. |
| `receipt_hash` | bytes32 | `H(parent's canonical_bytes)`. Allows integrity verification without possessing the parent. |
| `relationship` | string | `"input"` (computational dependency), `"reference"` (informational), or `"aggregation"` (combining multiple parents). |

### 3.2 RoyaltyTerms

Defines how revenue is distributed on resale.

| Field | Type | Description |
|---|---|---|
| `provider_royalty` | uint16 | Basis points (0–10000) owed to the original provider on resale. |
| `parent_royalty` | uint16 | Basis points owed to parent receipt holders, split equally among all parents. |
| `cascade` | bool | If true, royalties propagate up the entire provenance chain recursively. |

### 3.3 Extension

Optional protocol extension for forward compatibility.

| Field | Type | Description |
|---|---|---|
| `type` | string | Extension identifier. |
| `data` | bytes | Extension payload. |

---

## 4. Canonical Serialisation

For hashing and signing, the receipt MUST serialise deterministically. This section defines the exact encoding.

### 4.1 Field Encoding

Every field is encoded as:

```
LEN(encoded_value) = BE32(length) || encoded_value
```

Type-specific encoding of values before length-prefixing:

| Type | Encoding | Example |
|---|---|---|
| `uint16` | Big-endian 2 bytes | `500` → `01 F4` |
| `uint32` | Big-endian 4 bytes | `1000` → `00 00 03 E8` |
| `uint64` | Big-endian 8 bytes | `2000` → `00 00 00 00 00 00 07 D0` |
| `bool` | Single byte | `true` → `01`, `false` → `00` |
| `string` | UTF-8 bytes | `"ezkl-halo2"` → `65 7A 6B 6C 2D 68 61 6C 6F 32` |
| `bytes` | Raw bytes | As-is |
| `bytes32` | Raw 32 bytes | As-is |

After encoding, the value is length-prefixed with `BE32(length)`.

**Example:** `schema_version = 1` (uint16)

```
Encoded value:  00 01           (BE16(1), 2 bytes)
Length prefix:  00 00 00 02     (BE32(2))
Final:          00 00 00 02 00 01
```

**Example:** `proving_backend = "ezkl-halo2"` (string, 10 UTF-8 bytes)

```
Encoded value:  65 7A 6B 6C 2D 68 61 6C 6F 32
Length prefix:  00 00 00 0A     (BE32(10))
Final:          00 00 00 0A 65 7A 6B 6C 2D 68 61 6C 6F 32
```

### 4.2 List Encoding

Lists are encoded as:

```
BE32(item_count) || item_0.canonical_bytes() || item_1.canonical_bytes() || ...
```

The list count is a bare `BE32` (not length-prefixed). Each item's `canonical_bytes()` is the concatenation of its individually length-prefixed sub-fields.

**Example:** An empty `parent_receipts` list:

```
00 00 00 00     (BE32(0) — zero items)
```

### 4.3 Nested Structure Encoding

Nested structures (ParentRef, RoyaltyTerms, Extension) are serialised as the concatenation of their sub-fields, each individually length-prefixed. The nested structure as a whole is NOT wrapped in an outer length prefix.

Each structure type has a **fixed number of sub-fields**. Parsers MUST read exactly this many LEN-prefixed values per item. This is how deserialisers determine structure boundaries in lists.

**ParentRef canonical bytes** (3 sub-fields):

```
LEN(receipt_id) || LEN(receipt_hash) || LEN(UTF8(relationship))
```

**RoyaltyTerms canonical bytes** (3 sub-fields):

```
LEN(BE16(provider_royalty)) || LEN(BE16(parent_royalty)) || LEN(BOOL(cascade))
```

**Extension canonical bytes** (2 sub-fields):

```
LEN(UTF8(type)) || LEN(data)
```

**Example:** A `parent_receipts` list with one ParentRef where `receipt_id` and `receipt_hash` are each 32 zero bytes and `relationship = "input"`:

```
00 00 00 01                         BE32(1) — one item
00 00 00 20 00×32                   LEN(receipt_id) — 32 bytes of zeros
00 00 00 20 00×32                   LEN(receipt_hash) — 32 bytes of zeros
00 00 00 05 69 6E 70 75 74          LEN("input") — 5 UTF-8 bytes
```

A parser reading this list sees `count = 1`, then reads exactly 3 LEN-prefixed values to consume one ParentRef.

### 4.4 Receipt Serialisation Order

Fields are serialised in this exact order. This order is normative.

```
 1. LEN(BE16(schema_version))
 2. LEN(model_id)
 3. LEN(verification_key_id)
 4. LEN(input_hash)
 5. LEN(output_hash)
 6. LEN(proof)
 7. LEN(public_inputs)
 8. LEN(UTF8(proving_backend))
 9. LEN(BE64(timestamp))
10. LIST(parent_receipts)           — BE32(count) then each ParentRef
11. LEN(BE16(provenance_depth))
12. LEN(provider)
13. LEN(BE64(original_price))
14. LEN(UTF8(currency))
15. RoyaltyTerms.canonical_bytes()  — three LEN-prefixed sub-fields, no outer wrapper
16. LEN(UTF8(signature_scheme))
17. LIST(extensions)                — BE32(count) then each Extension
```

### 4.5 Worked Example: Complete Minimal Receipt

A root receipt with no parents, no extensions, `schema_version = 1`, all hash fields set to 32 zero bytes, empty proof and public inputs, `proving_backend = "ezkl-halo2"`, `timestamp = 1700000000`, `provider` = 32 zero bytes, `original_price = 150` (i.e., $1.50 in cents), `currency = "USD-cents"`, royalty terms `(500, 300, true)`, `signature_scheme = "ed25519"`.

Complete canonical bytes (hex), field by field:

```
Field  1  schema_version:      00 00 00 02  00 01
Field  2  model_id:            00 00 00 20  00×32
Field  3  verification_key_id: 00 00 00 20  00×32
Field  4  input_hash:          00 00 00 20  00×32
Field  5  output_hash:         00 00 00 20  00×32
Field  6  proof:               00 00 00 00
Field  7  public_inputs:       00 00 00 00
Field  8  proving_backend:     00 00 00 0A  65 7A 6B 6C 2D 68 61 6C 6F 32
Field  9  timestamp:           00 00 00 08  00 00 00 00 65 5E 26 00
Field 10  parent_receipts:     00 00 00 00
Field 11  provenance_depth:    00 00 00 02  00 00
Field 12  provider:            00 00 00 20  00×32
Field 13  original_price:      00 00 00 08  00 00 00 00 00 00 00 96
Field 14  currency:            00 00 00 09  55 53 44 2D 63 65 6E 74 73
Field 15a provider_royalty:    00 00 00 02  01 F4
Field 15b parent_royalty:      00 00 00 02  01 2C
Field 15c cascade:             00 00 00 01  01
Field 16  signature_scheme:    00 00 00 07  65 64 32 35 35 31 39
Field 17  extensions:          00 00 00 00
```

`receipt_id = SHA-256(all bytes above concatenated)`.

Notes:
- `00×32` means 32 zero bytes.
- Field 6 and 7 (proof, public_inputs) are zero-length: length prefix `00 00 00 00`, no payload.
- Field 10 (parent_receipts) is an empty list: just `BE32(0)`.
- Fields 15a–15c are RoyaltyTerms sub-fields, each individually LEN-prefixed, no outer wrapper.
- Field 17 (extensions) is an empty list: just `BE32(0)`.

An implementation that produces different bytes for these inputs is non-conformant.

### 4.6 Excluded Fields

The following fields are **excluded** from canonical serialisation:

| Field | Reason |
|---|---|
| `signature` | Computed over the canonical hash, so cannot be part of it. |
| `transfer_count` | Mutable state tracked by the transfer ledger. Changes with each resale. |
| `output_data` | Travels alongside the receipt but is not part of the immutable receipt. |

All other fields are immutable after signing.

### 4.7 Why Not JSON or Protobuf

JSON: key ordering and whitespace vary across implementations. Protobuf: default value edge cases produce non-deterministic serialisation. Binary canonical serialisation produces identical hashes in every language. JSON is used only for transport (see Section 15).

---

## 5. Receipt Identity

### 5.1 Computation

```
receipt_id = H(canonical_bytes)
```

Where `canonical_bytes` is the output of the procedure in Section 4.4.

`receipt_hash` is an alias for `receipt_id`. They are the same value.

### 5.2 Properties

- Deterministic: same fields always produce the same `receipt_id`.
- Tamper-evident: changing any canonical field changes the `receipt_id`.
- Self-identifying: the identifier IS the integrity check.

### 5.3 Signing

```
signature = Sign(private_key, receipt_hash)
```

Where `Sign` is the signing function for the scheme specified in `signature_scheme`.

For `"ed25519"`: the signature is 64 bytes, computed per RFC 8032.

The `provider` field MUST be set to the public key corresponding to `private_key` before computing `receipt_hash`. Changing `provider` after signing invalidates the signature.

---

## 6. Verification

A verifier receives a VCR and optionally the output data. Five checks:

### 6.1 Integrity

Recompute `receipt_hash` from the receipt's fields using the canonical serialisation procedure (Section 4). Compare against any claimed identifier.

For in-memory receipts where `receipt_id` is always computed on demand, this check is structural. For deserialised receipts, this confirms no fields were modified after serialisation.

### 6.2 Signature

Verify the `signature` over `receipt_hash` using the public key in `provider`, according to `signature_scheme`.

```
Verify(provider, signature, receipt_hash) → bool
```

Failure means the receipt was not created by the claimed provider.

### 6.3 Proof

Select the verification function by `proving_backend` and invoke:

```
verify(proof, verification_key, public_inputs) → bool
```

Where `verification_key` is looked up by `verification_key_id`. Failure means the computation was not performed correctly (or not performed by the claimed model).

### 6.4 Output Binding

If output data is provided:

```
H(output_data) == output_hash
```

A mismatch means the output does not correspond to what was proved.

### 6.5 Provenance (Optional)

For each entry in `parent_receipts`:
1. If the parent receipt is available, verify it recursively (all 5 checks).
2. If unavailable, the verifier can check that `receipt_hash` in the ParentRef is well-formed but cannot verify validity.

The verifier sets their own trust threshold for how many ancestors must be verified.

### 6.6 Outcome

All checks pass: the output was computed correctly by the claimed provider using the claimed model. This holds regardless of any prior relationship between verifier and provider.

---

## 7. Proving Backend Interface

The protocol is backend-agnostic. The entire proving backend abstraction is two functions:

```
prove(artifacts, input_data) → (proof_bytes, output_data, public_inputs)
verify(artifacts, proof_bytes, public_inputs) → bool
```

Where `artifacts` is backend-specific (circuit files, verification keys, enclave configuration, etc.).

### 7.1 ZK Backend (e.g. EZKL/Halo2)

- `proving_backend`: `"ezkl-halo2"`
- `proof`: ZK proof bytes (typically ~18 KB for Halo2)
- `public_inputs`: Public circuit inputs
- `verification_key_id`: `H(verification_key_bytes)`
- Verification: mathematical. The proof is unforgeable by the soundness property of the proving system.

### 7.2 TEE Backend (e.g. AWS Nitro Enclaves)

- `proving_backend`: `"tee-nitro-v1"`
- `proof`: Raw attestation document (COSE Sign1, ~4.5 KB)
- `public_inputs`: PCR0/PCR1/PCR2 values from enclave build
- `input_hash`: Embedded in attestation `user_data`
- `output_hash`: Embedded in attestation `user_data`
- Verification: validate COSE Sign1 signature, verify certificate chain against AWS Nitro Attestation PKI root CA, check PCR values match expected enclave build, confirm `user_data` contains expected hashes.

### 7.3 Adding Backends

Implementing a new backend requires:
1. A unique `proving_backend` identifier string.
2. An implementation of `prove()` that returns proof bytes and public inputs.
3. An implementation of `verify()` that validates proof bytes against public inputs.
4. Nothing else changes. The receipt schema, serialisation, settlement, transfer, and trust layers are all backend-agnostic.

### 7.4 Backend Security Models

Different proving backends provide different security guarantees:

- **ZK proofs** (e.g. Halo2) provide **mathematical soundness**. The proof is unforgeable given the hardness assumptions of the underlying cryptography. Verification requires only the proof, public inputs, and verification key. No trust in any hardware or third party is needed.

- **TEE attestations** (e.g. AWS Nitro) provide **hardware-rooted trust**. The attestation is trustworthy given the integrity of the enclave hardware and the manufacturer's certificate chain. Verification depends on trusting the hardware vendor's PKI (e.g. the AWS Nitro Attestation root CA).

The protocol treats all proving backends uniformly at the schema and verification layers. A receipt with `proving_backend = "ezkl-halo2"` and a receipt with `proving_backend = "tee-nitro-v1"` have identical structure, identical serialisation, and identical transfer mechanics.

However, the underlying trust assumptions differ. Verifiers SHOULD consider the security model of `proving_backend` when making trust decisions (e.g. when computing settlement terms per Section 12.6). The protocol does not prescribe how to weight different backends — this is a verifier-local policy decision.

### 7.5 Verification Key Retrieval

Proof verification (Section 6.3) requires the actual verification key, not just its hash. The receipt carries `verification_key_id = H(verification_key_bytes)` but not the key itself.

Implementations MUST be able to retrieve verification keys by `verification_key_id` to complete proof verification. This specification does not mandate a distribution mechanism. Conformant options include:

- **Content-addressable storage.** The key's hash is its address. Any store that maps `H(key) → key` suffices.
- **Provider-hosted endpoints.** The operator publishes keys at a known URL, retrievable by `verification_key_id`.
- **Transparency-log-backed registries.** Keys are published to append-only logs, providing auditability and preventing silent key rotation.
- **Out-of-band exchange.** Buyer and provider agree on key delivery as part of the settlement protocol.

If a verifier cannot retrieve the verification key for a given `verification_key_id`, proof verification (Section 6.3) cannot be completed. The verifier SHOULD treat this as a verification failure unless they have independent reason to trust the receipt.

---

## 8. Provenance DAG

VCRs form a directed acyclic graph (DAG) through `parent_receipts`.

### 8.1 Structure

```
[A: root]  depth 0
    \
[B: root]  depth 0  ──→  [D: derivative]  depth 1  ──→  [E: further]  depth 2
    /
[C: root]  depth 0
```

Each edge is a ParentRef containing the parent's `receipt_id` and `receipt_hash`.

### 8.2 Properties

- **Append-only.** New VCRs reference existing ones. Existing VCRs are immutable.
- **Tamper-evident.** Modifying any receipt changes its `receipt_hash`, which invalidates all descendants' ParentRef entries.
- **Independently verifiable.** Any node can be verified without the complete graph.
- **Multi-parent.** A VCR can reference multiple parents (general DAG, not linear chain).

### 8.3 Depth Calculation

```
provenance_depth = 0                                   if parent_receipts is empty
provenance_depth = max(parent.depth for parent in parents) + 1    otherwise
```

### 8.4 Relationship Types

| Value | Meaning |
|---|---|
| `"input"` | Computational dependency. The parent's output was used as input to this computation. |
| `"reference"` | Informational. The parent was consulted but not directly consumed. |
| `"aggregation"` | This receipt combines or summarises multiple parent outputs. |

---

## 9. Settlement Protocol

### 9.1 Task Specification

```
TaskSpec {
  model_id          : bytes32
  input             : bytes
  max_price         : uint64
  currency          : string
  required_backend  : string      // or "any"
  timeout_seconds   : uint32
}

task_spec_hash = H(canonical(TaskSpec))
```

**TaskSpec canonical serialisation order** (normative):

```
1. LEN(model_id)
2. LEN(input)
3. LEN(BE64(max_price))
4. LEN(UTF8(currency))
5. LEN(UTF8(required_backend))
6. LEN(BE32(timeout_seconds))
```

`task_spec_hash = H(field_1 || field_2 || ... || field_6)`. Same encoding rules as receipt fields (Section 4.1).

### 9.2 Direct Computation Flow

```
Client                              Provider
  |── REQUEST(task_spec) ──────────────→|
  |── ESCROW(payment, task_spec_hash) ─→|   funds locked
  |←── RECEIPT(vcr, output) ───────────|   provider delivers
  |── VERIFY(vcr) ─────────────────────|   client checks locally
  |── RELEASE or REFUND ───────────────→|   valid: release. invalid: refund.
```

Payment releases if and only if the receipt verifies. The escrow mechanism is pluggable.

### 9.3 Resale and Royalty Cascade

When a VCR holder resells to a buyer at `sale_price`:

**Algorithm: DISTRIBUTE(receipt, amount)**

```
1. provider_cut = amount × (receipt.royalty_terms.provider_royalty / 10000)
2. Credit provider_cut to receipt.provider
3. parent_cut_total = amount × (receipt.royalty_terms.parent_royalty / 10000)
4. If parent_cut_total > 0 AND receipt.parent_receipts is non-empty:
   a. per_parent = parent_cut_total / len(receipt.parent_receipts)
   b. For each parent_ref in receipt.parent_receipts:
      i.   If parent receipt is available AND receipt.royalty_terms.cascade == true:
           → DISTRIBUTE(parent_receipt, per_parent)    // recurse
      ii.  If parent receipt is available AND cascade == false:
           → Credit per_parent to parent_receipt.provider
      iii. If parent receipt is unavailable:
           → Credit per_parent to seller    // cannot resolve provider from ParentRef alone
5. seller_cut = sale_price - total_royalties_distributed
6. Credit seller_cut to seller
```

**Note on unavailable parents:** A ParentRef contains only `receipt_id` and `receipt_hash`, not `provider`. If the parent receipt cannot be resolved, the royalty share for that parent falls back to the seller. This incentivises sellers to make their provenance chain available — withholding a parent forfeits the royalty to themselves rather than the rightful recipient, but this is detectable and damages their trust quotient.

### 9.4 Cascade Properties

Royalties diminish geometrically with depth. With 3% parent royalty cascading through a chain where each level takes 3%:

| Depth | Share |
|---|---|
| 0 (direct parent) | 3.000% |
| 1 | 0.090% |
| 2 | 0.003% |
| 3 | 0.000% |

This is by design: meaningful for direct parents, negligible for deep ancestors.

---

## 10. Transfer Records

VCRs are immutable after signing. Ownership is tracked separately.

### 10.1 TransferRecord Schema

| Field | Type | Description |
|---|---|---|
| `receipt_id` | bytes32 | Which VCR was transferred. |
| `from_key` | bytes32 | Seller's public key. |
| `to_key` | bytes32 | Buyer's public key. |
| `price` | uint64 | Sale price in base currency units. |
| `currency` | string | Denomination. |
| `timestamp` | uint64 | Unix seconds. |
| `royalties_paid` | RoyaltyPayment[] | Breakdown of all royalty distributions. |
| `seller_signature` | bytes | Seller's signature over `transfer_hash`. |

### 10.2 RoyaltyPayment

| Field | Type | Description |
|---|---|---|
| `recipient` | bytes32 | Public key of royalty recipient. |
| `amount` | uint64 | Amount in base currency units. |
| `receipt_id` | bytes32 | Which VCR in the provenance chain they hold. |

### 10.3 TransferRecord Canonical Serialisation

```
1. LEN(receipt_id)
2. LEN(from_key)
3. LEN(to_key)
4. LEN(BE64(price))
5. LEN(UTF8(currency))
6. LEN(BE64(timestamp))
7. BE32(royalties_count) || for each: LEN(recipient) || LEN(BE64(amount)) || LEN(receipt_id)
```

`seller_signature` is excluded from canonical form. `transfer_hash = H(canonical_bytes)`.

### 10.4 Ownership Rules

1. A VCR MUST be registered before it can be transferred. The initial owner is the `provider`.
2. Only the current owner can transfer a VCR. `from_key` MUST match the current owner.
3. `seller_signature` MUST verify against `from_key` over `transfer_hash`.
4. After transfer, the current owner becomes `to_key`.
5. `transfer_count` on the receipt increments by 1.

---

## 11. Transparency Logs

Ownership tracking requires a global view. Transparency logs provide append-only history, public auditability, and double-spend detection without blockchain.

### 11.1 Merkle Tree Construction

Each transparency log is an append-only Merkle tree of transfer records.

**Leaf hashing:**

```
leaf_hash = H(0x00 || entry_bytes)
```

Where `entry_bytes = transfer.canonical_bytes() || BE64(log_timestamp)`.

**Internal node hashing:**

```
node_hash = H(0x01 || left_child || right_child)
```

The `0x00` and `0x01` domain separation prefixes prevent second-preimage attacks.

**Odd leaf handling:** If the number of nodes at any level of the tree is odd, the last node is duplicated to form a pair. This rule applies recursively at every level of the tree, not only to the leaf level.

**Example:** A tree with 3 leaves `[A, B, C]`:

```
Level 0 (leaves):   H(0x00||A)   H(0x00||B)   H(0x00||C)   H(0x00||C)  ← C duplicated
Level 1:            H(0x01||AB)                H(0x01||CC)
Level 2 (root):     H(0x01 || H(0x01||AB) || H(0x01||CC))
```

**Duplicate leaf rejection:** A transparency log MUST NOT accept an entry that produces a `leaf_hash` identical to an existing leaf. This prevents replay attacks where the same transfer record is submitted twice.

### 11.2 Inclusion Proofs

A Merkle inclusion proof for entry at index `i` consists of:
- `index`: Position in the log.
- `leaf_hash`: Hash of the entry.
- `path`: List of `(sibling_hash, direction)` pairs, where direction is `"left"` or `"right"`.
- `root`: The Merkle root at the time of proof generation.
- `log_size`: Number of entries in the log.

**Verification:**

```
current = leaf_hash
for (sibling, direction) in path:
    if direction == "left":
        current = H(0x01 || sibling || current)
    else:
        current = H(0x01 || current || sibling)
return current == root
```

### 11.3 Log Network Protocol

Multiple independent operators run transparency logs. This section defines the protocol by which logs discover each other, accept transfers, produce witnessed checkpoints, and enable new logs to join the network.

#### 11.3.1 Participants

Three roles exist in the network:

- **Submitter.** An agent submitting a transfer record. Submitters are not nodes — they are clients. A submitter sends a signed transfer to one or more logs and collects inclusion proofs in return.
- **Log operator.** Runs a transparency log — an append-only Merkle tree of transfer records with a persistent identity (Ed25519 keypair). A log operator accepts submissions, appends entries, signs checkpoints, and participates in witnessing.
- **Verifier.** Any party that queries logs to check ownership or verify inclusion proofs. A verifier does not need to run a log. Verification is stateless.

#### 11.3.2 Log Identity

Each log operator has a long-lived Ed25519 keypair. The public key is the log's identity. The operator publishes:

```
operator_key:  bytes32     — Ed25519 public key
log_url:       string      — base URL (e.g. https://log1.example.org)
```

#### 11.3.3 Bootstrap and Peer Discovery

The network uses static bootstrap with optional peer exchange.

**Bootstrap list.** A new log ships with a hardcoded list of bootstrap log URLs. The bootstrap list is a configuration parameter, not a protocol constant. Reference deployments include the seed log URLs.

**Peer exchange.** A log MAY expose its known peer list. A new log queries bootstrap peers for their peer lists and merges them. There is no DHT, no gossip protocol, no automatic discovery. Peer lists are advisory — a log operator chooses which peers to witness with.

**Joining the network.** A new log operator:
1. Generates an Ed25519 keypair.
2. Configures bootstrap peers.
3. Starts accepting submissions. No registration or permission is required.
4. Begins requesting witness signatures from peers (Section 11.3.7).
5. Other logs add the new log to their peer lists at their discretion.

A log with zero peers is fully functional for local use. Witnessing is an additive trust property, not a prerequisite for operation.

#### 11.3.4 Messages

The protocol defines five message types. All messages are JSON-encoded for transport (Section 15). All messages are request-response over HTTP.

**1. Submit (submitter → log)**

A submitter sends a signed transfer record to a log for inclusion.

Request:
```
{
  "receipt_id":        "hex64",
  "from_key":          "hex64",
  "to_key":            "hex64",
  "price":             uint64,
  "currency":          "string",
  "timestamp":         uint64,
  "royalties_paid":    [{"recipient": "hex64", "amount": uint64, "receipt_id": "hex64"}],
  "seller_signature":  "hex128",
  "canonical_bytes":   "hex"
}
```

The log independently reconstructs `canonical_bytes` from the submitted fields using the canonical serialisation defined in Section 10.3. If the reconstructed bytes do not match the submitted `canonical_bytes`, the submission is rejected. This prevents the submitter from getting an inclusion proof for data the log cannot independently verify.

Response (success):
```
{
  "index":          uint64,
  "leaf_hash":      "hex64",
  "root":           "hex64",
  "log_size":       uint64,
  "log_timestamp":  uint64,
  "checkpoint":     Checkpoint
}
```

The log MUST verify the `seller_signature` against `from_key` over `transfer_hash` (Section 10.3) before accepting.

**2. Query proof (verifier → log)**

A verifier requests an inclusion proof for a specific log entry.

```
GET /v1/proof/{index}
→ InclusionProof (Section 11.2)
```

**3. Query ownership (verifier → log)**

A verifier requests the current owner and transfer history for a receipt.

```
GET /v1/receipt/{receipt_id}
→ { "owner": "hex64", "transfers": [...], "latest_proof": InclusionProof }
```

**4. Checkpoint (log → anyone)**

A log publishes its latest signed checkpoint.

```
GET /v1/checkpoint
→ { "root": "hex64", "log_size": uint64, "timestamp": uint64,
     "operator_signature": "hex128", "witnesses": [...] }
```

**5. Witness request (log → peer log)**

A log sends its checkpoint to a peer for countersigning. See Section 11.3.7.

#### 11.3.5 Submission Flow

When a transfer occurs between two agents:

1. The seller constructs a `TransferRecord`, signs it, and computes `canonical_bytes`.
2. The seller (or buyer, or both) submits the signed transfer to one or more logs.
3. Each log validates the submission (Section 11.3.6), appends the entry, and returns an inclusion proof with a signed checkpoint.
4. The submitter collects inclusion proofs. The transfer is considered confirmed at the submitter's chosen threshold (Section 11.3.10).

The submitter decides which logs to submit to and how many confirmations to require. The protocol does not mandate a specific set of logs. A submitter that submits to only one log accepts the trust properties of that single log.

#### 11.3.6 Log Validation Rules

Before appending an entry, a log MUST perform these checks in order:

1. **Signature verification.** Verify `seller_signature` against `from_key` over `transfer_hash`. Reject if invalid.
2. **Canonical reconstruction.** Reconstruct `canonical_bytes` from the submitted fields. Reject if they don't match the submitted `canonical_bytes`.
3. **Double-spend detection.** (Section 11.3.8)
4. **Duplicate leaf rejection.** Compute `leaf_hash = H(0x00 || entry_bytes)` where `entry_bytes = canonical_bytes || BE64(log_timestamp)`. Reject if `leaf_hash` already exists in the tree.
5. **Append.** Add the leaf to the Merkle tree. Update the root. Sign a new checkpoint.

#### 11.3.7 Witnessed Checkpoints

A checkpoint signed by a single log operator proves that operator's claim about the tree state. Witnessed checkpoints extend this to multi-party attestation.

**Checkpoint binary format** (69 bytes, fixed):

```
"tessera-checkpoint-v1" (21 bytes) || BE64(log_size) || root (32 bytes) || BE64(timestamp)
```

The operator signs these 69 bytes with Ed25519. Witnesses countersign the exact same bytes.

**Witness protocol:**

1. After appending one or more entries, the log operator signs a checkpoint.
2. The operator sends the checkpoint to each configured peer:
   ```
   POST /v1/internal/witness
   { "checkpoint": { "root": "hex64", "log_size": uint64, "timestamp": uint64 },
     "operator_key": "hex64", "operator_signature": "hex128" }
   ```
3. The peer verifies:
   - The `operator_signature` is valid for `operator_key` over the checkpoint bytes.
   - `log_size` is greater than or equal to the last witnessed `log_size` for this operator (no rollback).
4. If valid, the peer countersigns the same 69 checkpoint bytes and returns:
   ```
   { "witness_key": "hex64", "witness_signature": "hex128" }
   ```
5. The operator collects witness signatures and includes them in the checkpoint response.

**Witness threshold.** A log operator configures a witness threshold (e.g. 2-of-3). A checkpoint is "fully witnessed" when the threshold is met. The threshold is an operator parameter, not a protocol constant. A log with `threshold = 0` operates without witnessing.

**Rollback detection.** A witness MUST reject a checkpoint if `log_size` is strictly less than the last `log_size` it witnessed for that operator. This prevents a malicious log from truncating its tree to erase transfers. Equal `log_size` with a different root is also rejected (fork detection).

#### 11.3.8 Double-Spend Detection

Before accepting a transfer, a log checks:
1. Has this `receipt_id` been transferred before in this log?
2. If yes, does the stored `to_key` (from the previous transfer) match the new `from_key`?
3. If not, reject: double-spend detected.

A double-spend attempt that goes to two different logs is detected at verification time: a verifier queries multiple logs for the current owner of a receipt (Section 11.3.9). If the logs disagree, a double-spend has occurred.

#### 11.3.9 Cross-Log Consistency Verification

A verifier queries multiple logs for the current owner of a `receipt_id`. Three outcomes:

1. **All logs agree.** Ownership is consistent. Confidence scales with the number of logs queried and the independence of their operators.
2. **Some logs have no record.** The receipt was not submitted to those logs. Not a conflict — the submitter chose fewer logs. The verifier trusts only the logs that have records, weighted by their witness status.
3. **Logs disagree on owner.** A double-spend has occurred. The conflicting transfer records are public evidence. Both logs have signed checkpoints proving they accepted different transfers. The double-spender's identity (`from_key` appears in both conflicting records) is cryptographically proven. Their effective stake (Section 12.1) drops to zero.

#### 11.3.10 Confirmation Semantics

A submitter chooses their confirmation threshold based on transaction value:

| Transaction value | Suggested threshold | Rationale |
|---|---|---|
| Low (< 100 units) | 1 log | Risk bounded by value. Speed matters more. |
| Medium (100–10,000) | 2-of-3 logs | Balance of speed and safety. |
| High (> 10,000) | 3-of-5 logs, fully witnessed | Maximum assurance. |

These are recommendations, not protocol rules. The buyer always decides. Confirmations are fast (seconds, not minutes) because log append is O(1) — there is no proof-of-work delay.

#### 11.3.11 Log Synchronisation

Logs do NOT replicate each other's state. Each log is an independent record of the submissions it has received. Two logs that receive the same transfer will have the same ownership result but different Merkle trees (because `log_timestamp` differs, and entry ordering may differ).

This is by design. Full replication would require consensus (the thing this protocol avoids). Instead, consistency emerges from verifiers querying multiple independent logs — the same principle as Certificate Transparency.

A log MAY offer a feed of recent entries for monitoring purposes, but this is not required by the protocol.

#### 11.3.12 Log Operator Incentives

A log operator benefits from running a log in three ways:

1. **Transaction fees.** A log MAY charge a fee per submission. The fee is negotiated out-of-band (pricing page, API key tiers, etc.). The protocol does not define fee structure.
2. **Trust quotient visibility.** Agents prefer submitting to well-witnessed logs. A log operator with more peers and higher uptime attracts more submissions, increasing fee revenue.
3. **Network participation.** An agent that also operates a log can submit its own transfers at zero cost and gains direct visibility into the network's transfer activity.

The protocol does not mandate that logs charge fees. A log operator who runs a log for their own agents' transfers (self-hosting) needs no external revenue.

#### 11.3.13 Liveness

The protocol is available as long as at least one log is reachable. There is no minimum network size. A single log provides weaker trust guarantees but full functionality. The network degrades gracefully — losing a log reduces redundancy but does not halt the system.

---

## 12. Trust and Stake

### 12.1 Effective Stake

For any operator, three quantities are deterministically computable from public VCR data:

**Direct value.** Sum of `original_price` across all their receipts. Settled receipts (transferred at least once) are weighted by a `settled_multiplier` (default 3.0), scaled by counterparty diversity. Unsettled receipts count at face value.

```
direct_value = Σ(receipt.original_price × multiplier)
  where multiplier = settled_multiplier × diversity   if transfer_count > 0
                   = 1.0                              otherwise
```

**Royalty NPV.** Net present value of future royalty income, estimated from royalty terms, transfer velocity, and a discount rate.

```
For each receipt with transfer_count > 0:
  base = original_price × (provider_royalty / 10000) × transfer_count
  royalty_npv += base × annuity_factor

annuity_factor = (1 - (1 + discount_rate)^(-royalty_horizon)) / discount_rate
```

**Dependency depth.** Count of downstream VCRs that reference this operator's receipts as parents.

**Combined formula:**

```
raw_stake = direct_weight × direct_value
          + royalty_weight × royalty_npv
          + depth_weight × dependency_count × depth_unit_value

effective_stake = raw_stake × max(counterparty_diversity, floor) + vouched_stake
```

### 12.2 Stake Parameters

| Parameter | Default | Description |
|---|---|---|
| `discount_rate` | 0.10 | Annual, for royalty NPV. |
| `royalty_horizon` | 10 | Future periods to estimate. |
| `direct_weight` | 1.0 | Weight for direct value component. |
| `royalty_weight` | 0.5 | Weight for royalty stream component. |
| `depth_weight` | 0.3 | Weight for dependency depth component. |
| `depth_unit_value` | 100 | Currency units per downstream dependent. |
| `settled_multiplier` | 3.0 | Settled receipts count 3x vs unsold claims. |
| `min_counterparties` | 5 | Minimum unique counterparties for full diversity. |
| `counterparty_floor` | 0.1 | Minimum diversity multiplier. |

These are market parameters, not protocol constants. The protocol defines the mechanisms; deployments set the parameters.

### 12.3 Counterparty Diversity

Reference implementation: first-order EigenTrust-family local trust scoring.

For each counterparty of operator O:
1. Compute `independence = 1.0 - (interactions_with_O / total_interactions)`.
2. `mean_independence = sum(independence) / counterparty_count`.
3. `diversity_penalty = min(1.0, counterparty_count / min_counterparties)`.
4. `counterparty_diversity = mean_independence × diversity_penalty`.

Returns a value in [0, 1]. Isolated sybil clusters get near-zero diversity. Well-connected legitimate operators approach 1.0.

### 12.4 Eigenvector Reputation (Full EigenTrust)

The protocol produces an interaction graph (receipts with parents create bilateral interactions, transfers create bilateral interactions). This graph is the input to eigenvector reputation computation.

Reference implementation: power iteration over the interaction graph.

```
1. Initialise scores[op] = 1.0 for all operators.
2. For each iteration (max 20, or until convergence < 1e-6):
   a. For each operator op:
      i.  For each counterparty cp of op:
          - independence = 1.0 - (interactions(op, cp) / total_interactions(cp))
          - weighted_sum += scores[cp] × independence
      ii. new_scores[op] = weighted_sum / counterparty_count(op)
   b. Normalise: new_scores = new_scores / max(new_scores)
   c. Check convergence: delta = Σ|new - old|
3. Return scores ∈ [0, 1] for each operator.
```

Mathematically equivalent to PageRank applied to the interaction graph. Isolated sybil clusters converge to zero.

### 12.5 Trust Quotient

```
trust_quotient = effective_stake / transaction_value
```

A quotient of 73 means the operator has 73x more to lose than they could gain by cheating on this transaction. A quotient of 0 means they have nothing to lose.

### 12.6 Settlement Terms

| Quotient | Recommendation |
|---|---|
| >= 50 | Instant settlement. Stake dwarfs the transaction. |
| 5–50 | Standard escrow. |
| < 5 | Collateral required. |

Thresholds are market parameters, not protocol constants. The protocol computes the quotient; participants decide how to use it.

### 12.7 Vouching

An established operator can vouch for a newcomer by contributing a fraction of their own stake:

```
vouched_stake = Σ(voucher_own_stake × stake_fraction)
```

Where `voucher_own_stake` excludes vouched contributions (prevents circular amplification).

### 12.8 Cold Start

A new operator with zero history has an effective stake of zero. Initial path:
1. Accept smaller transaction limits.
2. Get vouched by an established operator.
3. Build history through real transactions with diverse counterparties.
4. Trust quotient rises with every honest transaction.

---

## 13. Marketplace Metadata

For price discovery, these fields surface to buyers without revealing the output:

| Field | Purpose |
|---|---|
| `model_id` | What model produced this. |
| `proving_backend` | What verification system. |
| `provenance_depth` | How many layers deep. |
| `parent_receipts` count | What it's derived from. |
| `original_price` | What the computation cost. |
| `transfer_count` | How many prior resales. |
| `timestamp` | When it was computed. |
| `royalty_terms` | What ongoing costs attach. |

Sufficient for a rational purchasing decision without seeing the output.

---

## 14. Security Properties

### 14.1 What Holds

**Proof unforgeability.** Cannot create a valid proof for a computation not performed. Follows from proving system soundness.

**Signature unforgeability.** Cannot attribute a receipt to a provider who did not create it. Follows from Ed25519 security.

**Tamper detection.** Changing any canonical field changes `receipt_hash`, breaking the signature and all descendant provenance links.

**Output binding.** Cannot substitute a different output. `H(output_data) != output_hash` is caught at verification step 6.4.

**Double-sell prevention.** Transfer ledger enforces single ownership. Transparency logs provide global detection.

### 14.2 What Does Not Hold

**Price inflation.** `original_price` is self-reported. Mitigation: effective stake weights settled receipts higher than unsold claims. The market is the price oracle.

**Provenance claims are self-reported.** A producer can reference parent receipts they did not actually use. Mitigation: honest provenance is profitable through royalty participation and depth as a credibility signal. Dishonest provenance is detectable through a missing transfer record. See the game theory analysis.

**Timestamps are self-reported.** Production deployments use transparency log append order as authoritative ordering.

**Royalty enforcement is voluntary.** A hostile buyer can skip payments. Mitigation: the transparency log makes it visible and their trust quotient drops.

**Metadata leakage.** `model_id` identifies the model. `input_hash` identifies the input. For small input spaces, an attacker can brute-force the hash.

**ZK limits.** Fixed-point arithmetic limits model complexity. This is a backend limitation, not a protocol limitation.

### 14.3 Threat Model

The adversary cannot break SHA-256, Ed25519, or the proving system's soundness. Everything else is economic. The protocol makes fraud expensive in proportion to its payoff.

### 14.4 Edge Cases

The following boundary conditions have defined behaviour. Implementations MUST enforce these rules at validation time (before signing and at ingestion).

#### 14.4.1 Royalty Rate Bounds

`provider_royalty` and `parent_royalty` are each in the range [0, 10000] basis points. Their sum MUST NOT exceed 10000 bps. A receipt with `provider_royalty + parent_royalty > 10000` MUST be rejected with a validation error. This prevents payout exceeding 100% of the sale price.

- `provider_royalty = 7000, parent_royalty = 3000` (sum = 10000): **valid**.
- `provider_royalty = 7000, parent_royalty = 5000` (sum = 12000): **rejected**.
- `provider_royalty = 0, parent_royalty = 0`: **valid** (no royalties owed).

#### 14.4.2 Zero-Length Proofs

An empty `proof` field (zero bytes) is **valid** at the receipt layer. The receipt is structurally correct and produces a deterministic `receipt_id`. Proof verification is the responsibility of the proving backend (Section 7), not the receipt schema. A zero-length proof will fail backend verification but is not a receipt validation error.

#### 14.4.3 Empty Parent Lists with Cascade

A root receipt (`parent_receipts = []`) with `cascade = true` and `parent_royalty > 0` is **valid**. The `parent_royalty` field is declarative — it specifies terms for future resale, not a constraint on construction. During settlement (Section 9.3), the parent royalty share is only computed when `parent_receipts` is non-empty. For root receipts, the parent royalty share is zero and the full remainder goes to the seller.

#### 14.4.4 Self-Referencing Parent Receipts

A receipt cannot reference itself as a parent. This is **cryptographically impossible** by construction: `receipt_id = SHA-256(canonical_bytes)` and `canonical_bytes` includes `parent_receipts`. To self-reference, a receipt would need `receipt_id = SHA-256(...receipt_id...)`, which requires finding a SHA-256 fixed point — computationally infeasible. No runtime check is needed.

#### 14.4.5 Duplicate Parent Entries

A receipt MUST NOT contain two `ParentRef` entries with the same `receipt_id`. Duplicate parent entries MUST be rejected with a validation error. Rationale: duplicate parents would cause double-counting in royalty distribution (Section 9.3), where `per_parent = parent_cut_total // len(parent_receipts)` splits the parent share equally.

#### 14.4.6 Provenance Depth

`provenance_depth` MUST NOT exceed 256. A receipt with `provenance_depth > 256` MUST be rejected. This bounds the maximum recursion depth of the royalty cascade algorithm (Section 9.3). In practice, geometric diminishment means cascades beyond depth ~10 contribute negligibly (see Section 9.4), but the hard cap prevents denial-of-service via deep fabricated chains.

- `provenance_depth = 0` with `parent_receipts = []`: **valid** (root receipt).
- `provenance_depth = 256`: **valid** (boundary).
- `provenance_depth = 257`: **rejected**.

---

## 15. Transport

The canonical binary serialisation (Section 4) is used exclusively for hashing and signing. For network transport, receipts are encoded as JSON.

### 15.1 JSON Encoding

- `bytes` and `bytes32` fields: hex-encoded strings.
- `proof`, `public_inputs`, `signature`: base64-encoded strings.
- `output_data` (when present): base64-encoded string.
- Integer fields: JSON numbers.
- Boolean fields: JSON booleans.
- Lists: JSON arrays.
- Nested structures: JSON objects.
- Keys MUST be sorted alphabetically. Separators MUST be `(",", ":")` (compact, no whitespace).

JSON is used only for transport. Implementations MUST NOT use JSON for hashing or signing.

---

## 16. Conformance

A conformant implementation MUST:

1. Produce identical `receipt_id` values for identical receipt fields, using the canonical serialisation defined in Section 4.
2. Produce valid Ed25519 signatures per RFC 8032.
3. Verify all five checks in Section 6 in the specified order.
4. Implement the royalty cascade algorithm in Section 9.3 exactly as specified.
5. Implement transfer records with the canonical serialisation in Section 10.3.
6. Implement Merkle tree construction with the domain-separated hashing in Section 11.1.
7. Use SHA-256 as `H()` throughout.
8. Reject receipts that violate the edge case rules in Section 14.4 (royalty bounds, duplicate parents, provenance depth cap).

A conformant implementation MAY:
- Support additional `signature_scheme` values beyond `"ed25519"`.
- Support additional `proving_backend` values.
- Use any transport protocol (HTTP, gRPC, custom).
- Use any storage backend for the transfer ledger and transparency logs.
- Use any reputation algorithm that consumes the interaction graph, in place of the reference EigenTrust implementation.

Conformance is verified by producing correct outputs for the test vectors in the companion TEST-VECTORS.json file.

---

## Appendix A: Receipt Field Summary

| # | Field | Type | Canonical | Mutable |
|---|---|---|---|---|
| 1 | `schema_version` | uint16 | Yes | No |
| 2 | `model_id` | bytes32 | Yes | No |
| 3 | `verification_key_id` | bytes32 | Yes | No |
| 4 | `input_hash` | bytes32 | Yes | No |
| 5 | `output_hash` | bytes32 | Yes | No |
| 6 | `proof` | bytes | Yes | No |
| 7 | `public_inputs` | bytes | Yes | No |
| 8 | `proving_backend` | string | Yes | No |
| 9 | `timestamp` | uint64 | Yes | No |
| 10 | `parent_receipts` | ParentRef[] | Yes | No |
| 11 | `provenance_depth` | uint16 | Yes | No |
| 12 | `provider` | bytes32 | Yes | No |
| 13 | `original_price` | uint64 | Yes | No |
| 14 | `currency` | string | Yes | No |
| 15 | `royalty_terms` | RoyaltyTerms | Yes | No |
| 16 | `transfer_count` | uint16 | **No** | **Yes** |
| 17 | `signature` | bytes | **No** | No |
| 18 | `signature_scheme` | string | Yes | No |
| 19 | `extensions` | Extension[] | Yes | No |
| — | `receipt_id` | bytes32 | Derived | — |
| — | `receipt_hash` | bytes32 | Derived | — |

21 logical fields. 17 in canonical serialisation. 2 excluded. 2 derived.
