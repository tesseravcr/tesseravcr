# VCR Protocol Specification

The Verified Compute Receipt (VCR) is a protocol for verifiable, transferable, economically composable AI computation between autonomous agents.

This directory contains the canonical protocol definition. It is implementation-agnostic. Any implementation that conforms to this specification is a valid participant in the protocol.

## Documents

| Document | Description |
|---|---|
| [VCR-SPEC.md](VCR-SPEC.md) | Formal protocol specification. Receipt schema, canonical serialisation, verification procedure, settlement, transfer, transparency logs, trust computation. A developer should be able to build a conformant implementation from this document alone. |
| [WHITEPAPER.md](WHITEPAPER.md) | Vision and motivation. Why the VCR exists, what problem it solves, how it relates to existing systems, security analysis, incentive analysis. |
| [TEST-VECTORS.json](TEST-VECTORS.json) | Reference test cases. Known inputs with expected canonical bytes, hashes, signatures, and royalty cascade outputs. Use these to verify that an implementation is conformant. |

## Conformance

A conformant implementation MUST produce identical `receipt_id` values for identical receipt fields. The canonical serialisation in VCR-SPEC.md Section 4 is normative. TEST-VECTORS.json provides reference cases for verification.

## Implementations

| Language | Repository | Status |
|---|---|---|
| Python | [tessera-py](../tessera-py/) | Reference implementation |
| Rust | [tessera-rust](../tessera-rust/) | Conformant implementation |

## Generating Test Vectors

Test vectors are generated from the reference implementation:

```
cd tesseravcr/tessera-py
python3 generate_test_vectors.py
```

Keys are randomly generated per run. Structural properties (lengths, algorithms, cascade logic) are deterministic. Receipt IDs and signatures change per generation because keys differ. A future version will use fixed test keys for fully deterministic vectors.
