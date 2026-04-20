# Tessera — Reference Implementation

Reference implementation of the [VCR Protocol Specification](../spec/VCR-SPEC.md) in Python.

Seven modules, ~1500 lines, one external dependency (`cryptography`). Every claim in the [whitepaper](../spec/WHITEPAPER.md) runs.

## Run It

```
pip install cryptography
python3 demo.py
```

The demo walks through a realistic scenario where an autonomous investment agent assembles a due diligence pipeline from four specialist agents. It demonstrates receipts, provenance DAGs, royalty cascades, trust quotients, sybil resistance, and tamper detection. One command, zero setup.

## Protocol Modules

```
protocol/
  receipt.py         278 lines    receipt schema, canonical serialisation, verification
  settlement.py      137 lines    escrow, royalty cascade through provenance DAG
  transfer.py        121 lines    ownership tracking, transfer records, double-sell prevention
  stake.py           456 lines    self-collateralising trust, EigenTrust sybil resistance
  registry.py        157 lines    publish and discover operators and VCRs
  transparency.py    283 lines    append-only Merkle trees, double-spend detection
  tee_backend.py      72 lines    bridge between TEE attestation and VCR receipts
```

## Proving Backends

Two backends demonstrated:

```
ZK (EZKL/Halo2)    mathematical proof of correct computation for deterministic models
TEE (Nitro)         hardware-rooted attestation from AWS Nitro Enclaves, works with any model
```

See `examples/nitro-tee/` for the TEE implementation and `tools/verify_attestation.py` for standalone attestation verification.

## Tests

```
cd tesseravcr
PYTHONPATH=tessera-sdk python3 tessera-py/tests/test_protocol.py    # 24 protocol tests
PYTHONPATH=tessera-sdk python3 tessera-py/tests/simulate.py          # 300-round adversarial simulation
python3 tessera-py/generate_test_vectors.py                          # regenerate spec test vectors
```

## Conformance

This implementation produces outputs conformant with [TEST-VECTORS.json](../spec/TEST-VECTORS.json). The canonical serialisation, hash computation, and signature generation match the specification in [VCR-SPEC.md](../spec/VCR-SPEC.md) Section 4.

## Specification

The protocol is defined in [spec/](../spec/). This implementation is a reference — any implementation producing identical `receipt_id` values for identical fields is a valid participant.

MIT license.
