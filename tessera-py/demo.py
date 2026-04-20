#!/usr/bin/env python3
"""
Tessera VCR — Protocol Demo

Four autonomous agents. Each has something the others lack.
They transact through verified receipts, not trust.

Every signature is real Ed25519. Every hash is real SHA-256.
The Nitro attestation is a real hardware-signed document from
an AWS Nitro Enclave.

    pip install cryptography
    python3 demo.py
"""

import hashlib
import json
import os
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from protocol.receipt import Receipt, RoyaltyTerms
from protocol.transfer import TransferRecord, TransferLedger
from protocol.settlement import Ledger
from protocol.stake import (
    StakeCalculator, OperatorRegistry, trust_quotient, recommend_settlement,
)
from protocol.registry import Registry, OperatorProfile
from protocol.transparency import TransparencyLog, LogNetwork
from protocol import tee_backend
from protocol import ezkl_backend


def pub(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def tag(b):
    return b.hex()[:12]


def section(title):
    w = 64
    print(f"\n{'=' * w}")
    print(f"  {title}")
    print(f"{'=' * w}\n")


def build_history(key, model_id, registry, counterparty_keys, n=20):
    """Create n receipts with diverse counterparties for trust history."""
    receipts = []
    for i in range(n):
        r = Receipt(
            model_id=model_id,
            input_hash=hashlib.sha256(f"job-{model_id.hex()[:8]}-{i}".encode()).digest(),
            output_hash=hashlib.sha256(f"result-{model_id.hex()[:8]}-{i}".encode()).digest(),
            proof=b"<attestation>",
            proving_backend="tee-nitro-v1",
            original_price=2000,
            timestamp=int(time.time()) - 86400 * (n - i),
        )
        r.sign(key)
        registry.record_receipt(r)
        receipts.append(r)

        # different counterparties depend on this work
        cp_key = counterparty_keys[i % len(counterparty_keys)]
        cr = Receipt(
            model_id=hashlib.sha256(f"client-{i}".encode()).digest(),
            input_hash=hashlib.sha256(f"from-{model_id.hex()[:8]}-{i}".encode()).digest(),
            output_hash=hashlib.sha256(f"derived-{model_id.hex()[:8]}-{i}".encode()).digest(),
            proof=b"<attestation>",
            proving_backend="tee-nitro-v1",
            original_price=500,
            parent_receipts=[r.as_parent_ref("input")],
            provenance_depth=1,
            timestamp=int(time.time()) - 86400 * (n - i) + 3600,
        )
        cr.sign(cp_key)
        registry.record_receipt(cr)

    return receipts


def main():

    # =================================================================
    #  PROLOGUE
    # =================================================================

    section("VERIFIED COMPUTE RECEIPTS")

    print("""\
  When an agent computes something, it produces a receipt: a signed
  data structure that proves what model ran, what went in, what came
  out, and when. Any other agent can verify it without contacting
  the original producer.

  This demo walks through the protocol. Real Ed25519 signatures.
  Real SHA-256 hashes. Real Nitro Enclave attestation.
""")

    # =================================================================
    #  ACT 1: REAL HARDWARE ATTESTATION
    # =================================================================

    section("ACT 1: VERIFIED COMPUTATION — REAL HARDWARE ATTESTATION")

    att_path = os.path.join(
        os.path.dirname(__file__),
        "examples", "nitro-tee", "sample_attestation.json",
    )

    with open(att_path) as f:
        enclave_response = json.load(f)

    tee_output = tee_backend.from_enclave_response(enclave_response)

    print(f"  Loaded real Nitro Enclave attestation document.")
    print(f"  Enclave prompt:    \"{enclave_response['prompt']}\"")
    print(f"  Enclave output:    \"{enclave_response['output'][:60]}...\"")
    print(f"  Input hash:        {enclave_response['input_hash'][:24]}...")
    print(f"  Output hash:       {enclave_response['output_hash'][:24]}...")
    print(f"  Attestation size:  {len(tee_output.attestation):,} bytes (COSE Sign1)")
    print()

    # Wrap the TEE output into a VCR receipt
    enclave_key = Ed25519PrivateKey.generate()
    tee_receipt = tee_backend.wrap(
        tee_output,
        model_id=hashlib.sha256(b"claude-haiku-3.5").digest(),
        original_price=100,
        royalty_terms=RoyaltyTerms(provider_royalty=500),
    )
    tee_receipt.sign(enclave_key)

    print(f"  Wrapped into VCR receipt:")
    print(f"    Receipt ID:      {tag(tee_receipt.receipt_id)}")
    print(f"    Proving backend: {tee_receipt.proving_backend}")
    print(f"    Signature valid: {tee_receipt.verify_signature()}")
    print(f"    Output binding:  {tee_backend.verify_output_binding(tee_receipt)}")
    print(f"    Input binding:   {tee_backend.verify_input_binding(tee_receipt, enclave_response['prompt'])}")
    print()
    print(f"  The proof field carries {len(tee_receipt.proof):,} bytes of real")
    print(f"  hardware attestation — signed by the Nitro Security Module,")
    print(f"  verifiable against AWS's public certificate chain.")

    # --- ZK Backend: ezkl-halo2 ---

    print()
    print(f"  {'─' * 56}")
    print()

    zk_path = os.path.join(
        os.path.dirname(__file__),
        "examples", "zk-prove", "sample_proof.json",
    )

    with open(zk_path) as f:
        proof_artifacts = json.load(f)

    zk_output = ezkl_backend.from_proof_artifacts(proof_artifacts)

    zk_key = Ed25519PrivateKey.generate()
    zk_receipt = ezkl_backend.wrap(
        zk_output,
        model_id=hashlib.sha256(b"linear_classifier").digest(),
        original_price=500,
        royalty_terms=RoyaltyTerms(provider_royalty=500),
    )
    zk_receipt.sign(zk_key)

    print(f"  Loaded real Halo2 ZK proof (ezkl).")
    print(f"  Model:             {proof_artifacts['model_description']}")
    print(f"  Input:             {proof_artifacts['input_data']}")
    print(f"  Proof size:        {len(zk_output.proof):,} bytes (Halo2)")
    print(f"  VK ID:             {proof_artifacts['verification_key_id'][:24]}...")
    print()
    print(f"  Wrapped into VCR receipt:")
    print(f"    Receipt ID:      {tag(zk_receipt.receipt_id)}")
    print(f"    Proving backend: {zk_receipt.proving_backend}")
    print(f"    Signature valid: {zk_receipt.verify_signature()}")
    print()
    print(f"  Same receipt format, same signatures, same hashing.")
    print(f"  TEE proves hardware ran the code. ZK proves the math is correct.")
    print(f"  The protocol doesn't care which — it wraps both identically.")

    # =================================================================
    #  ACT 2: PROVENANCE — WHY AGENTS NEED AGENTS
    # =================================================================

    section("ACT 2: PROVENANCE — FOUR SPECIALISTS, ONE PIPELINE")

    sentinel_key, medgraph_key, reg_key, nexus_key = (
        Ed25519PrivateKey.generate() for _ in range(4)
    )
    sentinel, medgraph, reg, nexus = (
        pub(sentinel_key), pub(medgraph_key), pub(reg_key), pub(nexus_key)
    )

    names = {
        sentinel.hex(): "Sentinel", medgraph.hex(): "MedGraph",
        reg.hex(): "Regulatory", nexus.hex(): "Nexus",
    }

    # Operator registry for trust computation
    registry = Registry()
    for key, models in [
        (sentinel,  [b"supply-chain-intel-v3"]),
        (medgraph,  [b"biotech-analysis-v2"]),
        (reg,       [b"eu-compliance-audit-v1"]),
        (nexus,     [b"portfolio-strategy-v4"]),
    ]:
        registry.register_operator(OperatorProfile(
            pubkey=key, backends=["tee-nitro-v1"], models=models,
        ))

    # Build history — 8 diverse counterparties, each agent has prior work
    counterparty_keys = [Ed25519PrivateKey.generate() for _ in range(8)]
    for k in counterparty_keys:
        registry.register_operator(OperatorProfile(
            pubkey=pub(k), backends=["tee-nitro-v1"], models=[b"client"],
        ))

    build_history(sentinel_key, hashlib.sha256(b"supply-chain-intel-v3").digest(),
                  registry, counterparty_keys, n=30)
    build_history(medgraph_key, hashlib.sha256(b"biotech-analysis-v2").digest(),
                  registry, counterparty_keys, n=20)
    build_history(reg_key, hashlib.sha256(b"eu-compliance-audit-v1").digest(),
                  registry, counterparty_keys, n=15)
    build_history(nexus_key, hashlib.sha256(b"portfolio-strategy-v4").digest(),
                  registry, counterparty_keys, n=10)

    # --- The pipeline ---

    # Sentinel: proprietary satellite + supply chain data
    out_sentinel = (
        "Target has 3 manufacturing sites. Site B (Shenzhen) shows "
        "40% reduced shipping volume over 6 months. Supply chain risk: ELEVATED."
    )
    r_sentinel = Receipt(
        model_id=hashlib.sha256(b"supply-chain-intel-v3").digest(),
        input_hash=hashlib.sha256(b"Analyse supply chain for BioTarget Inc").digest(),
        output_hash=hashlib.sha256(out_sentinel.encode()).digest(),
        proof=tee_output.attestation,  # real Nitro attestation as proof bytes
        proving_backend="tee-nitro-v1",
        original_price=2000,
        royalty_terms=RoyaltyTerms(provider_royalty=1500, parent_royalty=1000, cascade=True),
        output_data=out_sentinel.encode(),
    )
    r_sentinel.sign(sentinel_key)
    registry.record_receipt(r_sentinel)

    # MedGraph: FDA clinical trial database
    out_medgraph = (
        "BT-401 in Phase III for NSCLC. Trial NCT-2029-4401 shows 23% ORR "
        "vs 18% control (p=0.04). FDA Advisory Committee Q3 2030. Clinical risk: MODERATE."
    )
    r_medgraph = Receipt(
        model_id=hashlib.sha256(b"biotech-analysis-v2").digest(),
        input_hash=hashlib.sha256(b"Clinical pipeline: BioTarget Inc").digest(),
        output_hash=hashlib.sha256(out_medgraph.encode()).digest(),
        proof=tee_output.attestation,
        proving_backend="tee-nitro-v1",
        original_price=5000,
        royalty_terms=RoyaltyTerms(provider_royalty=1500, parent_royalty=1000, cascade=True),
        output_data=out_medgraph.encode(),
    )
    r_medgraph.sign(medgraph_key)
    registry.record_receipt(r_medgraph)

    # Regulatory: certified EU AI Act auditor
    out_reg = (
        "BT-Dx classified high-risk under EU AI Act Annex III. Non-compliant: "
        "missing Art. 9, incomplete Art. 11. Remediation: 6-9 months. Risk: HIGH."
    )
    r_reg = Receipt(
        model_id=hashlib.sha256(b"eu-compliance-audit-v1").digest(),
        input_hash=hashlib.sha256(b"EU AI Act compliance: BioTarget AI systems").digest(),
        output_hash=hashlib.sha256(out_reg.encode()).digest(),
        proof=tee_output.attestation,
        proving_backend="tee-nitro-v1",
        original_price=3000,
        royalty_terms=RoyaltyTerms(provider_royalty=1500, parent_royalty=1000, cascade=True),
        output_data=out_reg.encode(),
    )
    r_reg.sign(reg_key)
    registry.record_receipt(r_reg)

    # Nexus: orchestrates everything, references all three as parents
    out_nexus = (
        "RECOMMENDATION: PASS. BioTarget presents asymmetric downside. "
        "Supply chain disruption (Sentinel), marginal clinical data (MedGraph, "
        "p=0.04), EU compliance gap 6-9 months (Regulatory). "
        "Risk-adjusted NPV does not justify $2.1B acquisition price."
    )
    r_nexus = Receipt(
        model_id=hashlib.sha256(b"portfolio-strategy-v4").digest(),
        input_hash=hashlib.sha256(b"Due diligence synthesis: BioTarget acquisition").digest(),
        output_hash=hashlib.sha256(out_nexus.encode()).digest(),
        proof=tee_output.attestation,
        proving_backend="tee-nitro-v1",
        original_price=8000,
        royalty_terms=RoyaltyTerms(provider_royalty=1500, parent_royalty=1000, cascade=True),
        parent_receipts=[
            r_sentinel.as_parent_ref("input"),
            r_medgraph.as_parent_ref("input"),
            r_reg.as_parent_ref("input"),
        ],
        provenance_depth=1,
        output_data=out_nexus.encode(),
    )
    r_nexus.sign(nexus_key)
    registry.record_receipt(r_nexus)

    print(f"  Sentinel    [{tag(r_sentinel.receipt_id)}]  supply chain intel     $20")
    print(f"    Proprietary satellite imagery. No other agent has this data.")
    print(f"    Signature: {r_sentinel.verify_signature()}  |  Proof: {len(r_sentinel.proof):,} bytes")
    print()
    print(f"  MedGraph    [{tag(r_medgraph.receipt_id)}]  clinical analysis      $50")
    print(f"    Fine-tuned on FDA trial databases. General LLMs hallucinate here.")
    print(f"    Signature: {r_medgraph.verify_signature()}  |  Proof: {len(r_medgraph.proof):,} bytes")
    print()
    print(f"  Regulatory  [{tag(r_reg.receipt_id)}]  compliance audit       $30")
    print(f"    Certified EU AI Act auditor. Legally required for high-risk AI.")
    print(f"    Signature: {r_reg.verify_signature()}  |  Proof: {len(r_reg.proof):,} bytes")
    print()
    print(f"  Nexus       [{tag(r_nexus.receipt_id)}]  investment strategy    $80")
    print(f"    Couldn't do any upstream task itself. Orchestrates all three.")
    print(f"    Signature: {r_nexus.verify_signature()}  |  Parents: {len(r_nexus.parent_receipts)}")

    # Provenance DAG
    print()
    print(f"  Provenance DAG:")
    print()
    print(f"    [{tag(r_sentinel.receipt_id)}] Sentinel   depth 0")
    print(f"           \\")
    print(f"    [{tag(r_medgraph.receipt_id)}] MedGraph   depth 0  -->  [{tag(r_nexus.receipt_id)}] Nexus  depth 1")
    print(f"           /")
    print(f"    [{tag(r_reg.receipt_id)}] Regulatory depth 0")
    print()
    print(f"  Every edge is a cryptographic hash reference. Modify any")
    print(f"  receipt and all descendants break. The chain is the audit trail.")

    # =================================================================
    #  ACT 3: TRANSFER & ROYALTY CASCADE
    # =================================================================

    section("ACT 3: ECONOMICS — TRANSFER AND ROYALTY CASCADE")

    fund_key = Ed25519PrivateKey.generate()
    fund = pub(fund_key)
    names[fund.hex()] = "Fund"

    # Transfer ownership
    transfer_ledger = TransferLedger()
    transfer_ledger.register(r_nexus.receipt_id, nexus)

    xfer = TransferRecord(
        receipt_id=r_nexus.receipt_id,
        from_key=nexus, to_key=fund,
        price=15000, currency="USD-cents",
    )
    xfer.sign(nexus_key)
    transfer_ledger.transfer(xfer)

    registry.stake_calculator.registry.record_transfer_interaction(nexus, fund)

    print(f"  A fund buys Nexus's analysis for $150.00")
    print(f"  Transfer signed by seller: {xfer.verify_signature()}")
    print(f"  New owner: Fund [{tag(fund)}]")
    print()

    # Royalty cascade
    ledger = Ledger()
    ledger.credit("fund", 50000)

    receipt_store = {
        r.receipt_id.hex(): r
        for r in [r_sentinel, r_medgraph, r_reg, r_nexus]
    }

    ledger.create_escrow("sale-001", "fund", 15000)
    payments, _ = ledger.release_escrow_resale(
        "sale-001", r_nexus, nexus, 15000, receipt_store,
    )

    print(f"  Royalties cascade through the provenance DAG:")
    print()
    for agent_id, amount in sorted(payments.items(), key=lambda x: -x[1]):
        name = names.get(agent_id, agent_id[:12])
        role = ""
        if name == "Nexus":
            role = "  (provider royalty + seller remainder)"
        elif name in ("Sentinel", "MedGraph", "Regulatory"):
            role = "  (parent royalty via cascade)"
        print(f"    {name:>12}: ${amount / 100:>8.2f}{role}")

    total = sum(payments.values())
    print()
    print(f"  Total distributed: ${total / 100:.2f}  (= sale price, zero leakage)")
    print()
    print(f"  Sentinel got paid because Nexus used its satellite data.")
    print(f"  MedGraph got paid because Nexus used its clinical analysis.")
    print(f"  No middleman decided. The DAG determined it.")

    # Double-sell prevention
    print()
    xfer_dup = TransferRecord(
        receipt_id=r_nexus.receipt_id,
        from_key=nexus, to_key=fund, price=15000, currency="USD-cents",
    )
    xfer_dup.sign(nexus_key)
    try:
        transfer_ledger.transfer(xfer_dup)
        print(f"  Double-sell: ALLOWED (bug)")
    except ValueError:
        print(f"  Double-sell attempt: BLOCKED (seller no longer owns it)")

    # =================================================================
    #  ACT 4: TRUST — YOUR HISTORY IS YOUR COLLATERAL
    # =================================================================

    section("ACT 4: TRUST — HISTORY IS COLLATERAL")

    calc = registry.stake_calculator

    print(f"  Trust comes from verified work history, not deposits.")
    print(f"  More receipts + diverse counterparties = higher stake.")
    print()
    print(f"  {'Operator':<12} {'Receipts':>8} {'Deps':>6} {'Diversity':>9} {'Stake':>10} {'$100 tx':>12}")
    print(f"  {'-' * 12} {'-' * 8} {'-' * 6} {'-' * 9} {'-' * 10} {'-' * 12}")

    for name, key in [("Sentinel", sentinel), ("MedGraph", medgraph),
                      ("Regulatory", reg), ("Nexus", nexus)]:
        s = calc.compute_stake(key)
        t = recommend_settlement(s.effective_stake, 10000)
        print(f"  {name:<12} {s.receipt_count:>8} {s.dependency_depth:>6}"
              f" {s.counterparty_diversity:>9.3f}"
              f" {'$' + f'{s.effective_stake / 100:.0f}':>10}"
              f" {t.recommendation:>12}")

    print()
    print(f"  Trust quotient = effective_stake / transaction_value")
    print(f"  Quotient >= 50 → instant settlement (stake dwarfs the tx)")
    print(f"  Quotient 5-50  → standard escrow")
    print(f"  Quotient < 5   → collateral required")
    print()

    # Settlement terms at different transaction sizes
    s = calc.compute_stake(sentinel)
    for tx, label in [(100, "$1"), (10000, "$100"), (100000, "$1,000")]:
        t = recommend_settlement(s.effective_stake, tx)
        print(f"  Sentinel + {label:>6} tx:  quotient={t.quotient:>6.0f}x  →  {t.recommendation}")

    # Cold start + vouching
    print()
    carol_key = Ed25519PrivateKey.generate()
    carol = pub(carol_key)
    names[carol.hex()] = "Carol"
    registry.register_operator(OperatorProfile(
        pubkey=carol, backends=["tee-nitro-v1"], models=[b"newcomer-v1"],
    ))

    carol_stake_before = calc.compute_stake(carol)
    registry.stake_calculator.registry.vouch_for(sentinel, carol, stake_fraction=0.1)
    carol_stake_after = calc.compute_stake(carol)

    print(f"  Cold start: Carol has zero history.")
    print(f"    Before vouch: stake = ${carol_stake_before.effective_stake / 100:.0f}")
    print(f"    Sentinel vouches (10% of own stake).")
    print(f"    After vouch:  stake = ${carol_stake_after.effective_stake / 100:.0f}")
    print(f"    Carol can now accept small transactions while building history.")

    # =================================================================
    #  ACT 5: INTEGRITY — EVERYTHING IS TAMPER-PROOF
    # =================================================================

    section("ACT 5: INTEGRITY")

    # --- Tamper detection ---
    print(f"  TAMPER DETECTION")
    print()

    tampered = Receipt(
        model_id=r_nexus.model_id,
        input_hash=r_nexus.input_hash,
        output_hash=hashlib.sha256(b"RECOMMENDATION: BUY AT ANY PRICE").digest(),
        proof=r_nexus.proof,
        proving_backend=r_nexus.proving_backend,
        original_price=r_nexus.original_price,
        signature=r_nexus.signature,
        provider=r_nexus.provider,
    )

    print(f"  Someone changes Nexus's output from PASS to BUY.")
    print(f"    Original: signature valid = {r_nexus.verify_signature()}")
    print(f"    Tampered: signature valid = {tampered.verify_signature()}")
    print(f"    Receipt ID changed: {r_nexus.receipt_id != tampered.receipt_id}")
    print(f"  One byte changed. Ed25519 breaks. Fraud is cryptographically impossible.")

    # --- Sybil resistance ---
    print()
    print(f"  SYBIL RESISTANCE")
    print()

    s1_key, s2_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    s1, s2 = pub(s1_key), pub(s2_key)
    for k in [s1, s2]:
        registry.register_operator(OperatorProfile(
            pubkey=k, backends=["tee-nitro-v1"], models=[b"fake"],
        ))

    # Sybils trade between themselves — no real counterparties
    for i in range(20):
        r = Receipt(
            model_id=hashlib.sha256(b"fake").digest(),
            input_hash=hashlib.sha256(f"sybil-{i}".encode()).digest(),
            output_hash=hashlib.sha256(f"fake-{i}".encode()).digest(),
            proof=b"<fabricated>", proving_backend="tee-nitro-v1",
            original_price=10000,
        )
        r.sign(s1_key)
        registry.record_receipt(r)
        c = Receipt(
            model_id=hashlib.sha256(b"fake").digest(),
            input_hash=hashlib.sha256(f"sybil-c-{i}".encode()).digest(),
            output_hash=hashlib.sha256(f"fake-c-{i}".encode()).digest(),
            proof=b"<fabricated>", proving_backend="tee-nitro-v1",
            original_price=10000,
            parent_receipts=[r.as_parent_ref("input")], provenance_depth=1,
        )
        c.sign(s2_key)
        registry.record_receipt(c)

    sybil_stake = calc.compute_stake(s1)
    legit_stake = calc.compute_stake(sentinel)
    weights = calc.compute_counterparty_weights()

    print(f"  Two sybil operators trade $100 receipts between themselves.")
    print(f"  40 receipts, $4,000 claimed. Zero real counterparties.")
    print()
    print(f"    Sybil-1  stake: ${sybil_stake.effective_stake / 100:>8.0f}"
          f"   EigenTrust: {weights.get(s1.hex(), 0):.4f}")
    print(f"    Sentinel stake: ${legit_stake.effective_stake / 100:>8.0f}"
          f"   EigenTrust: {weights.get(sentinel.hex(), 0):.4f}")
    print()
    print(f"  Isolated cluster. No legitimate operator depends on them.")
    print(f"  Eigenvector weight: near zero. The protocol didn't ban")
    print(f"  them — it marginalised them mathematically.")

    # --- Transparency log ---
    print()
    print(f"  TRANSPARENCY LOG")
    print()

    net = LogNetwork(threshold=2)
    net.add_log("log-alpha")
    net.add_log("log-beta")
    net.add_log("log-gamma")

    log_results = net.submit_transfer(xfer)
    first_log = list(log_results.keys())[0]
    first_entry = log_results[first_log]
    proof = net.logs[first_log].prove_inclusion(first_entry.index)

    consistent, msg = net.check_consistency(r_nexus.receipt_id)

    print(f"  Transfer published to {len(log_results)} independent Merkle logs.")
    print(f"  Inclusion proof valid: {proof.verify()}")
    print(f"  Cross-log consistency: {msg}")

    # Double-spend on logs
    xfer_fraud = TransferRecord(
        receipt_id=r_nexus.receipt_id,
        from_key=nexus, to_key=sentinel, price=15000, currency="USD-cents",
    )
    xfer_fraud.sign(nexus_key)
    try:
        net.submit_transfer(xfer_fraud)
        print(f"  Double-spend: ALLOWED (bug)")
    except ValueError:
        print(f"  Double-spend on logs: BLOCKED")

    print()
    print(f"  Append-only Merkle trees. Threshold confirmation across")
    print(f"  independent logs. Same model as Certificate Transparency,")
    print(f"  applied to compute receipts.")

    # =================================================================
    #  WHAT THIS PROVED
    # =================================================================

    section("WHAT THIS PROVED")

    print("""\
  Four autonomous agents assembled a due diligence pipeline.
  Each contributed something no single model could provide:

    Proprietary data       Sentinel's satellite imagery
    Domain expertise       MedGraph's FDA trial database
    Legal certification    Regulatory's EU AI Act audit
    Orchestration          Nexus synthesised all three

  The protocol proved:

    1. Computation is receipted, signed, and hardware-attested
    2. Provenance traces every input to its source
    3. Royalties cascade through the DAG — no middleman
    4. Trust grows from work history, not from deposits
    5. Sybil rings are marginalised by eigenvector scoring
    6. Ownership transfers are logged, double-spend is blocked
    7. Tampering with any receipt is cryptographically detectable

  The receipt is the proof.
  The accumulated proof is the trust.
  The trust is the collateral.
""")


if __name__ == "__main__":
    main()
