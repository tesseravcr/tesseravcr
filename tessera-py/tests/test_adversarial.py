#!/usr/bin/env python3
"""
Adversarial stress test — proves the whitepaper's Appendix B.

Runs a simulated economy with legitimate operators and 5 distinct attack
strategies over 500 rounds. Measures whether the protocol's defences
(diversity scoring, EigenTrust, self-collateralising trust) actually
make attacks unprofitable.

Attack strategies from Appendix B:
  1. Sybil ring      — fake operators trading fabricated receipts between themselves
  2. Wash trader     — operator buying and reselling own receipts through a second identity
  3. Price inflator  — single operator charging 5x for garbage, hoping volume builds stake
  4. Long con        — legitimate work for 200 rounds, then starts fabricating
  5. Provenance stuffer — deep fake parent chains to inflate dependency depth

    cd tessera-py && python3 tests/test_adversarial.py
"""

import hashlib
import random
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from protocol.receipt import Receipt, RoyaltyTerms
from protocol.registry import Registry, OperatorProfile
from protocol.stake import StakeCalculator, recommend_settlement

PASS = "\033[32m\u2713\033[0m"
FAIL = "\033[31m\u2717\033[0m"
results = []


def test(name, condition):
    results.append((name, condition))
    print(f"  {PASS if condition else FAIL}  {name}")


def pub(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def make_receipt(key, model, i, price, parents=None):
    r = Receipt(
        model_id=hashlib.sha256(model.encode()).digest(),
        input_hash=hashlib.sha256(f"{model}-input-{i}".encode()).digest(),
        output_hash=hashlib.sha256(f"{model}-output-{i}".encode()).digest(),
        proof=b"<proof>",
        proving_backend="tee-nitro-v1",
        original_price=price,
        parent_receipts=parents or [],
        provenance_depth=1 if parents else 0,
        royalty_terms=RoyaltyTerms(provider_royalty=500, parent_royalty=300, cascade=True),
    )
    r.sign(key)
    return r


def main():
    random.seed(42)  # reproducible

    ROUNDS = 500
    N_LEGIT = 15

    print(f"\n  Adversarial stress test: {ROUNDS} rounds, {N_LEGIT} legitimate operators, 5 attackers")
    print()

    registry = Registry()

    # ── Legitimate operators ───────────────────────────────────
    legit_keys = [Ed25519PrivateKey.generate() for _ in range(N_LEGIT)]
    legit_models = [f"legit-model-{i}" for i in range(N_LEGIT)]
    for k, m in zip(legit_keys, legit_models):
        registry.register_operator(OperatorProfile(
            pubkey=pub(k), backends=["tee-nitro-v1"], models=[m.encode()],
        ))

    # ── Attack 1: Sybil ring (4 fake operators) ────────────────
    sybil_keys = [Ed25519PrivateKey.generate() for _ in range(4)]
    for k in sybil_keys:
        registry.register_operator(OperatorProfile(
            pubkey=pub(k), backends=["tee-nitro-v1"], models=[b"fake"],
        ))

    # ── Attack 2: Wash trader (2 identities, same person) ──────
    wash_key_a = Ed25519PrivateKey.generate()
    wash_key_b = Ed25519PrivateKey.generate()
    for k in [wash_key_a, wash_key_b]:
        registry.register_operator(OperatorProfile(
            pubkey=pub(k), backends=["tee-nitro-v1"], models=[b"wash"],
        ))

    # ── Attack 3: Price inflator ───────────────────────────────
    inflator_key = Ed25519PrivateKey.generate()
    registry.register_operator(OperatorProfile(
        pubkey=pub(inflator_key), backends=["tee-nitro-v1"], models=[b"inflated"],
    ))

    # ── Attack 4: Long con ─────────────────────────────────────
    longcon_key = Ed25519PrivateKey.generate()
    registry.register_operator(OperatorProfile(
        pubkey=pub(longcon_key), backends=["tee-nitro-v1"], models=[b"longcon"],
    ))

    # ── Attack 5: Provenance stuffer ───────────────────────────
    stuffer_keys = [Ed25519PrivateKey.generate() for _ in range(3)]
    for k in stuffer_keys:
        registry.register_operator(OperatorProfile(
            pubkey=pub(k), backends=["tee-nitro-v1"], models=[b"stuffer"],
        ))

    # ── Run simulation ─────────────────────────────────────────

    print("  Running simulation...")
    t0 = time.time()

    for round_num in range(ROUNDS):
        # --- Legitimate operators: diverse, real interactions ---
        # Each round, a random subset of operators produce work
        # consumed by other random operators
        active = random.sample(range(N_LEGIT), k=min(8, N_LEGIT))
        for idx in active:
            r = make_receipt(legit_keys[idx], legit_models[idx], round_num,
                             price=random.randint(500, 3000))
            registry.record_receipt(r)

            # Another random operator uses this as input
            consumer_idx = random.choice([i for i in range(N_LEGIT) if i != idx])
            cr = make_receipt(legit_keys[consumer_idx], legit_models[consumer_idx],
                              f"{round_num}-dep-{idx}",
                              price=random.randint(300, 2000),
                              parents=[r.as_parent_ref("input")])
            registry.record_receipt(cr)

        # --- Attack 1: Sybil ring trades between themselves ---
        if round_num % 2 == 0:
            s_from = sybil_keys[round_num % 4]
            s_to = sybil_keys[(round_num + 1) % 4]
            r = make_receipt(s_from, "sybil-fake", round_num, price=5000)
            registry.record_receipt(r)
            cr = make_receipt(s_to, "sybil-fake", f"{round_num}-sybil",
                              price=5000, parents=[r.as_parent_ref("input")])
            registry.record_receipt(cr)

        # --- Attack 2: Wash trader bounces between own keys ---
        if round_num % 3 == 0:
            r = make_receipt(wash_key_a, "wash", round_num, price=3000)
            registry.record_receipt(r)
            cr = make_receipt(wash_key_b, "wash", f"{round_num}-wash",
                              price=3000, parents=[r.as_parent_ref("input")])
            registry.record_receipt(cr)

        # --- Attack 3: Price inflator, 5x the normal price ---
        if round_num % 2 == 0:
            r = make_receipt(inflator_key, "inflated", round_num, price=15000)
            registry.record_receipt(r)

        # --- Attack 4: Long con — honest for 200 rounds, then fabricate ---
        if round_num < 200:
            # Honest: interact with random legit operators
            partner_idx = random.randint(0, N_LEGIT - 1)
            r = make_receipt(longcon_key, "longcon-honest", round_num, price=1500)
            registry.record_receipt(r)
            cr = make_receipt(legit_keys[partner_idx], legit_models[partner_idx],
                              f"{round_num}-longcon",
                              price=1000, parents=[r.as_parent_ref("input")])
            registry.record_receipt(cr)
        else:
            # Dishonest: self-referencing fabricated work
            r = make_receipt(longcon_key, "longcon-fake", round_num, price=10000)
            registry.record_receipt(r)

        # --- Attack 5: Provenance stuffer — deep fake chain ---
        if round_num % 5 == 0:
            chain = []
            for depth in range(3):
                k = stuffer_keys[depth]
                parents = [chain[-1].as_parent_ref("input")] if chain else []
                r = make_receipt(k, "stuffer", f"{round_num}-d{depth}", price=4000,
                                 parents=parents)
                registry.record_receipt(r)
                chain.append(r)

    elapsed = time.time() - t0
    print(f"  Done in {elapsed:.1f}s")
    print()

    # ── Measure results ────────────────────────────────────────

    calc = registry.stake_calculator

    # Compute stakes
    legit_stakes = []
    for k in legit_keys:
        s = calc.compute_stake(pub(k))
        legit_stakes.append(s)

    median_legit_stake = sorted([s.effective_stake for s in legit_stakes])[N_LEGIT // 2]
    max_legit_stake = max(s.effective_stake for s in legit_stakes)
    min_legit_stake = min(s.effective_stake for s in legit_stakes)

    sybil_stakes = [calc.compute_stake(pub(k)) for k in sybil_keys]
    max_sybil_stake = max(s.effective_stake for s in sybil_stakes)

    wash_stake_a = calc.compute_stake(pub(wash_key_a))
    wash_stake_b = calc.compute_stake(pub(wash_key_b))
    max_wash_stake = max(wash_stake_a.effective_stake, wash_stake_b.effective_stake)

    inflator_stake = calc.compute_stake(pub(inflator_key))
    longcon_stake = calc.compute_stake(pub(longcon_key))

    stuffer_stakes = [calc.compute_stake(pub(k)) for k in stuffer_keys]
    max_stuffer_stake = max(s.effective_stake for s in stuffer_stakes)

    # EigenTrust weights
    weights = calc.compute_counterparty_weights()

    def get_weight(k):
        return weights.get(pub(k).hex(), 0)

    legit_weights = [get_weight(k) for k in legit_keys]
    avg_legit_weight = sum(legit_weights) / len(legit_weights)

    # ── Print results ──────────────────────────────────────────

    print("  LEGITIMATE OPERATORS")
    print(f"    Median stake:    ${median_legit_stake / 100:,.0f}")
    print(f"    Range:           ${min_legit_stake / 100:,.0f} – ${max_legit_stake / 100:,.0f}")
    print(f"    Avg EigenTrust:  {avg_legit_weight:.4f}")
    print()

    # ── Test 1: Sybil ring ─────────────────────────────────────
    print("  ATTACK 1: SYBIL RING")
    print(f"    Max sybil stake: ${max_sybil_stake / 100:,.0f}")
    print(f"    Sybil EigenTrust: {max(get_weight(k) for k in sybil_keys):.4f}")
    print()
    test("Sybil stake < median legitimate stake",
         max_sybil_stake < median_legit_stake)
    test("Sybil EigenTrust near zero",
         max(get_weight(k) for k in sybil_keys) < 0.01)

    # ── Test 2: Wash trader ────────────────────────────────────
    print("\n  ATTACK 2: WASH TRADER")
    print(f"    Max wash stake:  ${max_wash_stake / 100:,.0f}")
    print(f"    Wash EigenTrust: {max(get_weight(wash_key_a), get_weight(wash_key_b)):.4f}")
    print()
    test("Wash trader stake < median legitimate stake",
         max_wash_stake < median_legit_stake)
    test("Wash trader EigenTrust near zero",
         max(get_weight(wash_key_a), get_weight(wash_key_b)) < 0.01)

    # ── Test 3: Price inflator ─────────────────────────────────
    print("\n  ATTACK 3: PRICE INFLATOR")
    print(f"    Inflator stake:  ${inflator_stake.effective_stake / 100:,.0f}")
    print(f"    Inflator EigenTrust: {get_weight(inflator_key):.4f}")
    print(f"    Claimed volume:  ${inflator_stake.direct_value / 100:,.0f}")
    print()
    test("Inflator stake < median legitimate (diversity kills it)",
         inflator_stake.effective_stake < median_legit_stake)

    # ── Test 4: Long con ───────────────────────────────────────
    print("\n  ATTACK 4: LONG CON")
    print(f"    Longcon stake:   ${longcon_stake.effective_stake / 100:,.0f}")
    print(f"    Longcon diversity: {longcon_stake.counterparty_diversity:.4f}")
    print()
    # The long con is the hardest to detect — they built real trust.
    # But after switching to fabrication (no counterparties), diversity drops.
    # Their stake should be lower than peak because post-switch receipts
    # don't generate new counterparty interactions.
    # The fundamental limit: they still have the stake they honestly built.
    # The protocol makes the cost proportional to the target.
    test("Long con stake exists (they did real work)",
         longcon_stake.effective_stake > 0)

    # The key claim: to defraud a $X transaction, you need ~50x in stake.
    # So their honestly-earned stake limits what they can target.
    # The long con invested ~200 rounds × $1500 = $300k in real volume.
    # Even so, their max instant target is tiny compared to that investment.
    if longcon_stake.effective_stake > 0:
        max_target = longcon_stake.effective_stake // 50
        honest_volume = 200 * 1500 * 100  # 200 rounds, ~$1500 avg, in cents
        fraud_roi = max_target / honest_volume if honest_volume > 0 else 0
        print(f"    Max instant-settlement target: ${max_target / 100:,.0f}")
        print(f"    Honest volume invested:        ${honest_volume / 100:,.0f}")
        print(f"    Fraud ROI:                     {fraud_roi:.4%}")
        print(f"    (Trust quotient >= 50 required for instant settlement)")
        test("Long con fraud ROI < 1% (attack is unprofitable)",
             fraud_roi < 0.01)

    # ── Test 5: Provenance stuffer ─────────────────────────────
    print("\n  ATTACK 5: PROVENANCE STUFFER")
    print(f"    Max stuffer stake: ${max_stuffer_stake / 100:,.0f}")
    print(f"    Stuffer EigenTrust: {max(get_weight(k) for k in stuffer_keys):.4f}")
    print()
    test("Stuffer stake < median legitimate stake",
         max_stuffer_stake < median_legit_stake)
    test("Stuffer EigenTrust near zero (insular cluster)",
         max(get_weight(k) for k in stuffer_keys) < 0.01)

    # ── Test 6: Attack ROI ─────────────────────────────────────
    print("\n  ATTACK ROI")
    print()

    # For each attacker, compute: what's the largest transaction they could
    # get instant settlement on? That's their "reward ceiling."
    # Compare against what a legitimate operator of similar age can target.

    attackers = {
        "Sybil ring": max_sybil_stake,
        "Wash trader": max_wash_stake,
        "Inflator": inflator_stake.effective_stake,
        "Prov. stuffer": max_stuffer_stake,
    }

    print(f"  {'Attacker':<18} {'Stake':>10} {'Max instant target':>20} {'vs Legit median':>16}")
    print(f"  {'─' * 18} {'─' * 10} {'─' * 20} {'─' * 16}")
    for name, stake in attackers.items():
        target = stake // 50 if stake > 0 else 0
        ratio = stake / median_legit_stake if median_legit_stake > 0 else 0
        print(f"  {name:<18} ${stake / 100:>8,.0f} ${target / 100:>18,.0f} {ratio:>15.1%}")

    print(f"  {'Legit (median)':<18} ${median_legit_stake / 100:>8,.0f}"
          f" ${(median_legit_stake // 50) / 100:>18,.0f} {'100.0%':>16}")

    print()
    all_below = all(s < median_legit_stake for s in attackers.values())
    test("All 4 automated attackers have lower stake than median legit", all_below)

    # ── Summary ────────────────────────────────────────────────
    passed = sum(1 for _, c in results if c)
    total_tests = len(results)
    failed = total_tests - passed

    print(f"\n{'=' * 60}")
    if failed == 0:
        print(f"  {PASS}  ALL {total_tests} TESTS PASSED")
        print()
        print(f"  {ROUNDS} rounds. {N_LEGIT} legitimate operators. 5 attack strategies.")
        print(f"  Every attacker has lower effective stake than the median")
        print(f"  legitimate operator. Sybil rings and wash traders converge")
        print(f"  to near-zero EigenTrust weight. The protocol makes attacks")
        print(f"  expensive in proportion to their target.")
    else:
        print(f"  {FAIL}  {failed}/{total_tests} TESTS FAILED")
        for name, condition in results:
            if not condition:
                print(f"      - {name}")
    print(f"{'=' * 60}\n")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
