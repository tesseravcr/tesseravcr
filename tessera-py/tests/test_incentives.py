#!/usr/bin/env python3
"""
Incentive dominance verification — proves the whitepaper's Appendix A.

The whitepaper claims honest provenance attribution dominates dishonest
omission under the stated economic model. This script:

  1. Verifies the worked example (S=100, r_p=5%, r_a=3%, k=3, d=1.2, p=0.4, L=5000)
  2. Sweeps the full parameter space to find the exact boundary
  3. Identifies the minimum detection probability where honesty dominates
  4. Shows that for realistic agent parameters, honesty always wins

This is the economic equivalent of Satoshi's attacker probability table.

    cd tessera-py && python3 tests/test_incentives.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

PASS = "\033[32m\u2713\033[0m"
FAIL = "\033[31m\u2717\033[0m"
results = []


def test(name, condition):
    results.append((name, condition))
    print(f"  {PASS if condition else FAIL}  {name}")


# ── The model from Appendix A ────────────────────────────────

def e_honest(S, r_p, r_a, k, d):
    """Expected value of honest attribution."""
    return d * S * (1 + k * r_p - r_a)


def e_dishonest(S, r_p, k, p, L):
    """Expected value of dishonest omission."""
    return S * (1 + k * r_p) - p * L


def honesty_dominates(S, r_p, r_a, k, d, p, L):
    return e_honest(S, r_p, r_a, k, d) > e_dishonest(S, r_p, k, p, L)


def min_detection_probability(S, r_p, r_a, k, d, L):
    """Solve for p where E[honest] = E[dishonest].

    d*S*(1 + k*r_p - r_a) = S*(1 + k*r_p) - p*L
    p*L = S*(1 + k*r_p) - d*S*(1 + k*r_p - r_a)
    p = [S*(1 + k*r_p) - d*S*(1 + k*r_p - r_a)] / L
    """
    if L == 0:
        return float("inf")
    numerator = S * (1 + k * r_p) - d * S * (1 + k * r_p - r_a)
    return numerator / L


def main():
    # ── 1. Verify the whitepaper's worked example ──────────────
    print("\n1. WHITEPAPER WORKED EXAMPLE (Appendix A)")
    print()

    S, r_p, r_a, k, d, p, L = 100, 0.05, 0.03, 3, 1.2, 0.4, 5000

    honest = e_honest(S, r_p, r_a, k, d)
    dishonest = e_dishonest(S, r_p, k, p, L)

    print(f"  Parameters: S=${S}, r_p={r_p:.0%}, r_a={r_a:.0%}, k={k}, d={d}, p={p}, L=${L}")
    print(f"  E[honest]    = ${honest:.2f}")
    print(f"  E[dishonest] = ${dishonest:.2f}")
    print(f"  Advantage:     ${honest - dishonest:.2f}")
    print()

    test("E[honest] = $134.40 (matches whitepaper)", abs(honest - 134.40) < 0.01)
    test("E[dishonest] = -$1885.00 (matches whitepaper)", abs(dishonest - (-1885.0)) < 0.01)
    test("Honest dominates by $2019.40", abs((honest - dishonest) - 2019.40) < 0.01)

    # ── 2. Detection probability sweep ─────────────────────────
    print("\n2. DETECTION PROBABILITY SWEEP")
    print()
    print(f"  How low can detection probability go before dishonesty pays?")
    print()

    p_min = min_detection_probability(S, r_p, r_a, k, d, L)

    if p_min <= 0:
        print(f"  Minimum p: {p_min:.6f} (NEGATIVE — honesty dominates unconditionally)")
        print(f"  The provenance premium (d={d}) alone makes honest attribution")
        print(f"  more profitable than omission, even with zero detection risk.")
        print()
        test("Honesty dominates even at p=0 (provenance premium sufficient)",
             honesty_dominates(S, r_p, r_a, k, d, 0, L))
    else:
        print(f"  Minimum p for honesty to dominate: {p_min:.6f} ({p_min:.4%})")
        print()
        test(f"Honesty dominates at p={p_min + 0.001:.4f}",
             honesty_dominates(S, r_p, r_a, k, d, p_min + 0.001, L))
        test(f"Dishonesty wins at p={max(0, p_min - 0.001):.4f}",
             not honesty_dominates(S, r_p, r_a, k, d, max(0, p_min - 0.001), L))

    print()
    print(f"  Detection probability table (S=${S}, L=${L}):")
    print(f"  {'p':>8} {'E[honest]':>12} {'E[dishonest]':>14} {'Dominates':>10}")
    print(f"  {'─' * 8} {'─' * 12} {'─' * 14} {'─' * 10}")
    for p_val in [0.001, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.4, 0.8, 1.0]:
        eh = e_honest(S, r_p, r_a, k, d)
        ed = e_dishonest(S, r_p, k, p_val, L)
        dom = "honest" if eh > ed else "DISHONEST"
        print(f"  {p_val:>8.3f} {eh:>12.2f} {ed:>14.2f} {dom:>10}")

    # ── 3. Loss amount sweep ───────────────────────────────────
    print("\n3. LOSS AMOUNT SWEEP")
    print()
    print(f"  How much accumulated stake does an operator need for honesty to dominate?")
    print()

    # At various detection probabilities, what's the minimum L?
    print(f"  {'p':>8} {'Min L ($)':>12} {'Meaning':>50}")
    print(f"  {'─' * 8} {'─' * 12} {'─' * 50}")
    for p_val in [0.01, 0.05, 0.1, 0.2, 0.5, 1.0]:
        # Solve: E[honest] = E[dishonest] for L
        # d*S*(1+k*r_p-r_a) = S*(1+k*r_p) - p*L
        # p*L = S*(1+k*r_p) - d*S*(1+k*r_p-r_a)
        # L = [S*(1+k*r_p) - d*S*(1+k*r_p-r_a)] / p
        numerator = S * (1 + k * r_p) - d * S * (1 + k * r_p - r_a)
        L_min = numerator / p_val if p_val > 0 else float("inf")
        if L_min <= 0:
            meaning = "honesty dominates regardless of stake"
        else:
            meaning = f"need ${L_min:.0f} in stake ({L_min / S:.0f}x the transaction)"
        print(f"  {p_val:>8.2f} {L_min:>12.2f} {meaning:>50}")

    # ── 4. Full parameter space sweep ──────────────────────────
    print("\n4. PARAMETER SPACE SWEEP")
    print()

    # Sweep all reasonable parameter combinations
    total = 0
    honest_wins = 0
    dishonest_wins = 0
    boundary_cases = []

    for S_val in [10, 50, 100, 500, 1000]:
        for r_p_val in [0.01, 0.03, 0.05, 0.10, 0.15]:
            for r_a_val in [0.01, 0.03, 0.05, 0.10]:
                for k_val in [0, 1, 3, 5, 10]:
                    for d_val in [1.0, 1.05, 1.1, 1.2, 1.5]:
                        for p_val in [0.01, 0.05, 0.1, 0.2, 0.5, 1.0]:
                            for L_val in [100, 500, 1000, 5000, 10000, 50000]:
                                total += 1
                                if honesty_dominates(S_val, r_p_val, r_a_val, k_val, d_val, p_val, L_val):
                                    honest_wins += 1
                                else:
                                    dishonest_wins += 1
                                    # Track the most realistic dishonesty-wins cases
                                    if p_val >= 0.1 and L_val >= 1000 and d_val >= 1.1:
                                        boundary_cases.append({
                                            "S": S_val, "r_p": r_p_val, "r_a": r_a_val,
                                            "k": k_val, "d": d_val, "p": p_val, "L": L_val,
                                        })

    pct = honest_wins / total * 100
    print(f"  Swept {total:,} parameter combinations.")
    print(f"    Honest dominates: {honest_wins:,} ({pct:.1f}%)")
    print(f"    Dishonest wins:   {dishonest_wins:,} ({100 - pct:.1f}%)")
    print()

    test("Honest dominates in >80% of parameter space", pct > 80)

    # ── 5. Realistic agent conditions ──────────────────────────
    print("\n5. REALISTIC AGENT CONDITIONS")
    print()
    print(f"  For agents (not humans), detection probability is high because")
    print(f"  buyer agents cross-reference hashes against all known VCRs.")
    print(f"  Testing with p >= 0.5 and L >= 10x transaction value:")
    print()

    realistic_total = 0
    realistic_honest = 0

    for S_val in [10, 50, 100, 500, 1000]:
        for r_p_val in [0.03, 0.05, 0.10]:
            for r_a_val in [0.03, 0.05]:
                for k_val in [1, 3, 5]:
                    for d_val in [1.05, 1.1, 1.2]:
                        for p_val in [0.5, 0.7, 0.9, 1.0]:
                            for L_mult in [10, 50, 100]:
                                L_val = S_val * L_mult
                                realistic_total += 1
                                if honesty_dominates(S_val, r_p_val, r_a_val, k_val, d_val, p_val, L_val):
                                    realistic_honest += 1

    rpct = realistic_honest / realistic_total * 100
    print(f"  Swept {realistic_total:,} realistic combinations.")
    print(f"    Honest dominates: {realistic_honest:,} ({rpct:.1f}%)")
    print()

    test("Honest dominates in 100% of realistic agent conditions", rpct == 100)

    # ── 6. Boundary: when does dishonesty become rational? ─────
    print("\n6. DISHONESTY BOUNDARY")
    print()
    print(f"  Dishonesty only wins when:")
    if p_min <= 0:
        print(f"    - Provenance premium (d) is near 1.0 (no market value for verified chains)")
        print(f"      (for the base case with d={d}, honesty wins even at p=0)")
    else:
        print(f"    - Detection probability is very low (p < {p_min:.4f} for base case)")
    print(f"    - AND accumulated stake (L) is very small relative to transaction")
    print(f"    - AND provenance premium (d) is near 1.0")
    print()
    print(f"  The protocol's defence:")
    print(f"    - Agents cross-reference hashes instantly → p approaches 1")
    print(f"    - Self-collateralising trust means L grows with honest participation")
    print(f"    - Provenance is the differentiator in agent markets → d > 1")
    print()

    # The key insight: even with very low detection (p=0.01), if L >= 20x S,
    # honesty still dominates for any d >= 1.1
    all_pass = True
    for d_val in [1.1, 1.2, 1.5]:
        dom = honesty_dominates(100, 0.05, 0.03, 3, d_val, 0.01, 2000)
        if not dom:
            all_pass = False
    test("At p=0.01, L=20x, d>=1.1: honesty still dominates", all_pass)

    # ── Summary ────────────────────────────────────────────────
    passed = sum(1 for _, c in results if c)
    total_tests = len(results)
    failed = total_tests - passed

    print(f"\n{'=' * 60}")
    if failed == 0:
        print(f"  {PASS}  ALL {total_tests} TESTS PASSED")
        print()
        print(f"  The whitepaper's incentive model is verified.")
        print(f"  Honest provenance attribution is the dominant strategy")
        print(f"  for all realistic agent operating conditions.")
    else:
        print(f"  {FAIL}  {failed}/{total_tests} TESTS FAILED")
        for name, condition in results:
            if not condition:
                print(f"      - {name}")
    print(f"{'=' * 60}\n")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
