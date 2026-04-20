# stake — self-collateralising trust from VCR history
#
# Two layers, strictly separated:
#
# PROTOCOL DATA (this file owns):
#   - OperatorRegistry: records receipts, dependents, interactions, vouches
#   - Raw stake components: direct value, royalty NPV, dependency depth
#   - Trust quotient: effective_stake / transaction_value
#   - Settlement terms: the protocol's output to participants
#
# REPUTATION POLICY (reference implementation, pluggable):
#   - Counterparty diversity scoring (first-order EigenTrust)
#   - Eigenvector reputation weights (full EigenTrust / PageRank)
#   - Sybil resistance parameters (min_counterparties, floors)
#
# The protocol produces the interaction graph. The reputation layer
# consumes it. Different deployments can use different algorithms —
# EigenTrust (Kamvar et al. 2003), PageRank (Brin & Page 1998),
# or manual curation. The protocol doesn't mandate which.
#
# Fundamental limit (Douceur 2002): sybil attacks cannot be fully
# prevented in a decentralised system without a trust anchor. This
# protocol's trust anchor is economic: settled transactions through
# escrow cost real money. The reputation layer makes attacks
# expensive, not impossible. Same model as Bitcoin and Ethereum.

from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass, field

from .receipt import Receipt


def _encode_field(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


# ── Protocol parameters ──────────────────────────────────────

@dataclass
class StakeParams:
    # Protocol: raw stake computation
    discount_rate: float = 0.10     # annual, for royalty NPV
    royalty_horizon: int = 10       # future periods to estimate
    direct_weight: float = 1.0      # weight for direct value component
    royalty_weight: float = 0.5     # weight for royalty stream component
    depth_weight: float = 0.3       # weight for dependency depth component
    depth_unit_value: int = 100     # currency units per downstream dependent
    settled_multiplier: float = 3.0 # settled receipts count 3x vs unsold claims

    # Reputation policy: sybil resistance (reference defaults, all tunable)
    min_counterparties: int = 5     # minimum unique counterparties for full diversity
    counterparty_floor: float = 0.1 # minimum diversity multiplier

    def canonical_bytes(self) -> bytes:
        return (
            _encode_field(struct.pack(">d", self.discount_rate))
            + _encode_field(struct.pack(">I", self.royalty_horizon))
            + _encode_field(struct.pack(">d", self.direct_weight))
            + _encode_field(struct.pack(">d", self.royalty_weight))
            + _encode_field(struct.pack(">d", self.depth_weight))
            + _encode_field(struct.pack(">I", self.depth_unit_value))
            + _encode_field(struct.pack(">d", self.settled_multiplier))
        )


# ── Protocol data structures ─────────────────────────────────

@dataclass
class OperatorStake:
    """Computed stake for an operator at a point in time.

    Raw components (direct_value, royalty_npv, dependency_depth) are
    protocol-level facts derived from receipt data. counterparty_diversity
    is a reputation-layer score that modulates effective_stake.
    """
    operator: bytes             # bytes32 — Ed25519 public key
    receipt_count: int = 0
    direct_value: int = 0       # sum of original_price across all receipts
    royalty_npv: int = 0        # present value of future royalty streams
    dependency_depth: int = 0   # downstream VCRs referencing this operator's work
    counterparty_diversity: float = 1.0  # [0,1] — from reputation layer
    effective_stake: int = 0    # weighted combination — the number that matters
    computed_at: int = field(default_factory=lambda: int(time.time()))

    def canonical_bytes(self) -> bytes:
        return (
            _encode_field(self.operator)
            + _encode_field(struct.pack(">Q", self.receipt_count))
            + _encode_field(struct.pack(">Q", self.direct_value))
            + _encode_field(struct.pack(">Q", self.royalty_npv))
            + _encode_field(struct.pack(">Q", self.dependency_depth))
            + _encode_field(struct.pack(">Q", self.effective_stake))
            + _encode_field(struct.pack(">Q", self.computed_at))
        )

    @property
    def stake_hash(self) -> bytes:
        return hashlib.sha256(self.canonical_bytes()).digest()


@dataclass
class Vouch:
    """An established operator vouches for a new one.

    A public record that stakes the voucher's reputation on the newcomer.
    Enforcement is market-emergent: if the newcomer cheats, the market
    sees who endorsed them. No explicit slashing needed.
    """
    voucher: bytes          # established operator's pubkey
    newcomer: bytes         # new operator's pubkey
    stake_fraction: float   # fraction of voucher's stake contributed (0.0-1.0)
    timestamp: int = field(default_factory=lambda: int(time.time()))


# ── Registry: protocol-level fact recording ───────────────────

@dataclass
class OperatorRegistry:
    """Records receipts, provenance, interactions, and vouches.

    This is the protocol's data layer. It records facts about what
    happened on the network. The interaction graph it produces is the
    input to any reputation algorithm (EigenTrust, PageRank, etc).
    """
    receipts_by_operator: dict[str, list[str]] = field(default_factory=dict)
    receipt_store: dict[str, Receipt] = field(default_factory=dict)
    dependents: dict[str, set[str]] = field(default_factory=dict)
    vouches: dict[str, list[Vouch]] = field(default_factory=dict)
    interactions: dict[str, dict[str, int]] = field(default_factory=dict)

    def _record_interaction(self, op_a: str, op_b: str) -> None:
        """Record a bilateral interaction between two operators.

        Provenance references and transfers both create interactions.
        Self-interactions (same key on both sides) are ignored.
        """
        if op_a == op_b:
            return
        for a, b in [(op_a, op_b), (op_b, op_a)]:
            if a not in self.interactions:
                self.interactions[a] = {}
            self.interactions[a][b] = self.interactions[a].get(b, 0) + 1

    def register_operator(self, pubkey: bytes) -> None:
        key = pubkey.hex()
        if key not in self.receipts_by_operator:
            self.receipts_by_operator[key] = []

    def record_receipt(self, receipt: Receipt) -> None:
        rid = receipt.receipt_id.hex()
        if rid in self.receipt_store:
            raise ValueError(f"Receipt {rid[:16]}... already recorded")

        self.receipt_store[rid] = receipt

        operator_key = receipt.provider.hex()
        if operator_key not in self.receipts_by_operator:
            self.receipts_by_operator[operator_key] = []
        self.receipts_by_operator[operator_key].append(rid)

        for parent_ref in receipt.parent_receipts:
            pid = parent_ref.receipt_id.hex()
            if pid not in self.dependents:
                self.dependents[pid] = set()
            self.dependents[pid].add(rid)

            # track counterparty interaction from provenance
            parent_receipt = self.receipt_store.get(pid)
            if parent_receipt:
                self._record_interaction(operator_key, parent_receipt.provider.hex())

    def record_transfer_interaction(self, from_key: bytes, to_key: bytes) -> None:
        """Record an interaction from a transfer between operators."""
        self._record_interaction(from_key.hex(), to_key.hex())

    def get_counterparties(self, pubkey: bytes) -> dict[str, int]:
        """Return {counterparty_hex: interaction_count} for an operator."""
        return dict(self.interactions.get(pubkey.hex(), {}))

    def get_receipts(self, pubkey: bytes) -> list[Receipt]:
        rids = self.receipts_by_operator.get(pubkey.hex(), [])
        return [self.receipt_store[rid] for rid in rids if rid in self.receipt_store]

    def operator_dependent_count(self, pubkey: bytes) -> int:
        total = 0
        for rid in self.receipts_by_operator.get(pubkey.hex(), []):
            total += len(self.dependents.get(rid, set()))
        return total

    def vouch_for(self, voucher: bytes, newcomer: bytes, stake_fraction: float = 0.1) -> Vouch:
        if stake_fraction <= 0 or stake_fraction > 1.0:
            raise ValueError("stake_fraction must be between 0 and 1")
        vkey = voucher.hex()
        nkey = newcomer.hex()
        if vkey not in self.receipts_by_operator:
            raise ValueError("Voucher has no receipt history")
        if nkey not in self.receipts_by_operator:
            self.receipts_by_operator[nkey] = []
        v = Vouch(voucher=voucher, newcomer=newcomer, stake_fraction=stake_fraction)
        if nkey not in self.vouches:
            self.vouches[nkey] = []
        self.vouches[nkey].append(v)
        return v

    def get_vouches(self, pubkey: bytes) -> list[Vouch]:
        return self.vouches.get(pubkey.hex(), [])


# ── Stake computation ─────────────────────────────────────────

@dataclass
class StakeCalculator:
    """Computes effective stake from registry data.

    Raw stake components (direct value, royalty NPV, dependency depth)
    are protocol-level facts. The counterparty diversity score is a
    reference implementation of EigenTrust-family reputation scoring
    that modulates the raw stake. Deployments may substitute any
    reputation algorithm that consumes the interaction graph.
    """
    registry: OperatorRegistry
    params: StakeParams = field(default_factory=StakeParams)

    # ── Protocol: raw stake from receipt data ──

    def compute_direct_value(self, pubkey: bytes, diversity: float | None = None) -> int:
        """Sum of original_price across all receipts.

        Settled receipts (transferred at least once) get a multiplier
        because the market validated the price. The multiplier is scaled
        by counterparty diversity so self-dealing settlements don't count.
        """
        total = 0
        base_m = self.params.settled_multiplier
        if diversity is not None:
            m = 1.0 + (base_m - 1.0) * diversity
        else:
            m = base_m
        for r in self.registry.get_receipts(pubkey):
            if r.transfer_count > 0:
                total += int(r.original_price * m)
            else:
                total += r.original_price
        return total

    def compute_royalty_npv(self, pubkey: bytes) -> int:
        """NPV of future royalty income using closed-form geometric series."""
        total = 0.0
        r = self.params.discount_rate
        n = self.params.royalty_horizon

        if r > 0:
            annuity_factor = (1 - (1 + r) ** (-n)) / r
        else:
            annuity_factor = float(n)

        for receipt in self.registry.get_receipts(pubkey):
            if receipt.transfer_count == 0:
                continue
            base = (
                receipt.original_price
                * (receipt.royalty_terms.provider_royalty / 10000.0)
                * receipt.transfer_count
            )
            total += base * annuity_factor

        return int(total)

    def compute_dependency_depth(self, pubkey: bytes) -> int:
        return self.registry.operator_dependent_count(pubkey)

    def compute_vouched_stake(self, pubkey: bytes) -> int:
        """Stake contributed by vouchers. Uses own-stake only to prevent cycles."""
        total = 0
        for vouch in self.registry.get_vouches(pubkey):
            voucher_stake = self._compute_own_stake(vouch.voucher)
            total += int(voucher_stake * vouch.stake_fraction)
        return total

    # ── Reputation: reference sybil resistance (EigenTrust-family) ──

    def compute_counterparty_diversity(self, pubkey: bytes) -> float:
        """First-order counterparty diversity score.

        Reference implementation of EigenTrust-family local trust scoring.
        Measures two properties of an operator's counterparty set:

        1. Independence — what fraction of each counterparty's total
           interactions are with operators OTHER than this one.
        2. Count — operators with fewer than min_counterparties unique
           counterparties are penalised proportionally.

        Returns [0, 1]. Can be replaced by any algorithm that consumes
        the interaction graph from OperatorRegistry.
        """
        op_hex = pubkey.hex()
        counterparties = self.registry.interactions.get(op_hex, {})

        if not counterparties:
            return 0.0

        independence_sum = 0.0
        for cp_hex, interaction_count in counterparties.items():
            cp_interactions = self.registry.interactions.get(cp_hex, {})
            cp_total = sum(cp_interactions.values())
            if cp_total == 0:
                continue
            independence_sum += 1.0 - (interaction_count / cp_total)

        mean_independence = independence_sum / len(counterparties)
        diversity_penalty = min(1.0, len(counterparties) / self.params.min_counterparties)

        return mean_independence * diversity_penalty

    def compute_counterparty_weights(
        self, max_iterations: int = 20, tolerance: float = 1e-6,
    ) -> dict[str, float]:
        """Full eigenvector reputation — PageRank over the interaction graph.

        Reference implementation of EigenTrust (Kamvar et al. 2003) /
        PageRank (Brin & Page 1998) applied to the VCR interaction graph.
        Iteratively computes the principal eigenvector. Isolated sybil
        clusters converge to zero. Well-connected legitimate operators
        converge to positive values.

        Returns {operator_hex: weight} in [0, 1].
        """
        operators = list(self.registry.receipts_by_operator.keys())
        if not operators:
            return {}

        scores = {op: 1.0 for op in operators}

        for _ in range(max_iterations):
            new_scores = {}
            for op_hex in operators:
                counterparties = self.registry.interactions.get(op_hex, {})
                if not counterparties:
                    new_scores[op_hex] = 0.0
                    continue

                weighted_sum = 0.0
                for cp_hex, count in counterparties.items():
                    cp_interactions = self.registry.interactions.get(cp_hex, {})
                    cp_total = sum(cp_interactions.values())
                    if cp_total == 0:
                        continue
                    independence = 1.0 - (count / cp_total)
                    weighted_sum += scores.get(cp_hex, 0.0) * independence

                new_scores[op_hex] = weighted_sum / len(counterparties)

            max_score = max(new_scores.values()) if new_scores else 0
            if max_score > 0:
                new_scores = {op: s / max_score for op, s in new_scores.items()}

            delta = sum(abs(new_scores.get(op, 0) - scores.get(op, 0)) for op in operators)
            scores = new_scores
            if delta < tolerance:
                break

        return scores

    # ── Combined stake computation ──

    def _compute_own_stake(self, pubkey: bytes) -> int:
        """Operator's own stake excluding vouches. Prevents cycles."""
        diversity = self.compute_counterparty_diversity(pubkey)
        direct = self.compute_direct_value(pubkey, diversity=diversity)
        royalty = self.compute_royalty_npv(pubkey)
        depth = self.compute_dependency_depth(pubkey)
        p = self.params

        raw = int(
            p.direct_weight * direct
            + p.royalty_weight * royalty
            + p.depth_weight * depth * p.depth_unit_value
        )
        return int(raw * max(diversity, p.counterparty_floor))

    def compute_stake(self, pubkey: bytes) -> OperatorStake:
        diversity = self.compute_counterparty_diversity(pubkey)
        direct = self.compute_direct_value(pubkey, diversity=diversity)
        royalty = self.compute_royalty_npv(pubkey)
        depth = self.compute_dependency_depth(pubkey)
        vouched = self.compute_vouched_stake(pubkey)
        p = self.params

        raw = int(
            p.direct_weight * direct
            + p.royalty_weight * royalty
            + p.depth_weight * depth * p.depth_unit_value
        )
        effective = int(raw * max(diversity, p.counterparty_floor)) + vouched

        return OperatorStake(
            operator=pubkey,
            receipt_count=len(self.registry.get_receipts(pubkey)),
            direct_value=direct,
            royalty_npv=royalty,
            dependency_depth=depth,
            counterparty_diversity=diversity,
            effective_stake=effective,
        )


# ── Trust quotient and settlement ─────────────────────────────

def trust_quotient(effective_stake: int, transaction_value: int) -> float:
    if transaction_value <= 0:
        return float("inf")
    return effective_stake / transaction_value


@dataclass
class SettlementTerms:
    quotient: float
    recommendation: str         # "instant", "escrow", or "collateral_required"
    max_instant_value: int      # largest transaction qualifying for instant settlement


def recommend_settlement(
    effective_stake: int,
    transaction_value: int,
    instant_threshold: float = 50.0,
    escrow_threshold: float = 5.0,
) -> SettlementTerms:
    q = trust_quotient(effective_stake, transaction_value)

    if escrow_threshold > 0:
        max_instant = int(effective_stake / instant_threshold) if instant_threshold > 0 else 0
    else:
        max_instant = 0

    if q >= instant_threshold:
        return SettlementTerms(
            quotient=q,
            recommendation="instant",
            max_instant_value=max_instant,
        )
    elif q >= escrow_threshold:
        return SettlementTerms(
            quotient=q,
            recommendation="escrow",
            max_instant_value=max_instant,
        )
    else:
        return SettlementTerms(
            quotient=q,
            recommendation="collateral_required",
            max_instant_value=max_instant,
        )
