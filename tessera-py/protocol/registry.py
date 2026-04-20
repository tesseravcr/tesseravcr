# registry — publish and discover operators and VCRs
#
# operators register what they can compute and their terms.
# buyers query by capability, price, trust quotient, or metadata.
# the protocol handles the rest.
#
# in-memory for the poc. production would be distributed across transparency logs.

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .receipt import Receipt, RoyaltyTerms
from .stake import OperatorRegistry, StakeCalculator, trust_quotient


@dataclass
class OperatorProfile:
    pubkey: bytes                           # bytes32 — Ed25519 public key
    backends: list[str] = field(default_factory=list)       # proving backends offered
    models: list[bytes] = field(default_factory=list)       # model_ids offered
    max_price: int = 0                      # highest price willing to compute for
    currency: str = "USD-cents"
    metadata: dict[str, str] = field(default_factory=dict)  # free-form tags
    registered_at: int = field(default_factory=lambda: int(time.time()))


@dataclass
class Listing:
    receipt: Receipt
    seller: bytes               # bytes32 — current owner's public key
    asking_price: int
    currency: str = "USD-cents"
    description: str = ""
    tags: list[str] = field(default_factory=list)
    listed_at: int = field(default_factory=lambda: int(time.time()))

    @property
    def receipt_id_hex(self) -> str:
        return self.receipt.receipt_id.hex()


@dataclass
class QueryResult:
    listing: Listing
    trust_q: float              # trust quotient of the receipt's provider


@dataclass
class Registry:
    operators: dict[str, OperatorProfile] = field(default_factory=dict)
    listings: dict[str, Listing] = field(default_factory=dict)  # receipt_id_hex -> Listing
    stake_calculator: StakeCalculator = field(
        default_factory=lambda: StakeCalculator(registry=OperatorRegistry())
    )

    def register_operator(self, profile: OperatorProfile) -> None:
        key = profile.pubkey.hex()
        self.operators[key] = profile
        self.stake_calculator.registry.register_operator(profile.pubkey)

    def get_operator(self, pubkey: bytes) -> OperatorProfile | None:
        return self.operators.get(pubkey.hex())

    def list_vcr(self, listing: Listing) -> None:
        rid = listing.receipt_id_hex
        if rid in self.listings:
            raise ValueError(f"Receipt {rid[:16]}... already listed")
        self.listings[rid] = listing

    def delist(self, receipt_id: bytes) -> None:
        rid = receipt_id.hex()
        if rid not in self.listings:
            raise ValueError(f"Receipt {rid[:16]}... not listed")
        del self.listings[rid]

    def record_receipt(self, receipt: Receipt) -> None:
        receipt.validate()
        self.stake_calculator.registry.record_receipt(receipt)

    def query(
        self,
        model_id: bytes | None = None,
        backend: str | None = None,
        max_price: int | None = None,
        currency: str | None = None,
        min_trust_quotient: float | None = None,
        transaction_value: int | None = None,
        tags: list[str] | None = None,
        sort_by: str = "price",           # "price", "trust", "recent"
        limit: int = 50,
    ) -> list[QueryResult]:
        results = []

        for listing in self.listings.values():
            r = listing.receipt

            if model_id is not None and r.model_id != model_id:
                continue
            if backend is not None and r.proving_backend != backend:
                continue
            if max_price is not None and listing.asking_price > max_price:
                continue
            if currency is not None and listing.currency != currency:
                continue
            if tags:
                if not any(t in listing.tags for t in tags):
                    continue

            # compute trust quotient for the provider
            stake = self.stake_calculator.compute_stake(r.provider)
            tv = transaction_value if transaction_value is not None else listing.asking_price
            tq = trust_quotient(stake.effective_stake, tv)

            if min_trust_quotient is not None and tq < min_trust_quotient:
                continue

            results.append(QueryResult(listing=listing, trust_q=tq))

        if sort_by == "price":
            results.sort(key=lambda r: r.listing.asking_price)
        elif sort_by == "trust":
            results.sort(key=lambda r: -r.trust_q)
        elif sort_by == "recent":
            results.sort(key=lambda r: -r.listing.listed_at)

        return results[:limit]

    def find_operators(
        self,
        model_id: bytes | None = None,
        backend: str | None = None,
        max_price: int | None = None,
        min_trust_quotient: float | None = None,
        transaction_value: int = 0,
    ) -> list[tuple[OperatorProfile, float]]:
        results = []

        for profile in self.operators.values():
            if model_id is not None and model_id not in profile.models:
                continue
            if backend is not None and backend not in profile.backends:
                continue
            if max_price is not None and profile.max_price > 0 and profile.max_price > max_price:
                continue

            stake = self.stake_calculator.compute_stake(profile.pubkey)
            tv = transaction_value if transaction_value > 0 else 1
            tq = trust_quotient(stake.effective_stake, tv)

            if min_trust_quotient is not None and tq < min_trust_quotient:
                continue

            results.append((profile, tq))

        results.sort(key=lambda r: -r[1])
        return results
