# settlement — escrow and royalty cascade
#
# two modes:
#   1. direct: agent pays provider for new computation
#   2. resale: agent buys existing VCR, royalties cascade per terms
#
# all amounts are integers (base currency units, e.g. cents).
# integer division throughout — rounding remainders fall to the seller.
# no floating point in the money path.

from __future__ import annotations

from dataclasses import dataclass, field

from .receipt import Receipt
from .transfer import RoyaltyPayment


@dataclass
class Ledger:
    balances: dict[str, int] = field(default_factory=dict)
    escrows: dict[str, "Escrow"] = field(default_factory=dict)

    def credit(self, agent_id: str, amount: int) -> None:
        self.balances[agent_id] = self.balances.get(agent_id, 0) + amount

    def debit(self, agent_id: str, amount: int) -> None:
        bal = self.balances.get(agent_id, 0)
        if bal < amount:
            raise ValueError(f"{agent_id} has {bal}, needs {amount}")
        self.balances[agent_id] = bal - amount

    def balance(self, agent_id: str) -> int:
        return self.balances.get(agent_id, 0)

    def create_escrow(self, escrow_id: str, payer: str, amount: int) -> "Escrow":
        self.debit(payer, amount)
        esc = Escrow(escrow_id=escrow_id, payer=payer, amount=amount)
        self.escrows[escrow_id] = esc
        return esc

    def release_escrow_direct(self, escrow_id: str, receipt: Receipt) -> dict[str, int]:
        esc = self.escrows.pop(escrow_id)
        if esc.released:
            raise ValueError(f"Escrow {escrow_id} already released")
        esc.released = True
        provider_id = receipt.provider.hex()
        self.credit(provider_id, esc.amount)
        return {provider_id: esc.amount}

    def release_escrow_resale(
        self,
        escrow_id: str,
        receipt: Receipt,
        seller_pubkey: bytes,
        sale_price: int,
        receipt_store: dict[str, Receipt] | None = None,
    ) -> tuple[dict[str, int], list[RoyaltyPayment]]:
        esc = self.escrows.pop(escrow_id)
        if esc.released:
            raise ValueError(f"Escrow {escrow_id} already released")
        esc.released = True
        return settle_resale(self, receipt, seller_pubkey, sale_price, receipt_store)

    def refund_escrow(self, escrow_id: str) -> None:
        esc = self.escrows.pop(escrow_id)
        if not esc.released:
            self.credit(esc.payer, esc.amount)
            esc.released = True


@dataclass
class Escrow:
    escrow_id: str
    payer: str
    amount: int
    released: bool = False


def settle_resale(
    ledger: Ledger,
    receipt: Receipt,
    seller_pubkey: bytes,
    sale_price: int,
    receipt_store: dict[str, Receipt] | None = None,
) -> tuple[dict[str, int], list[RoyaltyPayment]]:
    payments: dict[str, int] = {}
    royalty_records: list[RoyaltyPayment] = []
    total_distributed = 0

    def _add_payment(key: str, amount: int):
        nonlocal total_distributed
        payments[key] = payments.get(key, 0) + amount
        total_distributed += amount

    def _distribute(rcpt: Receipt, amount: int):
        terms = rcpt.royalty_terms

        # provider gets their cut (integer division)
        provider_cut = amount * terms.provider_royalty // 10000
        if provider_cut > 0:
            provider_id = rcpt.provider.hex()
            ledger.credit(provider_id, provider_cut)
            _add_payment(provider_id, provider_cut)
            royalty_records.append(RoyaltyPayment(
                recipient=rcpt.provider,
                amount=provider_cut,
                receipt_id=rcpt.receipt_id,
            ))

        # parent royalty — only computed if parents exist.
        # if no parents, nothing is deducted. the share falls to the seller
        # via the remainder in sale_price - total_distributed.
        if rcpt.parent_receipts:
            parent_cut_total = amount * terms.parent_royalty // 10000
            if parent_cut_total > 0:
                per_parent = parent_cut_total // len(rcpt.parent_receipts)
                # integer division remainder falls to seller via total_distributed
                if per_parent > 0:
                    for parent_ref in rcpt.parent_receipts:
                        parent_receipt = (receipt_store or {}).get(parent_ref.receipt_id.hex())
                        if parent_receipt and terms.cascade:
                            _distribute(parent_receipt, per_parent)
                        elif parent_receipt:
                            parent_provider = parent_receipt.provider.hex()
                            ledger.credit(parent_provider, per_parent)
                            _add_payment(parent_provider, per_parent)
                            royalty_records.append(RoyaltyPayment(
                                recipient=parent_receipt.provider,
                                amount=per_parent,
                                receipt_id=parent_ref.receipt_id,
                            ))
                        # else: parent unavailable — share falls to seller.
                        # ParentRef has no provider field, so we cannot
                        # resolve the recipient. per spec §9.3, this
                        # incentivises sellers to make provenance available.

    _distribute(receipt, sale_price)

    # seller keeps everything not distributed as royalties.
    # this includes: their margin, integer division remainders,
    # and shares for unavailable parents.
    seller_cut = sale_price - total_distributed
    seller_id = seller_pubkey.hex()
    ledger.credit(seller_id, seller_cut)
    _add_payment(seller_id, seller_cut)

    return payments, royalty_records
