#!/usr/bin/env python3
"""Local credit/debit tracking for Tessera VCR agents.

Stores earnings, spending, and royalty records in a local SQLite database.
Each agent (provider or consumer) maintains its own ledger for accounting.

Usage:
    python ledger.py                  # show balance and recent history
    python ledger.py --history        # show full transaction history
    python ledger.py --reset          # reset the ledger (dangerous)
"""

import argparse
import os
import sqlite3
import time

from config import TESSERA_DIR

LEDGER_PATH = os.path.join(TESSERA_DIR, "ledger.db")


def _get_db():
    """Get a connection to the ledger database, creating tables if needed."""
    os.makedirs(TESSERA_DIR, exist_ok=True)
    conn = sqlite3.connect(LEDGER_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS credits (
            id INTEGER PRIMARY KEY,
            timestamp INTEGER,
            counterparty TEXT,
            amount INTEGER,
            currency TEXT,
            receipt_id TEXT,
            type TEXT
        )
    """)
    conn.commit()
    return conn


def record_earning(pubkey_hex: str, amount: int, receipt_id: str):
    """Record that the provider earned credits from inference.

    Args:
        pubkey_hex: counterparty (consumer) public key hex
        amount: amount earned in currency units
        receipt_id: associated receipt ID hex
    """
    conn = _get_db()
    conn.execute(
        "INSERT INTO credits (timestamp, counterparty, amount, currency, receipt_id, type) VALUES (?, ?, ?, ?, ?, ?)",
        (int(time.time()), pubkey_hex, amount, "USD-cents", receipt_id, "earned"),
    )
    conn.commit()
    conn.close()


def record_spending(pubkey_hex: str, amount: int, receipt_id: str):
    """Record that the consumer spent credits on inference.

    Args:
        pubkey_hex: counterparty (provider) public key hex
        amount: amount spent in currency units
        receipt_id: associated receipt ID hex
    """
    conn = _get_db()
    conn.execute(
        "INSERT INTO credits (timestamp, counterparty, amount, currency, receipt_id, type) VALUES (?, ?, ?, ?, ?, ?)",
        (int(time.time()), pubkey_hex, -amount, "USD-cents", receipt_id, "spent"),
    )
    conn.commit()
    conn.close()


def record_royalty(pubkey_hex: str, amount: int, receipt_id: str):
    """Record royalty income from downstream usage.

    Args:
        pubkey_hex: counterparty who triggered the royalty
        amount: royalty amount in currency units
        receipt_id: associated receipt ID hex
    """
    conn = _get_db()
    conn.execute(
        "INSERT INTO credits (timestamp, counterparty, amount, currency, receipt_id, type) VALUES (?, ?, ?, ?, ?, ?)",
        (int(time.time()), pubkey_hex, amount, "USD-cents", receipt_id, "royalty"),
    )
    conn.commit()
    conn.close()


def get_balance() -> int:
    """Get net credit balance (positive = net earner, negative = net spender).

    Returns:
        Net balance in currency units
    """
    conn = _get_db()
    cursor = conn.execute("SELECT COALESCE(SUM(amount), 0) FROM credits")
    balance = cursor.fetchone()[0]
    conn.close()
    return balance


def get_history(limit: int = 50) -> list:
    """Get recent transaction history.

    Args:
        limit: maximum number of records to return

    Returns:
        List of dicts with keys: id, timestamp, counterparty, amount, currency, receipt_id, type
    """
    conn = _get_db()
    cursor = conn.execute(
        "SELECT id, timestamp, counterparty, amount, currency, receipt_id, type "
        "FROM credits ORDER BY timestamp DESC LIMIT ?",
        (limit,),
    )
    rows = cursor.fetchall()
    conn.close()
    return [
        {
            "id": r[0],
            "timestamp": r[1],
            "counterparty": r[2],
            "amount": r[3],
            "currency": r[4],
            "receipt_id": r[5],
            "type": r[6],
        }
        for r in rows
    ]


def main():
    parser = argparse.ArgumentParser(description="Tessera VCR Ledger")
    parser.add_argument("--history", action="store_true", help="Show full transaction history")
    parser.add_argument("--reset", action="store_true", help="Reset the ledger database")
    parser.add_argument("--limit", type=int, default=50, help="Number of history records to show")
    args = parser.parse_args()

    if args.reset:
        if os.path.exists(LEDGER_PATH):
            os.remove(LEDGER_PATH)
            print("Ledger reset.")
        else:
            print("No ledger found.")
        return

    balance = get_balance()
    print("Tessera VCR Ledger")
    print("==================")
    print(f"  Database: {LEDGER_PATH}")
    print(f"  Balance:  {balance} USD-cents (${balance/100:.2f})")
    print()

    if args.history:
        history = get_history(limit=args.limit)
        if not history:
            print("  No transactions recorded.")
            return
        print(f"  {'Type':<8} {'Amount':>10} {'Counterparty':<20} {'Receipt ID':<18} {'Time'}")
        print(f"  {'-'*8} {'-'*10} {'-'*20} {'-'*18} {'-'*20}")
        for entry in history:
            counterparty = entry["counterparty"][:16] + "..." if entry["counterparty"] else "—"
            receipt = entry["receipt_id"][:16] + "..." if entry["receipt_id"] else "—"
            ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(entry["timestamp"]))
            print(f"  {entry['type']:<8} {entry['amount']:>10} {counterparty:<20} {receipt:<18} {ts}")


if __name__ == "__main__":
    main()
