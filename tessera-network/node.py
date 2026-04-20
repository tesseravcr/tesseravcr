"""
Tessera VCR node — a single agent's HTTP server.

Each agent runs one node. The node wraps the protocol layer with:
- HTTP endpoints for compute, receipt exchange, transfer, trust, verification
- SQLite persistence so state survives restarts
- An Ed25519 identity (keypair)

    python3 node.py --name sentinel --port 9001 --model supply-chain-intel
"""

import argparse
import base64
import hashlib
import json
import math
import os
import sqlite3
import sys
import threading
import time

import requests
from flask import Flask, request, jsonify

_OLLAMA_URL = os.environ.get("TESSERA_OLLAMA_URL", "http://localhost:11434")
_OLLAMA_MODEL = os.environ.get("TESSERA_OLLAMA_MODEL", "llama3.2:1b")

# Protocol imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tessera-py"))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)
from protocol.receipt import Receipt, RoyaltyTerms, ParentRef
from protocol.transfer import TransferRecord, TransferLedger, RoyaltyPayment
from protocol.settlement import Ledger, settle_resale
from protocol.stake import StakeCalculator, OperatorRegistry
from protocol.registry import Registry, OperatorProfile


# ── SQLite persistence ──────────────────────────────────────────

class Store:
    """Thin SQLite wrapper. One database per agent."""

    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.lock = threading.Lock()
        self._init_tables()

    def _init_tables(self):
        with self.conn:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS receipts (
                    receipt_id TEXT PRIMARY KEY,
                    json_data  TEXT NOT NULL,
                    provider   TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS transfers (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    receipt_id TEXT NOT NULL,
                    from_key   TEXT NOT NULL,
                    to_key     TEXT NOT NULL,
                    price      INTEGER NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ownership (
                    receipt_id TEXT PRIMARY KEY,
                    owner_key  TEXT NOT NULL
                );
            """)

    def save_receipt(self, receipt: Receipt):
        rid = receipt.receipt_id.hex()
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO receipts VALUES (?, ?, ?, ?)",
                (rid, receipt.to_json(), receipt.provider.hex(), int(time.time())),
            )
            self.conn.commit()

    def get_receipt(self, receipt_id_hex: str) -> Receipt | None:
        row = self.conn.execute(
            "SELECT json_data FROM receipts WHERE receipt_id = ?",
            (receipt_id_hex,),
        ).fetchone()
        return Receipt.from_json(row[0]) if row else None

    def get_all_receipts(self) -> dict[str, Receipt]:
        rows = self.conn.execute("SELECT receipt_id, json_data FROM receipts").fetchall()
        return {rid: Receipt.from_json(data) for rid, data in rows}

    def register_ownership(self, receipt_id_hex: str, owner_hex: str):
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO ownership VALUES (?, ?)",
                (receipt_id_hex, owner_hex),
            )
            self.conn.commit()

    def get_owner(self, receipt_id_hex: str) -> str | None:
        row = self.conn.execute(
            "SELECT owner_key FROM ownership WHERE receipt_id = ?",
            (receipt_id_hex,),
        ).fetchone()
        return row[0] if row else None

    def transfer_ownership(self, receipt_id_hex: str, from_hex: str, to_hex: str, price: int):
        with self.lock:
            current = self.conn.execute(
                "SELECT owner_key FROM ownership WHERE receipt_id = ?",
                (receipt_id_hex,),
            ).fetchone()
            if not current:
                raise ValueError("Receipt not registered")
            if current[0] != from_hex:
                raise ValueError("Not the owner")
            self.conn.execute(
                "UPDATE ownership SET owner_key = ? WHERE receipt_id = ?",
                (to_hex, receipt_id_hex),
            )
            self.conn.execute(
                "INSERT INTO transfers VALUES (NULL, ?, ?, ?, ?, ?)",
                (receipt_id_hex, from_hex, to_hex, price, int(time.time())),
            )
            self.conn.commit()


# ── Node (agent server) ────────────────────────────────────────

class Node:
    def __init__(self, name, port, models, db_path=None, key=None, log_url=None):
        self.name = name
        self.port = port
        self.models = models
        self.log_url = log_url  # Optional: URL of transparency log for trust queries
        self.key = key or Ed25519PrivateKey.generate()
        self.pubkey = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(__file__), "data", f"{name}.db"
            )
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.store = Store(db_path)

        # In-memory protocol state (rebuilt from DB on restart)
        self.registry = Registry()
        self.registry.register_operator(OperatorProfile(
            pubkey=self.pubkey, backends=["tee-nitro-v1", "ezkl-halo2"],
            models=[m.encode() for m in models],
        ))

        # Register receipts from DB into the registry
        for rid, receipt in self.store.get_all_receipts().items():
            try:
                self.registry.record_receipt(receipt)
            except ValueError:
                pass

        self.app = self._build_app()

    def _build_app(self):
        app = Flask(self.name)
        app.logger.disabled = True

        import logging
        log = logging.getLogger("werkzeug")
        log.setLevel(logging.ERROR)

        @app.route("/info", methods=["GET"])
        def info():
            return jsonify({
                "name": self.name,
                "pubkey": self.pubkey.hex(),
                "models": self.models,
                "port": self.port,
            })

        @app.route("/compute", methods=["POST"])
        def compute():
            data = request.json
            input_data = data.get("input_data", "").encode()
            model = data.get("model", self.models[0] if self.models else "default")
            price = data.get("price", 0)
            parent_refs = []
            for p in data.get("parents", []):
                parent_refs.append(ParentRef(
                    receipt_id=bytes.fromhex(p["receipt_id"]),
                    receipt_hash=bytes.fromhex(p["receipt_hash"]),
                    relationship=p.get("relationship", "input"),
                ))

            use_mock = os.environ.get("TESSERA_MOCK", "").strip() == "1"

            if use_mock:
                # Mock mode: deterministic output, no external calls
                output_data = f"{self.name} processed: {data.get('input_data', '')}"
                output_bytes = output_data.encode()
                computed_price = price
            else:
                # Real inference via Ollama (local LLM)
                ollama_model = data.get("ollama_model", _OLLAMA_MODEL)
                resp = requests.post(f"{_OLLAMA_URL}/api/chat", json={
                    "model": ollama_model,
                    "messages": [{"role": "user", "content": data.get("input_data", "")}],
                    "stream": False,
                }, timeout=120)
                resp.raise_for_status()
                body = resp.json()
                output_data = body["message"]["content"]
                output_bytes = output_data.encode()

                # Map token counts to price in USD-cents
                # Ollama is free/local, but we assign a nominal cost based on token count
                # so the economic layer has meaningful values to work with
                prompt_tokens = body.get("prompt_eval_count", 0)
                completion_tokens = body.get("eval_count", 0)
                total_tokens = prompt_tokens + completion_tokens
                # 1 cent per 1000 tokens (nominal)
                computed_price = max(1, math.ceil(total_tokens / 1000))

            receipt = Receipt(
                model_id=hashlib.sha256(model.encode()).digest(),
                input_hash=hashlib.sha256(input_data).digest(),
                output_hash=hashlib.sha256(output_bytes).digest(),
                proof=hashlib.sha256(output_bytes + self.pubkey).digest(),
                proving_backend="tee-nitro-v1",
                original_price=computed_price,
                royalty_terms=RoyaltyTerms(
                    provider_royalty=data.get("provider_royalty", 500),
                    parent_royalty=data.get("parent_royalty", 300),
                    cascade=data.get("cascade", True),
                ),
                parent_receipts=parent_refs,
                provenance_depth=len(parent_refs) and 1,
                output_data=output_bytes,
            )
            receipt.sign(self.key)

            self.store.save_receipt(receipt)
            self.store.register_ownership(receipt.receipt_id.hex(), self.pubkey.hex())
            self.registry.record_receipt(receipt)

            return jsonify({
                "receipt": json.loads(receipt.to_json()),
                "receipt_id": receipt.receipt_id.hex(),
                "output": output_data,
            })

        @app.route("/receipt/<receipt_id>", methods=["GET"])
        def get_receipt(receipt_id):
            receipt = self.store.get_receipt(receipt_id)
            if not receipt:
                return jsonify({"error": "not found"}), 404
            owner = self.store.get_owner(receipt_id)
            return jsonify({
                "receipt": json.loads(receipt.to_json()),
                "receipt_id": receipt_id,
                "owner": owner,
            })

        @app.route("/transfer", methods=["POST"])
        def transfer():
            data = request.json
            receipt_id_hex = data["receipt_id"]
            to_key_hex = data["to_key"]
            price = data["price"]

            receipt = self.store.get_receipt(receipt_id_hex)
            if not receipt:
                return jsonify({"error": "receipt not found"}), 404

            owner = self.store.get_owner(receipt_id_hex)
            if owner != self.pubkey.hex():
                return jsonify({"error": "not the owner"}), 403

            to_key = bytes.fromhex(to_key_hex)
            xfer = TransferRecord(
                receipt_id=bytes.fromhex(receipt_id_hex),
                from_key=self.pubkey,
                to_key=to_key,
                price=price,
                currency="USD-cents",
            )
            xfer.sign(self.key)
            self.store.transfer_ownership(receipt_id_hex, self.pubkey.hex(), to_key_hex, price)

            # Settle royalties
            receipt_store = self.store.get_all_receipts()
            ledger = Ledger()
            ledger.credit("buyer", price)
            ledger.create_escrow("sale", "buyer", price)
            payments, royalties = ledger.release_escrow_resale(
                "sale", receipt, self.pubkey, price, receipt_store,
            )

            return jsonify({
                "transfer_hash": xfer.transfer_hash.hex(),
                "signature_valid": xfer.verify_signature(),
                "payments": {k: v for k, v in payments.items()},
                "total_distributed": sum(payments.values()),
            })

        @app.route("/trust/<pubkey_hex>", methods=["GET"])
        def trust(pubkey_hex):
            """Compute trust score for an operator by querying transparency log."""
            if not self.log_url:
                return jsonify({"error": "no log configured"}), 400

            try:
                pubkey = bytes.fromhex(pubkey_hex)

                # Query log for receipts by this provider
                search_resp = requests.get(f"{self.log_url}/search", params={"provider": pubkey_hex}, timeout=5)
                search_resp.raise_for_status()
                receipts_data = search_resp.json().get("results", [])

                # Query log for vouches for this provider
                vouches_resp = requests.get(f"{self.log_url}/vouches/{pubkey_hex}", params={"direction": "for"}, timeout=5)
                vouches_resp.raise_for_status()
                vouches_data = vouches_resp.json().get("vouches", [])

                # Compute simplified stake
                # direct_value = sum of all receipt prices
                direct_value = sum(r["price"] for r in receipts_data)
                receipt_count = len(receipts_data)

                # vouched_stake = sum of all vouch amounts
                vouched_stake = sum(v["amount"] for v in vouches_data)

                # effective_stake = direct_value + vouched_stake
                # (simplified - real version includes royalty NPV, dependency depth, counterparty diversity)
                effective_stake = direct_value + vouched_stake

                # Compute settlement recommendation
                transaction_value = request.args.get("transaction_value", type=int)
                recommendation = None
                trust_quotient = None
                if transaction_value and transaction_value > 0:
                    trust_quotient = effective_stake / transaction_value
                    # Settlement recommendations based on trust quotient
                    if trust_quotient >= 50:
                        recommendation = "instant"
                    elif trust_quotient >= 5:
                        recommendation = "escrow"
                    else:
                        recommendation = "collateral_required"

                result = {
                    "pubkey": pubkey_hex,
                    "effective_stake": effective_stake,
                    "receipt_count": receipt_count,
                    "direct_value": direct_value,
                    "vouched_stake": vouched_stake,
                    "counterparty_diversity": 0.0,  # Would need full receipts with counterparty data
                }
                if trust_quotient is not None:
                    result["trust_quotient"] = trust_quotient
                if recommendation:
                    result["settlement_recommendation"] = recommendation

                return jsonify(result)

            except Exception as e:
                return jsonify({"error": f"trust computation failed: {str(e)}"}), 500

        @app.route("/vouch", methods=["POST"])
        def vouch():
            """Submit a vouch for another operator to the transparency log."""
            if not self.log_url:
                return jsonify({"error": "no log configured"}), 400

            data = request.json
            vouchee_hex = data["vouchee"]
            amount = data["amount"]
            timestamp = int(time.time())

            # Create vouch signature
            voucher = self.pubkey
            vouchee = bytes.fromhex(vouchee_hex)
            import struct
            vouch_data = voucher + vouchee + struct.pack(">Q", amount) + struct.pack(">Q", timestamp)
            vouch_hash = hashlib.sha256(vouch_data).digest()
            signature = self.key.sign(vouch_hash)

            # Submit to log
            try:
                resp = requests.post(f"{self.log_url}/vouch", json={
                    "voucher": voucher.hex(),
                    "vouchee": vouchee_hex,
                    "amount": amount,
                    "timestamp": timestamp,
                    "signature": signature.hex(),
                }, timeout=5)
                resp.raise_for_status()
                return jsonify(resp.json())
            except requests.RequestException as e:
                return jsonify({"error": f"vouch submission failed: {str(e)}"}), 500

        @app.route("/verify", methods=["POST"])
        def verify():
            data = request.json
            receipt = Receipt.from_json(json.dumps(data["receipt"]))
            checks = {
                "signature_valid": receipt.verify_signature(),
                "receipt_id_matches": receipt.receipt_id.hex() == data.get("receipt_id", ""),
            }
            if receipt.output_data:
                expected = hashlib.sha256(receipt.output_data).digest()
                checks["output_binding"] = expected == receipt.output_hash
            return jsonify(checks)

        return app

    def run(self):
        self.app.run(host="127.0.0.1", port=self.port, threaded=True)

    def run_background(self):
        t = threading.Thread(target=self.run, daemon=True)
        t.start()
        # Wait for server to be ready
        import requests as req
        for _ in range(50):
            try:
                req.get(f"http://127.0.0.1:{self.port}/info", timeout=0.5)
                return
            except Exception:
                time.sleep(0.1)
        raise RuntimeError(f"Node {self.name} failed to start on port {self.port}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run a Tessera VCR node")
    parser.add_argument("--name", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--model", action="append", default=[])
    args = parser.parse_args()
    node = Node(args.name, args.port, args.model or ["default"])
    print(f"  {args.name} running on port {args.port} [{node.pubkey.hex()[:16]}...]")
    node.run()
