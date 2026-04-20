# log_server — HTTP interface for a transparency log operator
#
# One process = one log operator. Run multiple on different ports
# for threshold confirmation.
#
#   python3 log_server.py --port 7001 --db log_alpha.db
#
# Endpoints:
#   POST /receipt          Submit a full receipt (indexes it + DAG edges)
#   GET  /receipt/<id>     Get a receipt by ID
#   GET  /dag/<id>         Full provenance DAG (ancestors + descendants)
#   GET  /parents/<id>     Direct parents
#   GET  /children/<id>    Direct children
#   GET  /ancestors/<id>   All ancestors (recursive)
#   GET  /descendants/<id> All descendants (recursive)
#   GET  /transfers/<id>   Transfer history for a receipt
#   GET  /owner/<id>       Current owner
#   GET  /search           Search receipts (query params: provider, model, min_price, max_price)
#   GET  /proof/<id>       Merkle inclusion proof
#   GET  /root             Current Merkle root and log size
#   GET  /stats            Log statistics
#   POST /submit           Submit a transfer record (existing)
#   POST /register         Register initial ownership (legacy)

import argparse
import json

from flask import Flask, request, jsonify

from transparency import TransparencyLog


app = Flask(__name__)
log: TransparencyLog = None


# ── Receipt submission ──

@app.route("/receipt", methods=["POST"])
def submit_receipt():
    """Submit a full receipt to the log. Indexes it and its provenance edges.

    Body: {"receipt": {...}, "receipt_id": "hex"}
    The receipt_id is computed by the node from canonical bytes.
    """
    data = request.get_json()
    receipt_data = data.get("receipt", data)
    receipt_id = data.get("receipt_id")
    receipt_json = json.dumps(receipt_data, sort_keys=True, separators=(",", ":"))
    try:
        result = log.submit_receipt(receipt_json, receipt_id=receipt_id)
        return jsonify({"status": "accepted", **result})
    except ValueError as e:
        return jsonify({"status": "rejected", "reason": str(e)}), 409


# ── Receipt query ──

@app.route("/receipt/<receipt_id>", methods=["GET"])
def get_receipt(receipt_id):
    result = log.get_receipt(receipt_id)
    if result is None:
        return jsonify({"status": "not_found"}), 404

    owner = log.owner(bytes.fromhex(receipt_id))
    parents = log.parents(receipt_id)
    children = log.children(receipt_id)

    return jsonify({
        "receipt_id": receipt_id,
        "receipt": json.loads(result["json_data"]),
        "provider": result["provider"],
        "model_id": result["model_id"],
        "price": result["price"],
        "provenance_depth": result["provenance_depth"],
        "owner": owner,
        "parents": parents,
        "children": children,
    })


# ── DAG traversal ──

@app.route("/dag/<receipt_id>", methods=["GET"])
def dag(receipt_id):
    """Full provenance context: ancestors, descendants, and the receipt itself."""
    receipt = log.get_receipt(receipt_id)
    if receipt is None:
        return jsonify({"status": "not_found"}), 404

    max_depth = request.args.get("depth", 256, type=int)

    return jsonify({
        "receipt_id": receipt_id,
        "provider": receipt["provider"],
        "model_id": receipt["model_id"],
        "price": receipt["price"],
        "ancestors": log.ancestors(receipt_id, max_depth),
        "descendants": log.descendants(receipt_id, max_depth),
        "parents": log.parents(receipt_id),
        "children": log.children(receipt_id),
    })


@app.route("/parents/<receipt_id>", methods=["GET"])
def parents(receipt_id):
    return jsonify({"receipt_id": receipt_id, "parents": log.parents(receipt_id)})


@app.route("/children/<receipt_id>", methods=["GET"])
def children(receipt_id):
    return jsonify({"receipt_id": receipt_id, "children": log.children(receipt_id)})


@app.route("/ancestors/<receipt_id>", methods=["GET"])
def ancestors(receipt_id):
    max_depth = request.args.get("depth", 256, type=int)
    return jsonify({
        "receipt_id": receipt_id,
        "ancestors": log.ancestors(receipt_id, max_depth),
    })


@app.route("/descendants/<receipt_id>", methods=["GET"])
def descendants(receipt_id):
    max_depth = request.args.get("depth", 256, type=int)
    return jsonify({
        "receipt_id": receipt_id,
        "descendants": log.descendants(receipt_id, max_depth),
    })


# ── Transfer history ──

@app.route("/transfers/<receipt_id>", methods=["GET"])
def transfer_history(receipt_id):
    return jsonify({
        "receipt_id": receipt_id,
        "transfers": log.transfers(receipt_id),
    })


# ── Search ──

@app.route("/search", methods=["GET"])
def search():
    results = log.search(
        provider=request.args.get("provider"),
        model_id=request.args.get("model"),
        min_price=request.args.get("min_price", type=int),
        max_price=request.args.get("max_price", type=int),
        limit=request.args.get("limit", 100, type=int),
        offset=request.args.get("offset", 0, type=int),
    )
    return jsonify({"results": results, "count": len(results)})


# ── Ownership ──

@app.route("/owner/<receipt_id>", methods=["GET"])
def owner(receipt_id):
    result = log.owner(bytes.fromhex(receipt_id))
    if result is None:
        return jsonify({"status": "not_found"}), 404
    return jsonify({"receipt_id": receipt_id, "owner": result})


# ── Merkle proofs ──

@app.route("/proof/<receipt_id>", methods=["GET"])
def proof(receipt_id):
    result = log.prove(bytes.fromhex(receipt_id))
    if result is None:
        return jsonify({"status": "not_found"}), 404
    return jsonify({"status": "ok", **result})


@app.route("/root", methods=["GET"])
def root():
    return jsonify({"root": log.root.hex(), "size": log.size})


# ── Stats ──

@app.route("/stats", methods=["GET"])
def stats():
    return jsonify(log.stats())


# ── Vouches ──

@app.route("/vouch", methods=["POST"])
def submit_vouch():
    """Submit a vouch record (stake delegation)."""
    data = request.get_json()
    try:
        result = log.submit_vouch(
            voucher=bytes.fromhex(data["voucher"]),
            vouchee=bytes.fromhex(data["vouchee"]),
            amount=data["amount"],
            timestamp=data["timestamp"],
            signature=bytes.fromhex(data["signature"]),
        )
        return jsonify({"status": "accepted", **result})
    except ValueError as e:
        return jsonify({"status": "rejected", "reason": str(e)}), 409


@app.route("/vouches/<pubkey>", methods=["GET"])
def get_vouches(pubkey):
    """Get all vouches for or by an operator."""
    direction = request.args.get("direction", "for")  # "for" or "by"
    try:
        pk = bytes.fromhex(pubkey)
        if direction == "by":
            vouches = log.get_vouches_by(pk)
        else:
            vouches = log.get_vouches_for(pk)
        return jsonify({"pubkey": pubkey, "vouches": vouches, "count": len(vouches)})
    except ValueError:
        return jsonify({"status": "error", "reason": "invalid pubkey"}), 400


# ── Legacy endpoints (backward compat) ──

@app.route("/submit", methods=["POST"])
def submit():
    data = request.get_json()
    try:
        result = log.submit(
            receipt_id=bytes.fromhex(data["receipt_id"]),
            from_key=bytes.fromhex(data["from_key"]),
            to_key=bytes.fromhex(data["to_key"]),
            price=data["price"],
            currency=data["currency"],
            timestamp=data["timestamp"],
            signature=bytes.fromhex(data["signature"]),
            canonical_bytes=bytes.fromhex(data["canonical_bytes"]),
        )
        return jsonify({"status": "accepted", **result})
    except ValueError as e:
        return jsonify({"status": "rejected", "reason": str(e)}), 409


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    try:
        log.register(
            receipt_id=bytes.fromhex(data["receipt_id"]),
            owner=bytes.fromhex(data["owner"]),
        )
        return jsonify({"status": "registered"})
    except ValueError as e:
        return jsonify({"status": "rejected", "reason": str(e)}), 409


def main():
    parser = argparse.ArgumentParser(description="Tessera transparency log operator")
    parser.add_argument("--port", type=int, default=7001)
    parser.add_argument("--db", type=str, default="log.db")
    parser.add_argument("--host", type=str, default="127.0.0.1")
    args = parser.parse_args()

    global log
    log = TransparencyLog(args.db)

    s = log.stats()
    print(f"Tessera log operator on {args.host}:{args.port} (db: {args.db})")
    print(f"  Receipts: {s['receipts']} | DAG edges: {s['dag_edges']} | Transfers: {s['transfers']}")
    print(f"  Providers: {s['providers']} | Models: {s['models']}")
    print(f"  Root: {s['root'][:32]}...")
    app.run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
