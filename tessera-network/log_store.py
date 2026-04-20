# store — SQLite persistence for a single transparency log
#
# Each log operator runs their own database. Logs are independent.
#
# Three layers of data:
#   1. receipts  — the full receipt (JSON), indexed by receipt_id
#   2. dag_edges — parent→child provenance links, queryable
#   3. entries   — append-only transfer log (Merkle leaves)
#   4. ownership — current owner per receipt

import sqlite3
import threading


class LogStore:
    """Persistent storage for one transparency log.

    Thread-safe. Each instance owns one SQLite connection.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()

    def _create_tables(self):
        self.conn.executescript("""
            -- Full receipt storage
            CREATE TABLE IF NOT EXISTS receipts (
                receipt_id    TEXT PRIMARY KEY,
                json_data     TEXT NOT NULL,
                provider      TEXT NOT NULL,
                model_id      TEXT NOT NULL,
                price         INTEGER NOT NULL,
                currency      TEXT NOT NULL,
                proving_backend TEXT NOT NULL,
                provenance_depth INTEGER NOT NULL DEFAULT 0,
                timestamp     INTEGER NOT NULL,
                leaf_hash     BLOB NOT NULL,
                created_at    INTEGER NOT NULL
            );

            -- Provenance DAG edges (parent → child)
            CREATE TABLE IF NOT EXISTS dag_edges (
                child_id      TEXT NOT NULL,
                parent_id     TEXT NOT NULL,
                relationship  TEXT NOT NULL,
                PRIMARY KEY (child_id, parent_id)
            );

            -- Transfer log (append-only, Merkle leaves)
            CREATE TABLE IF NOT EXISTS entries (
                idx         INTEGER PRIMARY KEY,
                receipt_id  TEXT NOT NULL,
                from_key    TEXT NOT NULL,
                to_key      TEXT NOT NULL,
                price       INTEGER NOT NULL,
                currency    TEXT NOT NULL,
                timestamp   INTEGER NOT NULL,
                leaf_hash   BLOB NOT NULL,
                raw_bytes   BLOB NOT NULL
            );

            -- Current ownership
            CREATE TABLE IF NOT EXISTS ownership (
                receipt_id  TEXT PRIMARY KEY,
                owner_key   TEXT NOT NULL,
                entry_idx   INTEGER NOT NULL
            );

            -- Vouches (stake delegation)
            CREATE TABLE IF NOT EXISTS vouches (
                voucher     TEXT NOT NULL,
                vouchee     TEXT NOT NULL,
                amount      INTEGER NOT NULL,
                timestamp   INTEGER NOT NULL,
                signature   BLOB NOT NULL,
                PRIMARY KEY (voucher, vouchee)
            );

            CREATE INDEX IF NOT EXISTS idx_entries_receipt
                ON entries(receipt_id);
            CREATE INDEX IF NOT EXISTS idx_receipts_provider
                ON receipts(provider);
            CREATE INDEX IF NOT EXISTS idx_receipts_model
                ON receipts(model_id);
            CREATE INDEX IF NOT EXISTS idx_receipts_timestamp
                ON receipts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_dag_parent
                ON dag_edges(parent_id);
            CREATE INDEX IF NOT EXISTS idx_dag_child
                ON dag_edges(child_id);
            CREATE INDEX IF NOT EXISTS idx_vouches_vouchee
                ON vouches(vouchee);
            CREATE INDEX IF NOT EXISTS idx_vouches_voucher
                ON vouches(voucher);
        """)
        self.conn.commit()

    # ── Receipt storage ──

    def store_receipt(self, receipt_id_hex: str, json_data: str,
                      provider_hex: str, model_id_hex: str,
                      price: int, currency: str, proving_backend: str,
                      provenance_depth: int, timestamp: int,
                      leaf_hash: bytes, parent_refs: list[dict]) -> bool:
        """Store a receipt and its DAG edges. Returns True if new, False if duplicate."""
        with self.lock:
            existing = self.conn.execute(
                "SELECT 1 FROM receipts WHERE receipt_id = ?",
                (receipt_id_hex,),
            ).fetchone()
            if existing:
                return False

            import time
            self.conn.execute(
                """INSERT INTO receipts
                   (receipt_id, json_data, provider, model_id, price, currency,
                    proving_backend, provenance_depth, timestamp, leaf_hash, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (receipt_id_hex, json_data, provider_hex, model_id_hex,
                 price, currency, proving_backend, provenance_depth,
                 timestamp, leaf_hash, int(time.time())),
            )

            for parent in parent_refs:
                self.conn.execute(
                    "INSERT OR IGNORE INTO dag_edges VALUES (?, ?, ?)",
                    (receipt_id_hex, parent["receipt_id"], parent["relationship"]),
                )

            self.conn.commit()
            return True

    def get_receipt(self, receipt_id_hex: str) -> dict | None:
        with self.lock:
            row = self.conn.execute(
                """SELECT receipt_id, json_data, provider, model_id, price, currency,
                          proving_backend, provenance_depth, timestamp
                   FROM receipts WHERE receipt_id = ?""",
                (receipt_id_hex,),
            ).fetchone()
            if not row:
                return None
            return {
                "receipt_id": row[0], "json_data": row[1], "provider": row[2],
                "model_id": row[3], "price": row[4], "currency": row[5],
                "proving_backend": row[6], "provenance_depth": row[7],
                "timestamp": row[8],
            }

    def receipt_exists(self, receipt_id_hex: str) -> bool:
        with self.lock:
            row = self.conn.execute(
                "SELECT 1 FROM receipts WHERE receipt_id = ?",
                (receipt_id_hex,),
            ).fetchone()
            return row is not None

    # ── DAG queries ──

    def get_parents(self, receipt_id_hex: str) -> list[dict]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT parent_id, relationship FROM dag_edges WHERE child_id = ?",
                (receipt_id_hex,),
            ).fetchall()
            return [{"receipt_id": r[0], "relationship": r[1]} for r in rows]

    def get_children(self, receipt_id_hex: str) -> list[dict]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT child_id, relationship FROM dag_edges WHERE parent_id = ?",
                (receipt_id_hex,),
            ).fetchall()
            return [{"receipt_id": r[0], "relationship": r[1]} for r in rows]

    def get_ancestors(self, receipt_id_hex: str, max_depth: int = 256) -> list[dict]:
        """Walk the DAG upward. Returns all ancestors with their depth from the starting receipt."""
        with self.lock:
            rows = self.conn.execute(
                """WITH RECURSIVE ancestors(rid, depth) AS (
                       SELECT parent_id, 1 FROM dag_edges WHERE child_id = ?
                       UNION
                       SELECT e.parent_id, a.depth + 1
                       FROM dag_edges e JOIN ancestors a ON e.child_id = a.rid
                       WHERE a.depth < ?
                   )
                   SELECT DISTINCT rid, MIN(depth) FROM ancestors GROUP BY rid ORDER BY depth""",
                (receipt_id_hex, max_depth),
            ).fetchall()
            return [{"receipt_id": r[0], "depth": r[1]} for r in rows]

    def get_descendants(self, receipt_id_hex: str, max_depth: int = 256) -> list[dict]:
        """Walk the DAG downward. Returns all descendants with their depth."""
        with self.lock:
            rows = self.conn.execute(
                """WITH RECURSIVE descendants(rid, depth) AS (
                       SELECT child_id, 1 FROM dag_edges WHERE parent_id = ?
                       UNION
                       SELECT e.child_id, d.depth + 1
                       FROM dag_edges e JOIN descendants d ON e.parent_id = d.rid
                       WHERE d.depth < ?
                   )
                   SELECT DISTINCT rid, MIN(depth) FROM descendants GROUP BY rid ORDER BY depth""",
                (receipt_id_hex, max_depth),
            ).fetchall()
            return [{"receipt_id": r[0], "depth": r[1]} for r in rows]

    # ── Search ──

    def search(self, provider: str = None, model_id: str = None,
               min_price: int = None, max_price: int = None,
               limit: int = 100, offset: int = 0) -> list[dict]:
        """Search receipts by provider, model, price range."""
        conditions = []
        params = []

        if provider:
            conditions.append("provider = ?")
            params.append(provider)
        if model_id:
            conditions.append("model_id = ?")
            params.append(model_id)
        if min_price is not None:
            conditions.append("price >= ?")
            params.append(min_price)
        if max_price is not None:
            conditions.append("price <= ?")
            params.append(max_price)

        where = " AND ".join(conditions) if conditions else "1=1"
        params.extend([limit, offset])

        with self.lock:
            rows = self.conn.execute(
                f"""SELECT receipt_id, provider, model_id, price, currency,
                           provenance_depth, timestamp
                    FROM receipts WHERE {where}
                    ORDER BY timestamp DESC LIMIT ? OFFSET ?""",
                params,
            ).fetchall()
            return [
                {
                    "receipt_id": r[0], "provider": r[1], "model_id": r[2],
                    "price": r[3], "currency": r[4], "provenance_depth": r[5],
                    "timestamp": r[6],
                }
                for r in rows
            ]

    def stats(self) -> dict:
        with self.lock:
            receipts = self.conn.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
            edges = self.conn.execute("SELECT COUNT(*) FROM dag_edges").fetchone()[0]
            transfers = self.conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
            providers = self.conn.execute("SELECT COUNT(DISTINCT provider) FROM receipts").fetchone()[0]
            models = self.conn.execute("SELECT COUNT(DISTINCT model_id) FROM receipts").fetchone()[0]
            return {
                "receipts": receipts, "dag_edges": edges, "transfers": transfers,
                "providers": providers, "models": models,
            }

    # ── Transfer log (unchanged from before) ──

    def get_owner(self, receipt_id_hex: str) -> str | None:
        with self.lock:
            row = self.conn.execute(
                "SELECT owner_key FROM ownership WHERE receipt_id = ?",
                (receipt_id_hex,),
            ).fetchone()
            return row[0] if row else None

    def append(self, receipt_id_hex: str, from_key_hex: str, to_key_hex: str,
               price: int, currency: str, timestamp: int,
               leaf_hash: bytes, raw_bytes: bytes) -> int:
        """Append a transfer entry. Returns the 0-based index."""
        with self.lock:
            row = self.conn.execute("SELECT COUNT(*) FROM entries").fetchone()
            idx = row[0]

            self.conn.execute(
                """INSERT INTO entries
                   (idx, receipt_id, from_key, to_key, price, currency, timestamp, leaf_hash, raw_bytes)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (idx, receipt_id_hex, from_key_hex, to_key_hex, price, currency,
                 timestamp, leaf_hash, raw_bytes),
            )

            self.conn.execute(
                """INSERT OR REPLACE INTO ownership (receipt_id, owner_key, entry_idx)
                   VALUES (?, ?, ?)""",
                (receipt_id_hex, to_key_hex, idx),
            )
            self.conn.commit()
            return idx

    def get_leaf_hashes(self) -> list[bytes]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT leaf_hash FROM entries ORDER BY idx"
            ).fetchall()
            return [row[0] for row in rows]

    def get_entry_index(self, receipt_id_hex: str) -> int | None:
        with self.lock:
            row = self.conn.execute(
                "SELECT entry_idx FROM ownership WHERE receipt_id = ?",
                (receipt_id_hex,),
            ).fetchone()
            return row[0] if row else None

    def get_transfer_history(self, receipt_id_hex: str) -> list[dict]:
        """Full transfer history for a receipt."""
        with self.lock:
            rows = self.conn.execute(
                """SELECT from_key, to_key, price, currency, timestamp
                   FROM entries WHERE receipt_id = ? ORDER BY idx""",
                (receipt_id_hex,),
            ).fetchall()
            return [
                {"from": r[0], "to": r[1], "price": r[2], "currency": r[3], "timestamp": r[4]}
                for r in rows
            ]

    def entry_count(self) -> int:
        with self.lock:
            row = self.conn.execute("SELECT COUNT(*) FROM entries").fetchone()
            return row[0]

    # ── Vouches ──

    def store_vouch(self, voucher_hex: str, vouchee_hex: str,
                    amount: int, timestamp: int, signature: bytes) -> bool:
        """Store a vouch. Returns True if new, False if duplicate."""
        with self.lock:
            existing = self.conn.execute(
                "SELECT 1 FROM vouches WHERE voucher = ? AND vouchee = ?",
                (voucher_hex, vouchee_hex),
            ).fetchone()
            if existing:
                return False

            self.conn.execute(
                "INSERT INTO vouches (voucher, vouchee, amount, timestamp, signature) VALUES (?, ?, ?, ?, ?)",
                (voucher_hex, vouchee_hex, amount, timestamp, signature),
            )
            self.conn.commit()
            return True

    def get_vouches_for(self, vouchee_hex: str) -> list[dict]:
        """Get all vouches for a specific operator."""
        with self.lock:
            rows = self.conn.execute(
                "SELECT voucher, amount, timestamp FROM vouches WHERE vouchee = ?",
                (vouchee_hex,),
            ).fetchall()
            return [
                {"voucher": r[0], "amount": r[1], "timestamp": r[2]}
                for r in rows
            ]

    def get_vouches_by(self, voucher_hex: str) -> list[dict]:
        """Get all vouches made by a specific operator."""
        with self.lock:
            rows = self.conn.execute(
                "SELECT vouchee, amount, timestamp FROM vouches WHERE voucher = ?",
                (voucher_hex,),
            ).fetchall()
            return [
                {"vouchee": r[0], "amount": r[1], "timestamp": r[2]}
                for r in rows
            ]

    def close(self):
        self.conn.close()
