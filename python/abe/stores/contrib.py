"""Optional database adapters. Drivers are imported lazily and are not dependencies of abe-ai.

    pip install "psycopg[binary]>=3"   # PostgresStore
    pip install "pymongo>=4"           # MongoStore
"""
from __future__ import annotations

import json

from ..canonical import canonical_json
from ..exceptions import RecordImmutableError
from ..models import Record
from . import RecordStore


class PostgresStore(RecordStore):
    """Append-only table. Pass a psycopg 3 connection (autocommit recommended) or a DSN string."""

    def __init__(self, conn_or_dsn, table: str = "fjp_records"):
        if not table.replace("_", "").isalnum():
            raise ValueError("table name must be alphanumeric/underscore")
        if isinstance(conn_or_dsn, str):
            import psycopg  # noqa: PLC0415
            conn_or_dsn = psycopg.connect(conn_or_dsn, autocommit=True)
        self.conn, self.table = conn_or_dsn, table
        with self.conn.cursor() as cur:
            cur.execute(f"CREATE TABLE IF NOT EXISTS {table} (record_id TEXT PRIMARY KEY, root_record_id TEXT NOT NULL,"
                        f" ts TEXT NOT NULL, record JSONB NOT NULL, record_canonical TEXT NOT NULL)")
            cur.execute(f"CREATE INDEX IF NOT EXISTS {table}_root ON {table}(root_record_id)")

    def save(self, record):
        d = record.to_dict()
        with self.conn.cursor() as cur:
            cur.execute(f"INSERT INTO {self.table} VALUES (%s,%s,%s,%s::jsonb,%s) ON CONFLICT (record_id) DO NOTHING",
                        (d["record_id"], d["root_record_id"], d["timestamp"], json.dumps(d), canonical_json(d)))
            if cur.rowcount == 0:
                raise RecordImmutableError(f"record {d['record_id']} already exists")

    def get(self, record_id):
        with self.conn.cursor() as cur:
            cur.execute(f"SELECT record_canonical FROM {self.table} WHERE record_id=%s", (record_id,))
            row = cur.fetchone()
        return Record.from_dict(json.loads(row[0])) if row else None

    def linked(self, root_record_id):
        with self.conn.cursor() as cur:
            cur.execute(f"SELECT record_canonical FROM {self.table} WHERE root_record_id=%s ORDER BY ts",
                        (root_record_id,))
            rows = cur.fetchall()
        return [Record.from_dict(json.loads(r[0])) for r in rows]


class MongoStore(RecordStore):
    """Pass a pymongo Collection. Uses a unique index on record_id; inserts only.

    Stores the canonical JSON alongside the document so hashes verify exactly after a round trip
    (BSON would otherwise turn integral floats into ints or reorder nothing — but we don't rely on it).
    """

    def __init__(self, collection):
        self.col = collection
        self.col.create_index("record_id", unique=True)
        self.col.create_index("root_record_id")

    def save(self, record):
        d = record.to_dict()
        try:
            self.col.insert_one({"record_id": d["record_id"], "root_record_id": d["root_record_id"],
                                 "timestamp": d["timestamp"], "record": d, "record_canonical": canonical_json(d)})
        except Exception as e:  # pymongo.errors.DuplicateKeyError without importing pymongo
            if type(e).__name__ == "DuplicateKeyError":
                raise RecordImmutableError(f"record {d['record_id']} already exists") from e
            raise

    def get(self, record_id):
        doc = self.col.find_one({"record_id": record_id}, {"record_canonical": 1})
        return Record.from_dict(json.loads(doc["record_canonical"])) if doc else None

    def linked(self, root_record_id):
        docs = self.col.find({"root_record_id": root_record_id}, {"record_canonical": 1}).sort("timestamp", 1)
        return [Record.from_dict(json.loads(d["record_canonical"])) for d in docs]
