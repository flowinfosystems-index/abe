"""Optional record stores. Default: none — the Gate returns the record to the caller and stores nothing.

All stores are append-only: save() refuses to overwrite an existing record_id.
Built in (stdlib only): MemoryStore, FileStore (JSON Lines), SQLiteStore, CallbackStore.
Optional: PostgresStore (psycopg 3), MongoStore (pymongo) — import from abe.stores.contrib.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from typing import Callable, Iterable

from ..canonical import canonical_json
from ..exceptions import RecordImmutableError
from ..models import Record


class RecordStore:
    def save(self, record: Record) -> None:
        raise NotImplementedError

    def get(self, record_id: str) -> Record | None:
        raise NotImplementedError

    def linked(self, root_record_id: str) -> list[Record]:
        """Every record whose root_record_id is root_record_id (including the root)."""
        raise NotImplementedError


class MemoryStore(RecordStore):
    def __init__(self):
        self._by_id: dict[str, Record] = {}
        self._lock = threading.Lock()

    def save(self, record):
        with self._lock:
            if record.record_id in self._by_id:
                raise RecordImmutableError(f"record {record.record_id} already exists")
            self._by_id[record.record_id] = record

    def get(self, record_id):
        return self._by_id.get(record_id)

    def linked(self, root_record_id):
        return [r for r in self._by_id.values() if r.get("root_record_id") == root_record_id]

    def all(self) -> list[Record]:
        return list(self._by_id.values())


class FileStore(RecordStore):
    """Append-only JSON Lines file. Suitable for a single process; use SQLite/Postgres for concurrency."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)

    def _iter(self) -> Iterable[dict]:
        if not os.path.exists(self.path):
            return
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def save(self, record):
        with self._lock:
            if self.get(record.record_id) is not None:
                raise RecordImmutableError(f"record {record.record_id} already exists")
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(canonical_json(record.to_dict()) + "\n")
                fh.flush()
                os.fsync(fh.fileno())

    def get(self, record_id):
        for d in self._iter():
            if d.get("record_id") == record_id:
                return Record.from_dict(d)
        return None

    def linked(self, root_record_id):
        return [Record.from_dict(d) for d in self._iter() if d.get("root_record_id") == root_record_id]


class SQLiteStore(RecordStore):
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        with self._conn:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS fjp_records (record_id TEXT PRIMARY KEY, root_record_id TEXT NOT NULL,"
                " timestamp TEXT NOT NULL, record_json TEXT NOT NULL)")
            self._conn.execute("CREATE INDEX IF NOT EXISTS fjp_records_root ON fjp_records(root_record_id)")
            # Enforce append-only at the database level too.
            self._conn.execute("CREATE TRIGGER IF NOT EXISTS fjp_records_no_update BEFORE UPDATE ON fjp_records "
                               "BEGIN SELECT RAISE(ABORT, 'FJP records are immutable'); END")
            self._conn.execute("CREATE TRIGGER IF NOT EXISTS fjp_records_no_delete BEFORE DELETE ON fjp_records "
                               "BEGIN SELECT RAISE(ABORT, 'FJP records are immutable'); END")

    def save(self, record):
        d = record.to_dict()
        with self._lock:
            try:
                with self._conn:
                    self._conn.execute("INSERT INTO fjp_records VALUES (?,?,?,?)",
                                       (d["record_id"], d["root_record_id"], d["timestamp"], canonical_json(d)))
            except sqlite3.IntegrityError as e:
                raise RecordImmutableError(f"record {d['record_id']} already exists") from e

    def get(self, record_id):
        with self._lock:
            row = self._conn.execute("SELECT record_json FROM fjp_records WHERE record_id=?", (record_id,)).fetchone()
        return Record.from_dict(json.loads(row[0])) if row else None

    def linked(self, root_record_id):
        with self._lock:
            rows = self._conn.execute("SELECT record_json FROM fjp_records WHERE root_record_id=? ORDER BY timestamp",
                                      (root_record_id,)).fetchall()
        return [Record.from_dict(json.loads(r[0])) for r in rows]

    def close(self):
        self._conn.close()


class CallbackStore(RecordStore):
    """Hands every record to your function (e.g. to ship to your SIEM or data lake). Write-only."""

    def __init__(self, fn: Callable[[dict], None]):
        self.fn = fn

    def save(self, record):
        self.fn(record.to_dict())

    def get(self, record_id):
        return None

    def linked(self, root_record_id):
        return []


def store_from_uri(uri: str | None) -> RecordStore | None:
    """memory: | file:path.jsonl | sqlite:path.db"""
    if not uri or uri == "none":
        return None
    if uri == "memory:" or uri == "memory":
        return MemoryStore()
    if uri.startswith("file:"):
        return FileStore(uri[5:])
    if uri.startswith("sqlite:"):
        return SQLiteStore(uri[7:])
    raise ValueError(f"unknown store {uri!r}; use memory:, file:<path.jsonl> or sqlite:<path.db>")


__all__ = ["RecordStore", "MemoryStore", "FileStore", "SQLiteStore", "CallbackStore", "store_from_uri"]
