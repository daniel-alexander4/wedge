"""Pending sign-in state.

Every wedge sign-in is one :class:`RequestRecord` keyed by ``request_id``,
carrying the challenge and the single-use tokens that gate session minting.
Single-use is enforced structurally: :meth:`RequestStore.take_authenticated`
removes the record atomically, so no second session can ever be minted from
the same sign-in (spec §5.4, §8.3), and a challenge dies with its record.

:class:`MemoryStore` covers one process (dev, tests, single-worker servers).
Multi-worker deployments (``gunicorn -w N``) must share state across
processes — use :class:`SQLiteStore`, or implement :class:`RequestStore` over
storage you already share.
"""

from __future__ import annotations

import abc
import contextlib
import dataclasses
import sqlite3
import threading
import time

__all__ = ["RequestRecord", "RequestStore", "MemoryStore", "SQLiteStore"]


@dataclasses.dataclass
class RequestRecord:
    request_id: str
    challenge: str
    namespace: str
    username: str | None  # asserted at start (username-carrying core flow), else None
    browser_nonce: str | None  # browser-binding cookie value (core flow), else None
    claim_token: str | None  # single-use claim token (app-initiated flow), else None
    status: str  # "pending" | "authenticated" | "denied"
    authenticated_username: str | None  # the account that verified, set with "authenticated"
    expires_at: float  # epoch seconds


class RequestStore(abc.ABC):
    """Storage for pending sign-ins. Implementations must make
    ``set_authenticated`` and ``take_authenticated`` atomic across every
    process that shares the store — they are the single-use guarantees."""

    @abc.abstractmethod
    def put(self, record: RequestRecord) -> None:
        """Insert a new record (may also opportunistically prune expired ones)."""

    @abc.abstractmethod
    def get(self, request_id: str) -> RequestRecord | None:
        """Return the live record, or None if unknown or expired."""

    @abc.abstractmethod
    def set_authenticated(self, request_id: str, username: str) -> bool:
        """Atomically move a live record from "pending" to "authenticated",
        recording the verified account. False if it was not pending."""

    @abc.abstractmethod
    def take_authenticated(self, request_id: str) -> RequestRecord | None:
        """Atomically remove and return a live "authenticated" record. Returns
        None otherwise. At most one caller can ever receive a given record."""


class MemoryStore(RequestStore):
    """In-process store; thread-safe, not shared across processes."""

    def __init__(self) -> None:
        self._records: dict[str, RequestRecord] = {}
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        expired = [rid for rid, rec in self._records.items() if rec.expires_at <= now]
        for rid in expired:
            del self._records[rid]

    def put(self, record: RequestRecord) -> None:
        with self._lock:
            self._prune(time.time())
            self._records[record.request_id] = dataclasses.replace(record)

    def get(self, request_id: str) -> RequestRecord | None:
        with self._lock:
            self._prune(time.time())
            rec = self._records.get(request_id)
            return dataclasses.replace(rec) if rec else None

    def set_authenticated(self, request_id: str, username: str) -> bool:
        with self._lock:
            self._prune(time.time())
            rec = self._records.get(request_id)
            if rec is None or rec.status != "pending":
                return False
            rec.status = "authenticated"
            rec.authenticated_username = username
            return True

    def take_authenticated(self, request_id: str) -> RequestRecord | None:
        with self._lock:
            self._prune(time.time())
            rec = self._records.get(request_id)
            if rec is None or rec.status != "authenticated":
                return None
            del self._records[request_id]
            return rec


class SQLiteStore(RequestStore):
    """SQLite-backed store for multi-worker deployments on one host.

    Opens a short-lived connection per operation (safe across threads and
    forked workers) and relies on ``BEGIN IMMEDIATE`` transactions for the
    atomic state transitions. WAL mode keeps readers and writers from
    blocking each other.
    """

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS wedge_requests (
            request_id TEXT PRIMARY KEY,
            challenge TEXT NOT NULL,
            namespace TEXT NOT NULL,
            username TEXT,
            browser_nonce TEXT,
            claim_token TEXT,
            status TEXT NOT NULL,
            authenticated_username TEXT,
            expires_at REAL NOT NULL
        )
    """

    def __init__(self, path: str) -> None:
        self._path = path
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(self._SCHEMA)

    def _connect(self) -> contextlib.closing[sqlite3.Connection]:
        conn = sqlite3.connect(self._path, timeout=5.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return contextlib.closing(conn)

    @staticmethod
    def _record(row: sqlite3.Row) -> RequestRecord:
        return RequestRecord(**{key: row[key] for key in row.keys()})

    def put(self, record: RequestRecord) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM wedge_requests WHERE expires_at <= ?", (time.time(),))
            conn.execute(
                "INSERT OR REPLACE INTO wedge_requests VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    record.request_id,
                    record.challenge,
                    record.namespace,
                    record.username,
                    record.browser_nonce,
                    record.claim_token,
                    record.status,
                    record.authenticated_username,
                    record.expires_at,
                ),
            )

    def get(self, request_id: str) -> RequestRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM wedge_requests WHERE request_id = ? AND expires_at > ?",
                (request_id, time.time()),
            ).fetchone()
            return self._record(row) if row else None

    def set_authenticated(self, request_id: str, username: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE wedge_requests SET status='authenticated', authenticated_username=?"
                " WHERE request_id=? AND status='pending' AND expires_at > ?",
                (username, request_id, time.time()),
            )
            return cur.rowcount == 1

    def take_authenticated(self, request_id: str) -> RequestRecord | None:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT * FROM wedge_requests WHERE request_id = ?"
                    " AND status='authenticated' AND expires_at > ?",
                    (request_id, time.time()),
                ).fetchone()
                if row is None:
                    conn.execute("ROLLBACK")
                    return None
                conn.execute("DELETE FROM wedge_requests WHERE request_id = ?", (request_id,))
                conn.execute("COMMIT")
                return self._record(row)
            except BaseException:
                conn.execute("ROLLBACK")
                raise
