import tempfile
import threading
import time
import unittest
from pathlib import Path

from wedge_rp.store import MemoryStore, RequestRecord, SQLiteStore


def record(request_id="req1", status="pending", ttl=60.0, **overrides):
    fields = dict(
        request_id=request_id,
        challenge="AbCdEfGhIjKlMnOpQrStUvWx",
        namespace="http://127.0.0.1:9411",
        username=None,
        browser_nonce="nonce",
        claim_token=None,
        status=status,
        authenticated_username=None,
        expires_at=time.time() + ttl,
    )
    fields.update(overrides)
    return RequestRecord(**fields)


class StoreContract:
    """Behavior every RequestStore must satisfy; subclassed per implementation."""

    def make_store(self):
        raise NotImplementedError

    def setUp(self):
        self.store = self.make_store()

    def test_put_get_roundtrip(self):
        self.store.put(record())
        rec = self.store.get("req1")
        self.assertIsNotNone(rec)
        self.assertEqual(rec.challenge, "AbCdEfGhIjKlMnOpQrStUvWx")
        self.assertEqual(rec.status, "pending")

    def test_unknown_is_none(self):
        self.assertIsNone(self.store.get("nope"))

    def test_expired_is_none(self):
        self.store.put(record(ttl=-1.0))
        self.assertIsNone(self.store.get("req1"))

    def test_set_authenticated_only_from_pending(self):
        self.store.put(record())
        self.assertTrue(self.store.set_authenticated("req1", "alice"))
        self.assertFalse(self.store.set_authenticated("req1", "mallory"))
        rec = self.store.get("req1")
        self.assertEqual(rec.status, "authenticated")
        self.assertEqual(rec.authenticated_username, "alice")

    def test_set_authenticated_unknown_or_expired(self):
        self.assertFalse(self.store.set_authenticated("nope", "alice"))
        self.store.put(record(ttl=-1.0))
        self.assertFalse(self.store.set_authenticated("req1", "alice"))

    def test_take_requires_authenticated(self):
        self.store.put(record())
        self.assertIsNone(self.store.take_authenticated("req1"))
        self.store.set_authenticated("req1", "alice")
        taken = self.store.take_authenticated("req1")
        self.assertEqual(taken.authenticated_username, "alice")

    def test_take_is_single_use(self):
        self.store.put(record())
        self.store.set_authenticated("req1", "alice")
        self.assertIsNotNone(self.store.take_authenticated("req1"))
        self.assertIsNone(self.store.take_authenticated("req1"))
        self.assertIsNone(self.store.get("req1"))

    def test_take_race_has_exactly_one_winner(self):
        self.store.put(record())
        self.store.set_authenticated("req1", "alice")
        wins, barrier = [], threading.Barrier(8)

        def contender():
            barrier.wait()
            if self.store.take_authenticated("req1") is not None:
                wins.append(1)

        threads = [threading.Thread(target=contender) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(wins), 1)


class MemoryStoreTest(StoreContract, unittest.TestCase):
    def make_store(self):
        return MemoryStore()


class SQLiteStoreTest(StoreContract, unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory(prefix="wedge-rp-test-")
        self.addCleanup(self._dir.cleanup)
        super().setUp()

    def make_store(self):
        return SQLiteStore(str(Path(self._dir.name) / "store.db"))

    def test_state_is_shared_across_instances(self):
        # Two store objects on one path model two gunicorn workers.
        path = str(Path(self._dir.name) / "shared.db")
        worker_a, worker_b = SQLiteStore(path), SQLiteStore(path)
        worker_a.put(record())
        self.assertIsNotNone(worker_b.get("req1"))
        self.assertTrue(worker_b.set_authenticated("req1", "alice"))
        taken = worker_a.take_authenticated("req1")
        self.assertEqual(taken.authenticated_username, "alice")
        self.assertIsNone(worker_b.take_authenticated("req1"))


if __name__ == "__main__":
    unittest.main()
