import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

import vt

from app.cache_backends.sqlite_backend import SQLiteCacheBackend


class SQLiteCacheBackendTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        os.remove(self.db_path)  # backend creates it fresh
        self.backend = SQLiteCacheBackend(self.db_path)

    def tearDown(self):
        self.backend.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_get_returns_none_when_absent(self):
        self.assertIsNone(self.backend.get("DOMAIN", "example.com"))

    def test_set_then_get_round_trips_the_report_and_cached_at(self):
        report = {"domain": "example.com", "malicious_score": 3, "tags": "phishing"}
        self.backend.set("DOMAIN", "example.com", report)
        result_report, cached_at = self.backend.get("DOMAIN", "example.com")
        self.assertEqual(result_report, report)
        self.assertIsInstance(cached_at, str)
        self.assertNotEqual(cached_at, "")

    def test_set_twice_updates_instead_of_duplicating(self):
        self.backend.set("DOMAIN", "example.com", {"malicious_score": 1})
        self.backend.set("DOMAIN", "example.com", {"malicious_score": 9})
        report, _ = self.backend.get("DOMAIN", "example.com")
        self.assertEqual(report, {"malicious_score": 9})

        conn = sqlite3.connect(self.db_path)
        count = conn.execute(
            "SELECT COUNT(*) FROM cached_reports WHERE value_type = ? AND value = ?",
            ("DOMAIN", "example.com"),
        ).fetchone()[0]
        conn.close()
        self.assertEqual(count, 1)

    def test_set_twice_refreshes_cached_at(self):
        self.backend.set("DOMAIN", "example.com", {"malicious_score": 1})
        _, first_cached_at = self.backend.get("DOMAIN", "example.com")
        self.backend.set("DOMAIN", "example.com", {"malicious_score": 9})
        _, second_cached_at = self.backend.get("DOMAIN", "example.com")
        self.assertGreaterEqual(second_cached_at, first_cached_at)

    def test_same_value_different_type_is_a_separate_entry(self):
        self.backend.set("DOMAIN", "8.8.8.8", {"kind": "domain-shaped"})
        self.backend.set("PUBLIC IPV4", "8.8.8.8", {"kind": "ip-shaped"})
        domain_report, _ = self.backend.get("DOMAIN", "8.8.8.8")
        ip_report, _ = self.backend.get("PUBLIC IPV4", "8.8.8.8")
        self.assertEqual(domain_report, {"kind": "domain-shaped"})
        self.assertEqual(ip_report, {"kind": "ip-shaped"})


class SetWithRealVtObjectAttributesTests(unittest.TestCase):
    """A real vt.Object's attributes include datetime (any *_date field) and
    WhistleBlowerDict (any nested-dict field, a collections.UserDict, not a
    dict subclass) - neither is JSON-serializable by default. Regression
    test for the bug this caused: an uncaught TypeError on the first
    cache write for any found domain/IP/URL value."""

    def test_set_does_not_raise_on_datetime_and_whistleblower_dict_fields(self):
        backend = SQLiteCacheBackend(":memory:")
        vt_object = vt.Object.from_dict({
            "type": "domain",
            "id": "example.com",
            "attributes": {
                "creation_date": 1000000000,  # becomes a real datetime on read
                "last_https_certificate": {"thumbprint": "abc123"},  # becomes a WhistleBlowerDict
            },
        })
        report = {
            "domain": "example.com",
            "creation_date": vt_object.creation_date,
            "https_certificate": vt_object.last_https_certificate,
        }

        backend.set("domains", "example.com", report)
        result, cached_at = backend.get("domains", "example.com")

        self.assertEqual(result["domain"], "example.com")
        self.assertIsInstance(result["creation_date"], str)
        self.assertEqual(result["https_certificate"], {"thumbprint": "abc123"})
        self.assertIsInstance(cached_at, str)


class ThreadSafetyTests(unittest.TestCase):
    """SQLiteCacheBackend.get()/set() must be safe to call concurrently from
    multiple threads - the worker (Task 2) runs each job's cache access inside
    a thread pool executor, and arq runs multiple jobs concurrently within one
    worker process by default."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        os.remove(self.db_path)
        self.backend = SQLiteCacheBackend(self.db_path)

    def tearDown(self):
        self.backend.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_concurrent_set_and_get_from_multiple_threads_does_not_raise(self):
        errors = []

        def write_and_read(i):
            try:
                self.backend.set("domains", f"value{i % 5}.com", {"malicious_score": i})
                self.backend.get("domains", f"value{i % 5}.com")
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=10) as executor:
            list(executor.map(write_and_read, range(50)))

        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
