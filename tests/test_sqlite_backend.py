import os
import sqlite3
import tempfile
import unittest

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

    def test_set_then_get_round_trips_the_report(self):
        report = {"domain": "example.com", "malicious_score": 3, "tags": "phishing"}
        self.backend.set("DOMAIN", "example.com", report)
        self.assertEqual(self.backend.get("DOMAIN", "example.com"), report)

    def test_set_twice_updates_instead_of_duplicating(self):
        self.backend.set("DOMAIN", "example.com", {"malicious_score": 1})
        self.backend.set("DOMAIN", "example.com", {"malicious_score": 9})
        self.assertEqual(self.backend.get("DOMAIN", "example.com"), {"malicious_score": 9})

        conn = sqlite3.connect(self.db_path)
        count = conn.execute(
            "SELECT COUNT(*) FROM cached_reports WHERE value_type = ? AND value = ?",
            ("DOMAIN", "example.com"),
        ).fetchone()[0]
        conn.close()
        self.assertEqual(count, 1)

    def test_same_value_different_type_is_a_separate_entry(self):
        self.backend.set("DOMAIN", "8.8.8.8", {"kind": "domain-shaped"})
        self.backend.set("PUBLIC IPV4", "8.8.8.8", {"kind": "ip-shaped"})
        self.assertEqual(self.backend.get("DOMAIN", "8.8.8.8"), {"kind": "domain-shaped"})
        self.assertEqual(self.backend.get("PUBLIC IPV4", "8.8.8.8"), {"kind": "ip-shaped"})

    def test_cached_at_column_is_populated(self):
        self.backend.set("DOMAIN", "example.com", {"a": 1})
        conn = sqlite3.connect(self.db_path)
        cached_at = conn.execute(
            "SELECT cached_at FROM cached_reports WHERE value_type = ? AND value = ?",
            ("DOMAIN", "example.com"),
        ).fetchone()[0]
        conn.close()
        self.assertIsNotNone(cached_at)
        self.assertNotEqual(cached_at, "")


if __name__ == "__main__":
    unittest.main()
