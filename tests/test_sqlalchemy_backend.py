import os
import tempfile
import unittest

import vt

from app.cache_backends.sqlalchemy_backend import SQLAlchemyCacheBackend


class SQLAlchemyCacheBackendTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        os.remove(self.db_path)  # backend creates it fresh
        self.backend = SQLAlchemyCacheBackend(f"sqlite:///{self.db_path}")

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

    def test_matches_the_cache_backend_tuple_contract(self):
        # ReportCacheService depends on the (dict, str) shape, not on which
        # backend produced it - confirm this backend honors it exactly like
        # SQLiteCacheBackend does.
        self.backend.set("URL", "http://example.com", {"url": "http://example.com"})
        result = self.backend.get("URL", "http://example.com")
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result[0], dict)
        self.assertIsInstance(result[1], str)


class SetWithRealVtObjectAttributesTests(unittest.TestCase):
    """Same regression class as tests/test_sqlite_backend.py's - a real
    vt.Object's attributes include datetime (any *_date field) and
    WhistleBlowerDict (any nested-dict field, a collections.UserDict, not a
    dict subclass), neither JSON-serializable by default. This backend uses
    the identical json.dumps(..., default=...) handling; this test exists so
    a copy-paste slip in that handling is caught here too, not just in the
    SQLite backend's own test file."""

    def test_set_does_not_raise_on_datetime_and_whistleblower_dict_fields(self):
        backend = SQLAlchemyCacheBackend("sqlite:///:memory:")
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


if __name__ == "__main__":
    unittest.main()
