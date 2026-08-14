import os
import unittest
from datetime import timedelta
from unittest import mock

from app.cache_backends.sqlalchemy_backend import SQLAlchemyCacheBackend
from app.cache_backends.sqlite_backend import SQLiteCacheBackend
from app.services.cache_config import build_cache_service


class BuildCacheServiceTests(unittest.TestCase):
    def setUp(self):
        self._env_patcher = mock.patch.dict(os.environ)
        self._env_patcher.start()
        os.environ.pop("VT_CACHE_DB_URL", None)
        os.environ.pop("VT_CACHE_TTL_HOURS", None)

    def tearDown(self):
        self._env_patcher.stop()

    def test_uses_sqlite_backend_by_default(self):
        service = build_cache_service()
        try:
            self.assertIsInstance(service.backend, SQLiteCacheBackend)
            self.assertEqual(service.backend.db_path, "vttools.sqlite")
        finally:
            service.backend.close()

    def test_uses_sqlalchemy_backend_when_db_url_is_set(self):
        os.environ["VT_CACHE_DB_URL"] = "sqlite:///:memory:"
        service = build_cache_service()
        try:
            self.assertIsInstance(service.backend, SQLAlchemyCacheBackend)
        finally:
            service.backend.close()

    def test_default_ttl_is_zero_hours(self):
        service = build_cache_service()
        try:
            self.assertEqual(service.ttl, timedelta(hours=0))
        finally:
            service.backend.close()

    def test_ttl_is_configurable_via_env_var(self):
        os.environ["VT_CACHE_TTL_HOURS"] = "1"
        service = build_cache_service()
        try:
            self.assertEqual(service.ttl, timedelta(hours=1))
        finally:
            service.backend.close()

    def test_empty_string_ttl_env_var_falls_back_to_default(self):
        # Regression test: a .env file with a blank `VT_CACHE_TTL_HOURS=` line
        # (as ships in .env.example) sets the var to "" rather than leaving it
        # unset - os.getenv's two-arg form then returns "" instead of the
        # default, and float("") used to raise ValueError.
        os.environ["VT_CACHE_TTL_HOURS"] = ""
        service = build_cache_service()
        try:
            self.assertEqual(service.ttl, timedelta(hours=0))
        finally:
            service.backend.close()


if __name__ == "__main__":
    unittest.main()
