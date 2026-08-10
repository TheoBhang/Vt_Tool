import os
from datetime import timedelta
from unittest import mock

import unittest

from init import Initializator
from app.services.analysis_service import AnalysisService
from app.services.misp_service import MispService
from app.FileHandler.output_to_file import OutputHandler
from app.cache_backends.sqlite_backend import SQLiteCacheBackend
from app.cache_backends.sqlalchemy_backend import SQLAlchemyCacheBackend


class InitializatorTests(unittest.TestCase):
    def setUp(self):
        self.init = Initializator("fake-api-key", proxy=None, case_num="000001")

    def tearDown(self):
        self.init.client.close()

    def test_wires_up_all_components(self):
        self.assertTrue(self.init.client)
        self.assertIsInstance(self.init.analysis, AnalysisService)
        self.assertIsInstance(self.init.misp, MispService)
        self.assertIsInstance(self.init.output, OutputHandler)

    def test_stores_constructor_args(self):
        self.assertEqual(self.init.api_key, "fake-api-key")
        self.assertIsNone(self.init.proxy)
        self.assertEqual(self.init.case_num, "000001")
        self.assertEqual(self.init.output.case_num, "000001")

    def test_analysis_service_is_wired_to_the_same_client(self):
        self.assertIs(self.init.analysis.virustotal.vt, self.init.client)

    def test_analysis_service_cache_uses_the_configured_database_file(self):
        self.assertEqual(self.init.analysis.cache.backend.db_path, "vttools.sqlite")

    def test_analysis_service_cache_uses_the_default_ttl(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("VT_CACHE_TTL_HOURS", None)
            init = Initializator("fake-api-key", proxy=None, case_num="000001")
            try:
                self.assertEqual(init.analysis.cache.ttl, timedelta(hours=24))
            finally:
                init.client.close()

    def test_analysis_service_cache_ttl_is_configurable_via_env_var(self):
        with mock.patch.dict(os.environ, {"VT_CACHE_TTL_HOURS": "1"}):
            init = Initializator("fake-api-key", proxy=None, case_num="000001")
            try:
                self.assertEqual(init.analysis.cache.ttl, timedelta(hours=1))
            finally:
                init.client.close()

    def test_uses_sqlite_backend_when_db_url_is_unset(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("VT_CACHE_DB_URL", None)
            init = Initializator("fake-api-key", proxy=None, case_num="000001")
            try:
                self.assertIsInstance(init.analysis.cache.backend, SQLiteCacheBackend)
            finally:
                init.client.close()

    def test_uses_sqlalchemy_backend_when_db_url_is_set(self):
        with mock.patch.dict(os.environ, {"VT_CACHE_DB_URL": "sqlite:///:memory:"}):
            init = Initializator("fake-api-key", proxy=None, case_num="000001")
            try:
                self.assertIsInstance(init.analysis.cache.backend, SQLAlchemyCacheBackend)
            finally:
                init.client.close()


if __name__ == "__main__":
    unittest.main()
