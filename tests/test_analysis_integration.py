import tempfile
import unittest
from unittest import mock

import vt_tools
from app.cache_backends.sqlite_backend import SQLiteCacheBackend
from app.services.analysis_service import AnalysisService
from app.services.cache_service import ReportCacheService
from app.services.validation_service import ValidationService
from app.services.virustotal_service import VirusTotalService


class AnalysisServiceIntegrationTests(unittest.TestCase):
    """Wires the real services together (mocking only the vt.Client, the
    actual external boundary) to catch shape mismatches no single service's
    mocked unit tests can see."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        self.tmp.close()
        self.vt_client = mock.Mock()
        self.service = AnalysisService(
            validation=ValidationService(),
            virustotal=VirusTotalService(self.vt_client),
            cache=ReportCacheService(SQLiteCacheBackend(self.tmp.name)),
        )

    def test_not_found_domain_produces_a_full_shaped_row_not_a_stub(self):
        # "nosuch.example" is rejected by DataValidator.validate_domain itself
        # (".example" is an RFC 2606 reserved TLD, not in the public suffix
        # list tldextract uses), which would raise ValidationError before ever
        # reaching VirusTotalService - unrelated to the bug under test. Use a
        # syntactically-ordinary domain instead so classify() succeeds and the
        # VT lookup is what returns not-found.
        self.vt_client.get_object.side_effect = Exception("NotFoundError raised by vt-py")

        report, from_cache = self.service.analyze("doesnotexist12345.org", "domains")

        self.assertFalse(from_cache)
        self.assertEqual(report["domain"], "doesnotexist12345.org")
        self.assertIn("ip", report)
        self.assertIn("creation_date", report)

    def test_batch_with_not_found_and_found_both_produce_full_rows_for_csv(self):
        found_report = mock.Mock()
        found_report.last_analysis_stats = {"malicious": 1, "harmless": 50}
        found_report.tags = []
        found_report.whois = ""
        found_report.port = None
        found_report.creation_date = "2020-01-01"
        found_report.reputation = 0
        found_report.last_analysis_results = {}
        found_report.last_dns_records = []
        found_report.last_https_certificate = ""
        found_report.registrar = ""

        self.vt_client.get_object.side_effect = [
            Exception("NotFoundError raised by vt-py"),
            found_report,
        ]

        not_found_report, _ = self.service.analyze("doesnotexist12345.org", "domains")
        found_result, _ = self.service.analyze("example.com", "domains")

        headers, rows = vt_tools.extract_table_data([not_found_report, found_result])

        self.assertEqual(len(rows[0]), len(headers))
        self.assertEqual(len(rows[1]), len(headers))


if __name__ == "__main__":
    unittest.main()
