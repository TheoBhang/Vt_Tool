import unittest
from unittest import mock

from app.VirusTotal.vt_reporter import VTReporter, NOT_FOUND_ERROR


class FakeReport:
    """Minimal stand-in for vt.Object: supports getattr() and .get()."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def get(self, key, default=None):
        return self.__dict__.get(key, default)


class CreateReportTests(unittest.TestCase):
    def test_unknown_value_type_returns_none(self):
        reporter = VTReporter(mock.Mock())
        self.assertIsNone(reporter.create_report("BOGUS", "x"))

    def test_not_found_error_returns_sentinel(self):
        vt_client = mock.Mock()
        vt_client.get_object.side_effect = Exception("NotFoundError raised by vt-py")
        reporter = VTReporter(vt_client)
        self.assertEqual(reporter.create_report("DOMAIN", "nosuch.example"), NOT_FOUND_ERROR)

    def test_other_errors_propagate(self):
        vt_client = mock.Mock()
        vt_client.get_object.side_effect = RuntimeError("network down")
        reporter = VTReporter(vt_client)
        with self.assertRaises(RuntimeError):
            reporter.create_report("DOMAIN", "example.com")


class GetReportIpTests(unittest.TestCase):
    def test_populates_ip_fields_from_report(self):
        with mock.patch("app.VirusTotal.vt_reporter.DBHandler") as MockDB:
            vt_client = mock.Mock()
            report = FakeReport(
                last_analysis_stats={"malicious": 2, "harmless": 60},
                tags=["t1", "t2"],
                as_owner="Google LLC",
                continent="NA",
                country="US",
                network="8.8.8.0/24",
                last_https_certificate="cert",
                regional_internet_registry="ARIN",
                asn=15169,
            )
            vt_client.get_object.return_value = report
            reporter = VTReporter(vt_client)

            result = reporter.get_report("PUBLIC IPV4", "8.8.8.8")

            csv_row = result["csv_report"][0]
            self.assertEqual(csv_row["malicious_score"], 2)
            self.assertEqual(csv_row["total_scans"], 62)
            self.assertEqual(csv_row["tags"], "t1, t2")
            self.assertEqual(csv_row["location"], "NA / US")
            self.assertEqual(csv_row["owner"], "Google LLC")
            self.assertTrue(MockDB.return_value.insert_ip_data.called)


class GetReportNotFoundTests(unittest.TestCase):
    def test_not_found_still_caches_an_empty_row(self):
        with mock.patch("app.VirusTotal.vt_reporter.DBHandler") as MockDB:
            vt_client = mock.Mock()
            vt_client.get_object.side_effect = Exception("NotFoundError")
            reporter = VTReporter(vt_client)

            result = reporter.get_report("DOMAIN", "nosuch.example")

            csv_row = result["csv_report"][0]
            self.assertEqual(csv_row["malicious_score"], 0)
            self.assertEqual(csv_row["tags"], "Not found")
            self.assertTrue(MockDB.return_value.insert_domain_data.called)


class GetReportHashThreatClassificationTests(unittest.TestCase):
    def test_populates_threat_category_and_labels_when_present(self):
        with mock.patch("app.VirusTotal.vt_reporter.DBHandler"):
            vt_client = mock.Mock()
            report = FakeReport(
                last_analysis_stats={"malicious": 40, "harmless": 20},
                tags=[],
                type_extension="exe", size=1024, md5="m", sha1="s1", sha256="s2",
                ssdeep="sd", tlsh="t", meaningful_name="n", names=["n1", "n2"],
                trid=[{"file_type": "Win32 EXE", "probability": "80.0%"}],
                popular_threat_classification={
                    "suggested_threat_label": "trojan.generic",
                    "popular_threat_category": [{"value": "trojan"}],
                },
            )
            vt_client.get_object.return_value = report
            reporter = VTReporter(vt_client)

            result = reporter.get_report("SHA-256", "a" * 64)

            csv_row = result["csv_report"][0]
            self.assertEqual(csv_row["threat_category"], "trojan")
            self.assertEqual(csv_row["threat_labels"], "trojan.generic")
            self.assertEqual(csv_row["type"], "Win32 EXE")

    def test_missing_classification_falls_back_to_not_found(self):
        with mock.patch("app.VirusTotal.vt_reporter.DBHandler"):
            vt_client = mock.Mock()
            report = FakeReport(
                last_analysis_stats={"malicious": 0, "harmless": 20},
                tags=[],
                type_extension="exe", size=1024, md5="m", sha1="s1", sha256="s2",
                ssdeep="sd", tlsh="t", meaningful_name="n", names=["n1"],
                # no `trid`, no `popular_threat_classification` attribute at all
            )
            vt_client.get_object.return_value = report
            reporter = VTReporter(vt_client)

            result = reporter.get_report("SHA-256", "b" * 64)

            csv_row = result["csv_report"][0]
            self.assertEqual(csv_row["threat_category"], "Not found")
            self.assertEqual(csv_row["threat_labels"], "Not found")
            self.assertEqual(csv_row["type"], "Not found")


if __name__ == "__main__":
    unittest.main()
