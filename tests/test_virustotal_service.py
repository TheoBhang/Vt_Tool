import unittest
from unittest import mock

from app.errors import VirusTotalAPIError
from app.services.virustotal_service import VirusTotalService


class FakeReport:
    """Minimal stand-in for vt.Object: supports getattr() and .get()."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def get(self, key, default=None):
        return self.__dict__.get(key, default)


class CreateReportTests(unittest.TestCase):
    def test_unknown_value_type_returns_default_object(self):
        service = VirusTotalService(mock.Mock())
        result = service.get_report("BOGUS", "x")
        self.assertEqual(result["malicious_score"], "Not found")

    def test_not_found_returns_default_object_no_exception(self):
        vt_client = mock.Mock()
        vt_client.get_object.side_effect = Exception("NotFoundError raised by vt-py")
        service = VirusTotalService(vt_client)
        result = service.get_report("DOMAIN", "nosuch.example")
        self.assertEqual(result["malicious_score"], "Not found")
        self.assertEqual(result["tags"], "Not found")

    def test_other_errors_raise_virustotal_api_error(self):
        vt_client = mock.Mock()
        vt_client.get_object.side_effect = RuntimeError("network down")
        service = VirusTotalService(vt_client)
        with self.assertRaises(VirusTotalAPIError):
            service.get_report("DOMAIN", "example.com")


class GetReportIpTests(unittest.TestCase):
    def test_populates_ip_fields_from_report(self):
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
        service = VirusTotalService(vt_client)

        result = service.get_report("PUBLIC IPV4", "8.8.8.8")

        self.assertEqual(result["malicious_score"], 2)
        self.assertEqual(result["total_scans"], 62)
        self.assertEqual(result["tags"], "t1, t2")
        self.assertEqual(result["location"], "NA / US")
        self.assertEqual(result["owner"], "Google LLC")
        self.assertEqual(result["link"], "https://www.virustotal.com/gui/search/8.8.8.8")

    def test_does_not_write_to_a_database(self):
        # The one deliberate behavior change from VTReporter: no DB side effect.
        vt_client = mock.Mock()
        vt_client.get_object.return_value = FakeReport(
            last_analysis_stats={"malicious": 0, "harmless": 1}, tags=[],
            as_owner="x", continent="NA", country="US", network="n",
            last_https_certificate="c", regional_internet_registry="r", asn=1,
        )
        service = VirusTotalService(vt_client)
        self.assertFalse(hasattr(service, "insert_into_db"))
        self.assertFalse(hasattr(service, "db_handler"))


class GetReportHashThreatClassificationTests(unittest.TestCase):
    def test_populates_threat_category_and_labels_when_present(self):
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
        service = VirusTotalService(vt_client)

        result = service.get_report("SHA-256", "a" * 64)

        self.assertEqual(result["threat_category"], "trojan")
        self.assertEqual(result["threat_labels"], "trojan.generic")
        self.assertEqual(result["type"], "Win32 EXE")

    def test_missing_classification_falls_back_to_not_found(self):
        vt_client = mock.Mock()
        report = FakeReport(
            last_analysis_stats={"malicious": 0, "harmless": 20},
            tags=[],
            type_extension="exe", size=1024, md5="m", sha1="s1", sha256="s2",
            ssdeep="sd", tlsh="t", meaningful_name="n", names=["n1"],
        )
        vt_client.get_object.return_value = report
        service = VirusTotalService(vt_client)

        result = service.get_report("SHA-256", "b" * 64)

        self.assertEqual(result["threat_category"], "Not found")
        self.assertEqual(result["threat_labels"], "Not found")


if __name__ == "__main__":
    unittest.main()
