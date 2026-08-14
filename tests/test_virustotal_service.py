import unittest
from unittest import mock

from vt import APIError

from app.DataHandler.validator import get_service_name
from app.errors import VirusTotalAPIError
from app.services.virustotal_service import VirusTotalService


class FakeReport:
    """Minimal stand-in for vt.Object: supports getattr() and .get()."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def get(self, key, default=None):
        return self.__dict__.get(key, default)


class CreateReportTests(unittest.TestCase):
    def test_unknown_value_type_raises(self):
        service = VirusTotalService(mock.Mock())
        with self.assertRaises(VirusTotalAPIError):
            service.get_report("BOGUS", "x")

    def test_not_found_returns_default_object_no_exception(self):
        vt_client = mock.Mock()
        vt_client.get_object.side_effect = APIError("NotFoundError", "not found")
        service = VirusTotalService(vt_client)
        result = service.get_report("DOMAIN", "nosuch.example")
        self.assertEqual(result["malicious_score"], 0)
        self.assertEqual(result["tags"], "Not found")
        self.assertEqual(result["domain"], "nosuch.example")
        self.assertEqual(result["total_scans"], 0)

    def test_other_errors_raise_virustotal_api_error(self):
        vt_client = mock.Mock()
        vt_client.get_object.side_effect = RuntimeError("network down")
        service = VirusTotalService(vt_client)
        with self.assertRaises(VirusTotalAPIError):
            service.get_report("DOMAIN", "example.com")

    def test_error_message_mentioning_not_found_is_not_miscategorized(self):
        # Regression test: not-found detection used to substring-match
        # "NotFoundError" in str(e) - a transient error whose message merely
        # mentions that string (without actually being a not-found response)
        # would be miscategorized as "not found" and cached as a synthetic
        # 0-malicious/0-scans result instead of surfacing the real failure.
        vt_client = mock.Mock()
        vt_client.get_object.side_effect = APIError(
            "QuotaExceededError", "proxy relayed a NotFoundError from a different upstream"
        )
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

    def test_populates_port_protocol_network_certificate_and_info_ip(self):
        vt_client = mock.Mock()
        report = FakeReport(
            last_analysis_stats={"malicious": 0, "harmless": 60},
            tags=[],
            as_owner="Google LLC",
            continent="NA",
            country="US",
            network="8.8.8.0/24",
            last_https_certificate="cert-data",
            regional_internet_registry="ARIN",
            asn=15169,
        )
        vt_client.get_object.return_value = report
        service = VirusTotalService(vt_client)

        result = service.get_report("PUBLIC IPV4", ("8.8.8.8", 443))

        self.assertEqual(result["port"], 443)
        self.assertEqual(result["protocol"], get_service_name(443))
        self.assertEqual(result["network"], "8.8.8.0/24")
        self.assertEqual(result["https_certificate"], "cert-data")
        self.assertEqual(result["info-ip"]["regional_internet_registry"], "ARIN")
        self.assertEqual(result["info-ip"]["asn"], 15169)

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
        self.assertEqual(result["type_probability"], "80.0%")
        self.assertEqual(result["extension"], "exe")
        self.assertEqual(result["size"], 1024)
        self.assertEqual(result["md5"], "m")
        self.assertEqual(result["sha1"], "s1")
        self.assertEqual(result["sha256"], "s2")
        self.assertEqual(result["ssdeep"], "sd")
        self.assertEqual(result["tlsh"], "t")
        self.assertEqual(result["meaningful_name"], "n")
        self.assertEqual(result["names"], "n1, n2")

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


class GetReportDomainTests(unittest.TestCase):
    def test_populates_domain_fields_from_report(self):
        vt_client = mock.Mock()
        report = FakeReport(
            last_analysis_stats={"malicious": 1, "harmless": 50},
            tags=["phishing"],
            whois="Registrar: Example\nIP Address: 93.184.216.34\nCreation Date: 2000-01-01",
            port=80,
            creation_date="2000-01-01T00:00:00",
            reputation=5,
            last_analysis_results={"Vendor1": {"category": "harmless"}},
            last_dns_records=[{"type": "A", "value": "93.184.216.34"}],
            last_https_certificate="cert-data",
            registrar="Example Registrar",
        )
        vt_client.get_object.return_value = report
        service = VirusTotalService(vt_client)

        result = service.get_report("DOMAIN", "example.com")

        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["ip"], "93.184.216.34")
        self.assertEqual(result["port"], 80)
        self.assertEqual(result["protocol"], get_service_name(80))
        self.assertEqual(result["creation_date"], "2000-01-01T00:00:00")
        self.assertEqual(result["reputation"], 5)
        self.assertEqual(result["whois"], report.whois)
        self.assertEqual(result["info"]["registrar"], "Example Registrar")


class GetReportUrlTests(unittest.TestCase):
    def test_populates_url_fields_from_report(self):
        vt_client = mock.Mock()
        report = FakeReport(
            last_analysis_stats={"malicious": 3, "harmless": 70},
            tags=["suspicious"],
            first_submission_date="2023-01-15T10:30:00",
            ip_address="93.184.216.34",
            title="Example Domain",
            last_final_url="https://sub.example.com/path?x=1",
            html_meta={"description": "example"},
            targeted_brand={"some": "brand"},
            outgoing_links=["https://sub.example.com/other"],
            redirection_chain=["https://sub.example.com/path?x=1"],
            trackers={"Google Analytics": []},
        )
        vt_client.get_object.return_value = report
        service = VirusTotalService(vt_client)

        result = service.get_report("URL", "https://sub.example.com/path?x=1")

        self.assertEqual(result["url"], "https://sub.example.com/path?x=1")
        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["tld"], "com")
        self.assertEqual(result["subdomain"], "sub")
        self.assertEqual(result["scheme"], "https")
        self.assertEqual(result["resource_path"], "/path")
        self.assertEqual(result["query_strings"], "x=1")
        self.assertEqual(result["ip"], "93.184.216.34")
        self.assertEqual(result["title"], "Example Domain")
        self.assertEqual(result["final_url"], "https://sub.example.com/path?x=1")
        self.assertNotEqual(result["first_scan"], "Not found")


if __name__ == "__main__":
    unittest.main()
