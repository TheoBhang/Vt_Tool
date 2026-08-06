import unittest
from unittest import mock

import vt_tools


class CountIocsTests(unittest.TestCase):
    def test_sums_list_lengths(self):
        self.assertEqual(
            vt_tools.count_iocs({"ips": ["a", "b"], "domains": ["c"]}), 3
        )

    def test_rejects_non_dict(self):
        with self.assertRaises(TypeError):
            vt_tools.count_iocs(["not", "a", "dict"])


class ExtractTableDataTests(unittest.TestCase):
    def test_headers_are_the_union_of_all_results(self):
        results = [
            {"csv_report": [{"ip": "8.8.8.8", "malicious_score": 0}]},
            {"csv_report": [{"ip": "1.1.1.1", "malicious_score": 5, "extra": "x"}]},
        ]
        headers, rows = vt_tools.extract_table_data(results)
        self.assertEqual(set(headers), {"ip", "malicious_score", "extra"})

    def test_rows_are_fully_populated_with_final_headers(self):
        results = [
            {"csv_report": [{"ip": "8.8.8.8", "malicious_score": 0}]},
            {"csv_report": [{"ip": "1.1.1.1", "malicious_score": 5, "extra": "x"}]},
        ]
        headers, rows = vt_tools.extract_table_data(results)
        self.assertEqual(len(rows[0]), len(headers))
        self.assertEqual(len(rows[1]), len(headers))
        row0 = dict(zip(headers, rows[0]))
        row1 = dict(zip(headers, rows[1]))
        self.assertEqual(row0["ip"], "8.8.8.8")
        self.assertEqual(row0["extra"], "")
        self.assertEqual(row1["extra"], "x")


class GetRemainingQuotaTests(unittest.TestCase):
    def test_computes_remaining_from_allowed_and_used(self):
        class FakeResponse:
            status_code = 200

            def raise_for_status(self):
                pass

            def json(self):
                return {"data": {"api_requests_hourly": {"user": {"allowed": 500, "used": 120}}}}

        class FakeSession:
            def __enter__(self):
                return self

            def __exit__(self, *exc_info):
                return False

            def __init__(self):
                self.proxies = {}

            def get(self, url, headers=None):
                return FakeResponse()

        with mock.patch("vt_tools.requests.Session", return_value=FakeSession()):
            self.assertEqual(vt_tools.get_remaining_quota("key", None, None), 380)

    def test_returns_zero_on_request_exception(self):
        import requests

        class FailingSession:
            def __enter__(self):
                return self

            def __exit__(self, *exc_info):
                return False

            def __init__(self):
                self.proxies = {}

            def get(self, url, headers=None):
                raise requests.exceptions.RequestException("network down")

        with mock.patch("vt_tools.requests.Session", return_value=FailingSession()):
            self.assertEqual(vt_tools.get_remaining_quota("key", None, None), 0)


class ValueExistsTests(unittest.TestCase):
    def test_hashes_uses_singular_hash_column(self):
        init = mock.Mock()
        vt_tools.value_exists(init, "somehash", "hashes", conn=None)
        init.db_handler.exists.assert_called_once_with(None, "hashes", "somehash", "hash")

    def test_ips_unwraps_tuple_and_uses_ip_column(self):
        init = mock.Mock()
        vt_tools.value_exists(init, ("8.8.8.8", "443"), "ips", conn=None)
        init.db_handler.exists.assert_called_once_with(None, "ips", "8.8.8.8", "ip")

    def test_domains_uses_singular_domain_column(self):
        init = mock.Mock()
        vt_tools.value_exists(init, "example.com", "domains", conn=None)
        init.db_handler.exists.assert_called_once_with(None, "domains", "example.com", "domain")


class ValidateValueTests(unittest.TestCase):
    def test_hashes_calls_validate_hash(self):
        init = mock.Mock()
        init.validator.validate_hash.return_value = "MD5"
        result = vt_tools.validate_value(init, "a" * 32, "hashes")
        init.validator.validate_hash.assert_called_once_with("a" * 32)
        self.assertEqual(result, "MD5")

    def test_other_types_call_matching_validate_method(self):
        init = mock.Mock()
        init.validator.validate_domain.return_value = "DOMAIN"
        result = vt_tools.validate_value(init, "example.com", "domains")
        init.validator.validate_domain.assert_called_once_with("example.com")
        self.assertEqual(result, "DOMAIN")

    def test_missing_validator_method_returns_empty_string(self):
        init = mock.Mock(spec=["validator"])
        init.validator = mock.Mock(spec=[])  # no validate_domain attribute at all
        result = vt_tools.validate_value(init, "example.com", "domains")
        self.assertEqual(result, "")


if __name__ == "__main__":
    unittest.main()
