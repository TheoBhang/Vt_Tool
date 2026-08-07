import unittest
from unittest import mock

import vt_tools
from app import errors as errors_module


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
            {"ip": "8.8.8.8", "malicious_score": 0},
            {"ip": "1.1.1.1", "malicious_score": 5, "extra": "x"},
        ]
        headers, rows = vt_tools.extract_table_data(results)
        self.assertEqual(set(headers), {"ip", "malicious_score", "extra"})

    def test_rows_are_fully_populated_with_final_headers(self):
        results = [
            {"ip": "8.8.8.8", "malicious_score": 0},
            {"ip": "1.1.1.1", "malicious_score": 5, "extra": "x"},
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


class AnalyzeSingleValueTests(unittest.TestCase):
    def test_cache_hit_reports_one_skipped_value(self):
        init = mock.Mock()
        init.analysis.analyze.return_value = ({"malicious_score": 1}, True)
        results, skipped, errors = vt_tools.analyze_single_value(init, "domains", "example.com")
        self.assertEqual(results, [{"malicious_score": 1}])
        self.assertEqual(skipped, 1)
        self.assertEqual(errors, 0)

    def test_cache_miss_reports_zero_skipped(self):
        init = mock.Mock()
        init.analysis.analyze.return_value = ({"malicious_score": 9}, False)
        results, skipped, errors = vt_tools.analyze_single_value(init, "domains", "example.com")
        self.assertEqual(results, [{"malicious_score": 9}])
        self.assertEqual(skipped, 0)
        self.assertEqual(errors, 0)

    def test_validation_error_counts_as_one_error_no_results(self):
        init = mock.Mock()
        init.analysis.analyze.side_effect = errors_module.ValidationError("invalid")
        results, skipped, errs = vt_tools.analyze_single_value(init, "domains", "not-a-domain")
        self.assertEqual(results, [])
        self.assertEqual(skipped, 0)
        self.assertEqual(errs, 1)

    def test_virustotal_api_error_counts_as_one_error_no_results(self):
        init = mock.Mock()
        init.analysis.analyze.side_effect = errors_module.VirusTotalAPIError("network down")
        results, skipped, errs = vt_tools.analyze_single_value(init, "domains", "example.com")
        self.assertEqual(results, [])
        self.assertEqual(skipped, 0)
        self.assertEqual(errs, 1)


if __name__ == "__main__":
    unittest.main()
