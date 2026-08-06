import csv
import os
import tempfile
import unittest
from unittest import mock

from app.MISP.vt_tools2misp import (
    process_csv_file,
    get_attribute_mapping,
    load_template,
    apply_template_data,
    create_misp_object,
    identify_object_type,
    misp_choice,
)


class ProcessCsvFileTests(unittest.TestCase):
    def test_reads_rows_as_dicts(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "test.csv")
            with open(path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["ip", "malicious_score", "link"])
                writer.writeheader()
                writer.writerow({"ip": "8.8.8.8", "malicious_score": "0", "link": "http://x"})
            rows = process_csv_file(path)
        self.assertEqual(rows, [{"ip": "8.8.8.8", "malicious_score": "0", "link": "http://x"}])

    def test_missing_file_returns_empty_list(self):
        self.assertEqual(process_csv_file("/nonexistent/file.csv"), [])


class GetAttributeMappingTests(unittest.TestCase):
    def test_maps_known_headers(self):
        mapping = {"ip": ("ip", "ip-dst", "Network activity", False)}
        result = get_attribute_mapping(["ip", "unrelated"], mapping)
        self.assertEqual(result, {"ip": ("ip", "ip-dst", "Network activity", False)})

    def test_raises_when_no_headers_match(self):
        mapping = {"ip": ("ip", "ip-dst", "Network activity", False)}
        with self.assertRaises(ValueError):
            get_attribute_mapping(["nope"], mapping)


class LoadTemplateTests(unittest.TestCase):
    def test_parses_template_rows_keyed_by_value(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "template.csv")
            with open(path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["value", "comment", "tag1"])
                writer.writerow(["8.8.8.8", "test comment", "tlp:green"])
            template = load_template(path)
        self.assertEqual(
            template, {"8.8.8.8": {"comment": ["test comment"], "tag1": ["tlp:green"]}}
        )

    def test_missing_value_column_returns_empty_dict(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "template.csv")
            with open(path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["not_value", "comment"])
                writer.writerow(["x", "y"])
            self.assertEqual(load_template(path), {})

    def test_missing_file_returns_empty_dict(self):
        self.assertEqual(load_template("/nonexistent/template.csv"), {})


class ApplyTemplateDataTests(unittest.TestCase):
    def test_merges_matching_template_row_into_data(self):
        data = [{"ip": "8.8.8.8", "malicious_score": "0"}]
        template = {"8.8.8.8": {"comment": ["hi"], "tag1": ["tlp:green"]}}
        apply_template_data(data, template, "ip")
        self.assertEqual(
            data, [{"ip": "8.8.8.8", "malicious_score": "0", "comment": "hi", "tag1": "tlp:green"}]
        )

    def test_no_match_leaves_row_unchanged(self):
        data = [{"ip": "1.1.1.1", "malicious_score": "0"}]
        apply_template_data(data, {"8.8.8.8": {"comment": ["hi"]}}, "ip")
        self.assertEqual(data, [{"ip": "1.1.1.1", "malicious_score": "0"}])


class CreateMispObjectTests(unittest.TestCase):
    def test_builds_object_with_mapped_attributes(self):
        row = {"ip": "8.8.8.8", "malicious_score": "Not found", "comment": "hi"}
        attribute_mapping = {
            "ip": ("ip", "ip-dst", "Network activity", False),
            "malicious_score": ("malicious_score", "text", "Antivirus detection", False),
        }
        obj = create_misp_object(row, "ip-port", attribute_mapping)
        self.assertEqual(obj.name, "ip-port")
        self.assertEqual(obj.comment, "hi")
        # "Not found" sentinel values are skipped, so only "ip" is added.
        self.assertEqual(len(obj.attributes), 1)
        self.assertEqual(obj.attributes[0].type, "ip-dst")
        self.assertEqual(obj.attributes[0].value, "8.8.8.8")
        self.assertTrue(obj.attributes[0].to_ids)

    def test_incomplete_mapping_returns_none(self):
        row = {"ip": "8.8.8.8"}
        attribute_mapping = {"ip": ("ip", "ip-dst", "Network activity")}  # missing 4th element
        self.assertIsNone(create_misp_object(row, "ip-port", attribute_mapping))


class IdentifyObjectTypeTests(unittest.TestCase):
    def test_matches_known_patterns_case_insensitively(self):
        self.assertEqual(identify_object_type("000001_Hashes_Analysis_x.csv"), "file")
        self.assertEqual(identify_object_type("000001_URL_Analysis_x.csv"), "url")
        self.assertEqual(identify_object_type("000001_IP_Analysis_x.csv"), "ip-port")
        self.assertEqual(identify_object_type("000001_Domains_Analysis_x.csv"), "domain-ip")
        # Test with lowercase to verify re.IGNORECASE is actually needed
        self.assertEqual(identify_object_type("000001_hashes_analysis_x.csv"), "file")

    def test_unknown_filename_raises(self):
        with self.assertRaises(ValueError):
            identify_object_type("unrelated_file.csv")


class MispChoiceTests(unittest.TestCase):
    def test_yes_calls_misp_event_with_case_and_files(self):
        with mock.patch("app.MISP.vt_tools2misp.misp_event") as mock_event:
            with mock.patch("app.MISP.vt_tools2misp.Prompt.ask", return_value="y"):
                misp_choice("123456", ["a.csv"])
        mock_event.assert_called_once_with("123456", ["a.csv"], None, None)

    def test_yes_passes_through_template_file_and_template(self):
        with mock.patch("app.MISP.vt_tools2misp.misp_event") as mock_event:
            with mock.patch("app.MISP.vt_tools2misp.Prompt.ask", return_value="1"):
                misp_choice("123456", ["a.csv"], "template.csv", "value,comment")
        mock_event.assert_called_once_with("123456", ["a.csv"], "template.csv", "value,comment")

    def test_case_000000_prompts_for_event_id(self):
        with mock.patch("app.MISP.vt_tools2misp.misp_event") as mock_event:
            with mock.patch(
                "app.MISP.vt_tools2misp.Prompt.ask", side_effect=["yes", "999999"]
            ):
                misp_choice("000000", ["a.csv"])
        mock_event.assert_called_once_with("999999", ["a.csv"], None, None)

    def test_no_choice_skips_misp_event(self):
        with mock.patch("app.MISP.vt_tools2misp.misp_event") as mock_event:
            with mock.patch("app.MISP.vt_tools2misp.Prompt.ask", return_value="no"):
                misp_choice("123456", ["a.csv"])
        mock_event.assert_not_called()

    def test_invalid_choice_retries_until_valid(self):
        with mock.patch("app.MISP.vt_tools2misp.misp_event") as mock_event:
            with mock.patch(
                "app.MISP.vt_tools2misp.Prompt.ask", side_effect=["bogus", "n"]
            ):
                misp_choice("123456", ["a.csv"])
        mock_event.assert_not_called()


if __name__ == "__main__":
    unittest.main()
