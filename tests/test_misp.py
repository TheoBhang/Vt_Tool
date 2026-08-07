import csv
import os
import tempfile
import unittest
from unittest import mock

from app.MISP.vt_tools2misp import (
    process_csv_file,
    load_template,
    apply_template_data,
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
